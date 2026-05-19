"""
lambda_function.py — Secondary Calendar Ownership Transfer
AWS Lambda handler for Okta Workflows offboarding integration.

Triggered by Okta Workflows via HTTP (API Gateway or Lambda Function URL).
Impersonates the departing user via Google DWD, lists their owned secondary
calendars, and transfers each one to the specified new owner.

Expected event payload from Okta Workflows:
{
    "departing_user_email": "user@example.com",
    "new_owner_email":      "manager@example.com"
}

Response to Okta Workflows:
{
    "status":    "success" | "partial" | "error",
    "summary": {
        "total":     int,
        "succeeded": int,
        "failed":    int
    },
    "transfers": [
        {
            "calendar_id":  "c_abc@group.calendar.google.com",
            "display_name": "Team Calendar",
            "status":       "TRANSFERRED" | "FAILED",
            "message":      ""
        },
        ...
    ],
    "error": ""   # top-level error message if auth/setup failed entirely
}

Environment variables (set in Lambda console):
    GOOGLE_SA_CREDENTIALS_ARN — ARN of the Secrets Manager secret containing
                                the Google service account JSON key file.
                                Format: {"key": "<full SA JSON string>"}

Required Google API scope on the Example-IT service account DWD entry:
    https://www.googleapis.com/auth/calendar

Deployment:
    Package this file + dependencies into a Lambda zip or container image.
    See README section below for packaging instructions.
"""

import json
import logging
import os
import re
import time

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Google auth — bundled in the Lambda deployment package
# ---------------------------------------------------------------------------
try:
    from google.oauth2 import service_account
    from google.oauth2.service_account import Credentials
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError as e:
    raise RuntimeError(f"Import failed: {e}") from e

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CALENDAR_SCOPE   = "https://www.googleapis.com/auth/calendar"
RATE_LIMIT_DELAY = 0.5
RETRY_DELAY      = 10
MAX_RETRIES      = 3

# Email domain validation — only accept Example Co work addresses
ALLOWED_EMAIL_PATTERN = re.compile(r"^[^@]+@example\.com$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Logging — Lambda captures stdout automatically to CloudWatch
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def _get_sa_credentials() -> dict:
    """
    Retrieves the Google service account JSON from AWS Secrets Manager.
    Reads the secret ARN from the GOOGLE_SA_CREDENTIALS_ARN environment variable.
    The secret value must be a JSON string of the full service account key file.
    """
    secret_arn = os.environ.get("GOOGLE_SA_CREDENTIALS_ARN")
    if not secret_arn:
        raise RuntimeError("GOOGLE_SA_CREDENTIALS_ARN environment variable is not set.")

    try:
        client        = boto3.client("secretsmanager")
        response      = client.get_secret_value(SecretId=secret_arn)
        secret_string = response["SecretString"]
        return json.loads(secret_string)
    except ClientError as e:
        logger.error("Failed to retrieve Google SA credentials from Secrets Manager: %s", e)
        raise
    except json.JSONDecodeError as e:
        logger.error("Secrets Manager value is not valid JSON: %s", e)
        raise


def build_calendar_service(impersonate_email: str):
    """
    Build a Calendar API service impersonating the given user.
    Loads service account credentials from AWS Secrets Manager.
    """
    sa_info = _get_sa_credentials()
    creds   = service_account.Credentials.from_service_account_info(
        sa_info, scopes=[CALENDAR_SCOPE]
    ).with_subject(impersonate_email)

    return build("calendar", "v3", credentials=creds)


# ---------------------------------------------------------------------------
# Calendar listing — impersonates the departing user
# ---------------------------------------------------------------------------
def list_owned_secondary_calendars(service, departing_email: str) -> list[dict]:
    """
    Returns all secondary calendars owned by the departing user.
    Filters: accessRole=owner, primary=False.
    """
    calendars  = []
    page_token = None

    while True:
        try:
            resp = (
                service.calendarList()
                .list(
                    minAccessRole="owner",
                    pageToken=page_token,
                    maxResults=250,
                )
                .execute()
            )
        except HttpError as e:
            logger.error(f"Failed to list calendars for {departing_email}: {e}")
            raise

        for item in resp.get("items", []):
            # Skip primary calendar
            if item.get("primary", False):
                continue
            # Skip if not owner (belt-and-suspenders on top of minAccessRole)
            if item.get("accessRole") != "owner":
                continue
            calendars.append({
                "calendar_id":  item["id"],
                "display_name": item.get("summary", ""),
            })

        page_token = resp.get("nextPageToken")
        if not page_token:
            break
        time.sleep(RATE_LIMIT_DELAY)

    logger.info(f"Found {len(calendars)} owned secondary calendar(s) for {departing_email}.")
    return calendars


# ---------------------------------------------------------------------------
# ACL transfer
# ---------------------------------------------------------------------------
def transfer_ownership(service, calendar_id: str, new_owner_email: str) -> dict:
    """
    Inserts an ACL rule granting owner role to new_owner_email.
    Returns: {success, status, message}
    """
    body = {
        "role":  "owner",
        "scope": {
            "type":  "user",
            "value": new_owner_email,
        },
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            service.acl().insert(
                calendarId=calendar_id,
                body=body,
                sendNotifications=False,
            ).execute()
            logger.info(f"  ✅ Transferred {calendar_id} → {new_owner_email}")
            return {"success": True, "status": "TRANSFERRED", "message": ""}

        except HttpError as e:
            status = e.resp.status
            if status == 429 or (status == 403 and "quota" in str(e).lower()):
                logger.warning(f"  Rate limit on {calendar_id} (attempt {attempt}). Waiting {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            elif status == 404:
                return {"success": False, "status": "FAILED", "message": "404 Calendar not found"}
            elif status == 403:
                return {"success": False, "status": "FAILED", "message": f"403 Forbidden: {e}"}
            elif status == 400:
                return {"success": False, "status": "FAILED", "message": f"400 Bad request: {e}"}
            else:
                logger.warning(f"  HTTP {status} on attempt {attempt} for {calendar_id}: {e}")
                if attempt == MAX_RETRIES:
                    return {"success": False, "status": "FAILED", "message": str(e)}
                time.sleep(RETRY_DELAY)

        except Exception as e:
            logger.error(f"  Unexpected error for {calendar_id}: {e}")
            return {"success": False, "status": "FAILED", "message": str(e)}

    return {"success": False, "status": "FAILED", "message": "Max retries exceeded"}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    """
    Entry point for AWS Lambda.

    Okta Workflows HTTP action should POST JSON to this function's URL:
    {
        "departing_user_email": "user@example.com",
        "new_owner_email":      "manager@example.com"
    }
    """
    logger.info("Lambda invoked. Request ID: %s", context.aws_request_id)

    # ------------------------------------------------------------------
    # Parse and validate payload
    # Supports three invocation styles:
    #   1. API Gateway proxy:         event["body"] is a JSON string
    #   2. Lambda Function URL:       event["body"] is already a dict
    #   3. Okta Workflows Lambda connector: payload keys are top-level on event
    # ------------------------------------------------------------------
    try:
        raw_body = event.get("body")
        if raw_body is not None:
            payload = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        elif "departing_user_email" in event:
            payload = event
        else:
            payload = {}
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON body: %s", e)
        return _response(400, {"status": "error", "error": f"Invalid JSON body: {e}"})

    departing_email = payload.get("departing_user_email", "").strip()
    new_owner_email = payload.get("new_owner_email", "").strip()

    if not departing_email or not new_owner_email:
        msg = "Missing required fields: departing_user_email and new_owner_email"
        logger.error(msg)
        return _response(400, {"status": "error", "error": msg})

    if not ALLOWED_EMAIL_PATTERN.match(departing_email):
        logger.warning("Rejected non-Example Co departing_user_email: %s", departing_email)
        return _response(400, {"status": "error", "error": f"departing_user_email must be a @example.com address. Received: {departing_email}"})

    if not ALLOWED_EMAIL_PATTERN.match(new_owner_email):
        logger.warning("Rejected non-Example Co new_owner_email: %s", new_owner_email)
        return _response(400, {"status": "error", "error": f"new_owner_email must be a @example.com address. Received: {new_owner_email}"})

    logger.info("Processing offboard: %s → new owner: %s", departing_email, new_owner_email)

    # ------------------------------------------------------------------
    # Build Calendar service impersonating the departing user
    # ------------------------------------------------------------------
    try:
        service = build_calendar_service(departing_email)
    except Exception as e:
        logger.error(f"Auth failed: {e}")
        return _response(500, {"status": "error", "error": f"Auth failed: {e}"})

    # ------------------------------------------------------------------
    # List owned secondary calendars
    # ------------------------------------------------------------------
    try:
        calendars = list_owned_secondary_calendars(service, departing_email)
    except Exception as e:
        logger.error(f"Calendar listing failed: {e}")
        return _response(500, {"status": "error", "error": f"Calendar listing failed: {e}"})

    if not calendars:
        logger.info(f"No owned secondary calendars found for {departing_email}. Nothing to transfer.")
        return _response(200, {
            "status":    "success",
            "summary":   {"total": 0, "succeeded": 0, "failed": 0},
            "transfers": [],
            "error":     "",
        })

    # ------------------------------------------------------------------
    # Transfer each calendar
    # ------------------------------------------------------------------
    transfers  = []
    succeeded  = 0
    failed     = 0

    for cal in calendars:
        cal_id = cal["calendar_id"]
        name   = cal["display_name"]

        logger.info(f"Transferring '{name}' ({cal_id}) → {new_owner_email}")
        result = transfer_ownership(service, cal_id, new_owner_email)

        if result["success"]:
            succeeded += 1
        else:
            failed += 1
            logger.warning(f"  ❌ Failed: {cal_id} — {result['message']}")

        transfers.append({
            "calendar_id":  cal_id,
            "display_name": name,
            "status":       result["status"],
            "message":      result["message"],
        })

        time.sleep(RATE_LIMIT_DELAY)

    # ------------------------------------------------------------------
    # Build response
    # ------------------------------------------------------------------
    total      = len(calendars)
    top_status = "success" if failed == 0 else ("partial" if succeeded > 0 else "error")

    logger.info(f"Complete. {succeeded}/{total} transferred, {failed} failed.")

    return _response(200, {
        "status":  top_status,
        "summary": {
            "total":     total,
            "succeeded": succeeded,
            "failed":    failed,
        },
        "transfers": transfers,
        "error":     "",
    })


# ---------------------------------------------------------------------------
# Response helper
# ---------------------------------------------------------------------------
def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers":    {"Content-Type": "application/json"},
        "body":       json.dumps(body),
    }
