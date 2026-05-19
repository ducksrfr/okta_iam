"""
rippling_user_lookup.py
-----------------------
AWS Lambda function called by Okta Workflows to locate a specific employee
in Rippling by their work email address.

Responsibilities (Lambda only):
  - Paginate through the Rippling List Users API
  - Find the user whose WORK email matches the address supplied by Okta Workflows
  - Return id, active, full name object, and WORK email(s) to the Workflow
  - The Workflow itself is responsible for updating the Okta profile

The Lambda does NOT write to Okta. It is a read-only Rippling query.

Expected API Gateway POST body (sent by Okta Workflows):
  {
    "email": "employee@example.com",   # work email to search for
    "dry_run": true | false            # if true, finds user but flags result so
                                       # the Workflow skips the Okta update
  }

Response body (200) — found:
  {
    "found": true,
    "dry_run": false,
    "user": {
      "id": "...",
      "active": true,
      "name": {
        "formatted": "...",
        "given_name": "...",
        "middle_name": "...",
        "family_name": "...",
        "preferred_given_name": "...",
        "preferred_family_name": "..."
      },
      "work_emails": [
        { "value": "employee@example.com", "type": "WORK", "display": "..." }
      ]
    }
  }

Response body (200) — not found:
  {
    "found": false,
    "dry_run": false,
    "user": null
  }

Environment variables:
  RIPPLING_API_TOKEN  — Bearer token for the Rippling API.
                        Prefer storing in AWS Secrets Manager via RIPPLING_SECRET_ARN.
  RIPPLING_SECRET_ARN — (optional) ARN of a Secrets Manager secret whose
                        SecretString is JSON: {"token": "<bearer token>"}
                        Takes precedence over RIPPLING_API_TOKEN if set.

Rippling API reference:
  GET https://rest.ripplingapis.com/users/
  Scope required: users.read
  Pagination: cursor-based via "next_link" in each response envelope
"""

import json
import logging
import os
import re
import time

import boto3
import requests
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants — verified against Rippling REST API schema (April 2026)
# ---------------------------------------------------------------------------
RIPPLING_BASE_URL = "https://rest.ripplingapis.com"
LIST_USERS_PATH   = "/users/"

# Response envelope keys
RESULTS_KEY       = "results"     # list of user objects in each page
NEXT_LINK_KEY     = "next_link"   # cursor URL for the next page; null/absent = last page

# User object field names
NAME_FIELD        = "name"        # object: formatted, given_name, middle_name,
                                  #         family_name, preferred_given_name,
                                  #         preferred_family_name
EMAIL_ARRAY_FIELD = "emails"      # list of email objects

# Email object field names (each item in the emails array)
EMAIL_VALUE_FIELD = "value"       # the email address string
EMAIL_TYPE_FIELD  = "type"        # e.g. "WORK", "HOME"
WORK_EMAIL_TYPE   = "WORK"        # case-insensitive comparison applied in helpers below

# Email domain validation — Lambda only accepts Example Co work addresses
ALLOWED_EMAIL_PATTERN = re.compile(r"^[^@]+@example\.com$", re.IGNORECASE)

# Rippling rate limit retry settings
MAX_RETRIES       = 5
INITIAL_BACKOFF   = 2             # seconds; doubles on each 429 retry
MAX_PAGES         = 200           # circuit breaker — stop paginating after this many pages


# ---------------------------------------------------------------------------
# Token retrieval
# ---------------------------------------------------------------------------

def _get_bearer_token() -> str:
    """
    Returns the Rippling API bearer token.
    Prefers Secrets Manager (RIPPLING_SECRET_ARN) over a plain env var
    (RIPPLING_API_TOKEN) so credentials are never stored in Lambda config
    in plain text in production.
    """
    secret_arn = os.environ.get("RIPPLING_SECRET_ARN")
    if secret_arn:
        try:
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_arn)
            secret = json.loads(response["SecretString"])
            return secret["token"]
        except ClientError as exc:
            logger.error("Failed to retrieve token from Secrets Manager: %s", exc)
            raise

    token = os.environ.get("RIPPLING_API_TOKEN")
    if not token:
        raise OSError(
            "No Rippling API token found. Set RIPPLING_SECRET_ARN or RIPPLING_API_TOKEN."
        )
    return token


# ---------------------------------------------------------------------------
# Rippling API client
# ---------------------------------------------------------------------------

def _rippling_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _fetch_page(token: str, url: str) -> dict:
    """
    Fetches one page from the given Rippling URL.
    Retries automatically on HTTP 429 (rate limited) using exponential backoff.

    Returns the full response envelope:
      {
        "__meta": { ... },
        "results": [ <user objects> ],
        "next_link": "<url>" | null
      }
    """
    backoff = INITIAL_BACKOFF

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                headers=_rippling_headers(token),
                timeout=30,
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", backoff))
                logger.warning(
                    "Rate limited by Rippling (attempt %d/%d). Waiting %ds before retry.",
                    attempt, MAX_RETRIES, retry_after,
                )
                time.sleep(retry_after)
                backoff = min(backoff * 2, 60)
                continue

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.warning("Request timed out (attempt %d/%d).", attempt, MAX_RETRIES)
            if attempt == MAX_RETRIES:
                raise
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

        except requests.exceptions.RequestException as exc:
            logger.error("Rippling API request failed: %s", exc)
            raise

    raise RuntimeError(f"Rippling API request failed after {MAX_RETRIES} attempts.")


# ---------------------------------------------------------------------------
# Email helpers
# ---------------------------------------------------------------------------

def _extract_work_emails(email_list: list) -> list:
    """
    Returns only the email objects whose type matches WORK_EMAIL_TYPE.
    Comparison is case-insensitive to be defensive against API variation.
    """
    return [
        entry for entry in (email_list or [])
        if str(entry.get(EMAIL_TYPE_FIELD, "")).upper() == WORK_EMAIL_TYPE
    ]


def _user_has_work_email(user: dict, target_email: str) -> bool:
    """
    Returns True if any of the user's WORK email addresses matches target_email.

    Only emails with type == WORK_EMAIL_TYPE are evaluated. HOME or any other
    type are skipped entirely — no value comparison or regex check is applied
    to them.
    """
    target_lower = target_email.strip().lower()

    for entry in (user.get(EMAIL_ARRAY_FIELD) or []):
        email_type = str(entry.get(EMAIL_TYPE_FIELD, "")).upper()

        if email_type != WORK_EMAIL_TYPE:
            # Not a WORK email — skip without inspecting the value
            continue

        if entry.get(EMAIL_VALUE_FIELD, "").strip().lower() == target_lower:
            return True

    return False


# ---------------------------------------------------------------------------
# Main search logic
# ---------------------------------------------------------------------------

def _find_rippling_user(token: str, target_email: str) -> dict | None:
    """
    Paginates through all Rippling users using cursor-based pagination (next_link)
    and returns the first user whose WORK email matches target_email, or None.

    Returns a dict with only the fields Okta Workflows needs:
      id, active, name (full object), work_emails (WORK-filtered list)
    """
    next_url = f"{RIPPLING_BASE_URL}{LIST_USERS_PATH}"
    page_num = 0

    while next_url:
        page_num += 1
        if page_num > MAX_PAGES:
            logger.error(
                "Safety limit: exceeded %d pages without finding a match. Stopping.",
                MAX_PAGES,
            )
            break
        logger.info("Fetching Rippling users page %d: %s", page_num, next_url)

        envelope = _fetch_page(token, next_url)
        users    = envelope.get(RESULTS_KEY, [])

        if not users:
            logger.info("Empty results on page %d — end of user list.", page_num)
            break

        for user in users:
            if _user_has_work_email(user, target_email):
                logger.info(
                    "Match found on page %d for email: %s (Rippling ID: %s)",
                    page_num, target_email, user.get("id"),
                )
                # Early exit — stop paginating immediately and return only the
                # fields Okta Workflows needs to update the user's Okta profile.
                return {
                    "id":          user.get("id"),
                    "active":      user.get("active"),
                    "name":        user.get(NAME_FIELD),
                    "work_emails": _extract_work_emails(user.get(EMAIL_ARRAY_FIELD) or []),
                }

        # Advance to next page; next_link is null or absent on the last page
        next_url = envelope.get(NEXT_LINK_KEY) or None

    logger.info("User not found after %d page(s).", page_num)
    return None


# ---------------------------------------------------------------------------
# Response helper
# ---------------------------------------------------------------------------

def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers":    {"Content-Type": "application/json"},
        "body":       json.dumps(body),
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context) -> dict:
    """
    Entry point invoked by API Gateway.

    Okta Workflows sends a POST request with a JSON body containing:
      - email    (required) the Okta user's current work email to look up in Rippling
      - dry_run  (optional, default false) if true, the user is found and returned
                 but the response is flagged so the Workflow skips the Okta update

    The dry_run flag passes through to the Workflow — this Lambda always queries
    Rippling regardless of dry_run mode (it is read-only either way).
    """
    logger.info("Lambda invoked. Request ID: %s", context.aws_request_id)

    # ---- Parse request body ------------------------------------------------
    # Supports two invocation styles:
    #   1. API Gateway proxy:  event["body"] is a JSON string containing the payload
    #   2. Direct / Okta Workflows AWS Lambda connector:  payload keys (email,
    #      dry_run) are top-level on event itself — there is no "body" wrapper
    try:
        raw_body = event.get("body")
        if raw_body is not None:
            # API Gateway proxy — body is a JSON string
            body = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        elif "email" in event:
            # Direct invocation (Okta Workflows Lambda connector) — payload IS event
            body = event
        else:
            body = {}
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON body: %s", exc)
        return _response(400, {"error": "Request body must be valid JSON."})

    target_email = (body.get("email") or "").strip()
    dry_run      = bool(body.get("dry_run", False))

    if not target_email:
        return _response(400, {"error": "'email' is required in the request body."})

    if not ALLOWED_EMAIL_PATTERN.match(target_email):
        logger.warning("Rejected non-Example Co email address: %s", target_email)
        return _response(400, {"error": f"Email must be a @example.com address. Received: {target_email}"})

    logger.info(
        "Searching Rippling for work email: %s | dry_run=%s", target_email, dry_run
    )

    # ---- Retrieve token ----------------------------------------------------
    try:
        token = _get_bearer_token()
    except Exception as exc:
        logger.error("Token retrieval failed: %s", exc)
        return _response(500, {"error": "Failed to retrieve Rippling API credentials."})

    # ---- Search Rippling ---------------------------------------------------
    try:
        user = _find_rippling_user(token, target_email)
    except Exception as exc:
        logger.error("Rippling search failed: %s", exc)
        return _response(502, {"error": f"Rippling API error: {str(exc)}"})

    # ---- Build response ----------------------------------------------------
    if user:
        if dry_run:
            logger.info(
                "DRY RUN — user found (Rippling ID: %s). Workflow should skip Okta update.",
                user.get("id"),
            )
        else:
            logger.info(
                "User found (Rippling ID: %s). Returning data to Workflow.", user.get("id")
            )
        payload = {"found": True, "dry_run": dry_run, "user": user}
    else:
        logger.info("No Rippling user found with work email: %s", target_email)
        payload = {"found": False, "dry_run": dry_run, "user": None}

    return _response(200, payload)


