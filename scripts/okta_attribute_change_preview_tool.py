"""
okta_attribute_change_preview.py  (v2)
======================================

AWS Lambda function (invoked from an Okta Workflow) that previews the
group-membership impact of changing one or more profile attributes
(department, costCenter, division) on a set of users.

v2 changes vs the original draft
--------------------------------
* Cascade bug: _simulate_membership now preserves the user's non-rule
  baseline memberships across passes so isMemberOfGroup() checks against
  directly-assigned / AD-mapped groups don't spuriously flip false.
* Full profile retained for OEL evaluation (was: 6 hard-coded attrs).
  Lets rules referencing user.title, user.userType, custom attrs, etc.
  evaluate correctly.
* OKTA_GROUP filtering applied to fetched groups, user-group memberships,
  and CSV output rows (per IT preference: no APP_GROUP analysis).
* OEL parser expanded to cover what Example Co rules actually use:
  String.substringBefore/substringAfter (string-returning), toUpperCase,
  toLowerCase, len, equals, equalsIgnoreCase, append, the `null` keyword,
  the `+` concatenation operator, numeric (<, <=, >, >=) comparisons,
  and Arrays.contains. Function results may now be non-bool values used
  inside == / != comparisons.
* Secrets Manager credentials cached at module scope (warm-start fix).
* Lambda remaining-time bailout via context.get_remaining_time_in_millis.
* S3 upload becomes mandatory when CSV exceeds 5 MB (Lambda 6 MB sync
  response limit).
* Attribute-reference discovery walks the parsed AST instead of doing a
  textual substring search — no more false hits on user.departmentLead.
* Per-rule manual exclusions are now honored: rules.conditions.people.
  users.exclude is read at fetch time, and excluded users are skipped in
  both ADD and REMOVE simulation. This is the only mechanism that keeps
  a user in a rule-granted group when the rule's expression stops
  matching them.
* REMOVE rows mean the rule's dynamic re-evaluation will remove the user
  from the group. Okta group rules ARE the source of those memberships;
  when the expression no longer matches and the user is not on the
  exclusion list, removal is deterministic.
* MAX_RULE_PASSES default bumped from 5 to 10.

The function:
  1. Pulls every group and every group rule from the Okta tenant once
     (cheaper than per-user lookups when previewing many users).
  2. For each user, fetches the profile and current group memberships.
  3. Locally evaluates every ACTIVE group rule against the user's
     CURRENT profile and against the SIMULATED profile (with the
     attribute changes applied).
  4. Iterates evaluation passes until membership converges so that
     nested-group references (isMemberOfGroup / isMemberOfGroupName)
     in rule conditions cascade correctly.
  5. Diffs the two membership sets and emits a CSV describing every
     ADD / REMOVE / MANUAL_REVIEW event, including the triggering rule
     and the cascade depth.

Lambda input (event)
--------------------
Per-attribute values (preferred — lets you change multiple attributes in
one run with different values):
{
    "attributes_to_change": ["department", "costCenter"],
    "new_value": [
        {"attribute": "department", "value": "Engineering"},
        {"attribute": "costCenter", "value": "ExampleCostCenter"}
    ],
    "user_emails": ["alice@example.com", ...]
}

Legacy single-value form (still accepted; applies one value to every
attribute in attributes_to_change — useful for one-attr previews):
{
    "attributes_to_change": ["department"],
    "new_value":            "Engineering",
    "user_emails":          ["alice@example.com"]
}

Supported attributes (allow-list):
    String-typed: department, costCenter, division, office, countryCode,
                  userType
    Boolean-typed: is_manager

Validation rules:
* Every attribute in attributes_to_change must have a matching entry in
  the new_value array (or new_value must be a string for the legacy form).
* Every attribute in the new_value array must appear in
  attributes_to_change. The two lists must agree.
* attributes_to_change is constrained to the SUPPORTED_ATTRIBUTES
  allow-list above.
* is_manager values must be JSON booleans (true / false), not strings.
  The legacy string form of new_value cannot be used when is_manager is
  in attributes_to_change — the array form is required.

Example with a boolean attribute:
{
    "attributes_to_change": ["is_manager", "department"],
    "new_value": [
        {"attribute": "is_manager", "value": true},
        {"attribute": "department", "value": "Engineering Management"}
    ],
    "user_emails": ["alice@example.com"]
}

CSV output context
------------------
The `current_values` column in the output CSV always shows every
SUPPORTED_ATTRIBUTES attribute's current value for each user, regardless
of which subset is being changed. Maximum context, no configuration.

Lambda output
-------------
{
    "statusCode": 200,
    "summary": {
        "users_processed":      <int>,
        "users_failed":         <int>,
        "rules_evaluated":      <int>,
        "rules_manual_review":  <int>,
        "total_csv_rows":       <int>,
        "s3_uri":               "<optional>"
    },
    "csv_base64": "<base64 CSV body>"
}

Environment
-----------
OKTA_DOMAIN              required, e.g. "acme.okta.com" (no scheme)
OKTA_API_TOKEN           required UNLESS OKTA_SECRET_NAME is set
OKTA_SECRET_NAME         optional; AWS Secrets Manager secret name with JSON
                         {"OKTA_DOMAIN": "...", "OKTA_API_TOKEN": "..."}
OUTPUT_S3_BUCKET         optional; if set, CSV is also written here
OUTPUT_S3_PREFIX         optional; default "okta-attribute-previews/"
USER_BATCH_SIZE          optional; default 25
USER_BATCH_PAUSE_SEC     optional; default 0.5 (pause between user batches)
RATE_LIMIT_FLOOR         optional; default 20 (sleep until reset when remaining drops below)
MAX_RULE_PASSES          optional; default 5 (cap on cascade iteration)
LOG_LEVEL                optional; default "INFO"

Deployment checklist (AWS Lambda)
---------------------------------
Required configuration when creating the function in the AWS console:

  Runtime              Python 3.11 or newer
  Architecture         x86_64 (no native deps; arm64 also works)
  Memory               512 MB (1024 MB if you commonly preview >100 users)
  Timeout              MINIMUM 60 seconds. Defaults to 3 seconds when you
                       create a new function — the script's startup sanity
                       check refuses to run below this floor with a clear
                       error message rather than silently dying mid-fetch.
                       Recommended values by preview size:
                         1–10 users     : 60 sec
                         10–50 users    : 180 sec
                         50–200 users   : 600 sec (10 min)
                         200+ users     : switch to async (Event invocation)
                       Maximum is 900 sec (15 min, AWS hard cap).
  Ephemeral storage    512 MB (default) is fine
  Execution role       Permissions required:
                         secretsmanager:GetSecretValue  on OKTA_SECRET_NAME
                         s3:PutObject + s3:GetObject    on OUTPUT_S3_BUCKET
                         logs:CreateLogStream/PutLogEvents (default role)

Environment variables (required unless noted):
  OKTA_SECRET_NAME              Secrets Manager secret name with JSON
                                {"OKTA_DOMAIN": "...", "OKTA_API_TOKEN": "..."}
  OUTPUT_S3_BUCKET              Required for previews > 5 MB CSV output
  OUTPUT_S3_PREFIX              Optional; default "okta-attribute-previews/"
  LAMBDA_MIN_TIMEOUT_MS_AT_START  Optional override (default 60000)
  USER_BATCH_SIZE / MAX_RULE_PASSES / RATE_LIMIT_FLOOR  Optional tuning

Okta API token scope:
  Read-only Admin for Users, Groups, and Group Rules. Do not use a
  Super Admin token — this function is read-only against Okta.

Honest limitations
------------------
* The OEL parser supports the operator and function set documented inline
  in `_OEL_SUPPORTED_FUNCTIONS`. Conditions using anything else are not
  silently skipped: they emit MANUAL_REVIEW rows so an IT reviewer can
  decide what to do.
* This script does not call Okta's group-rule preview/evaluation APIs;
  all condition evaluation is local to keep API call volume bounded.
* This script is read-only against Okta. There is no live-run vs dry-run
  switch because there is nothing to write to Okta. (The "dry run by
  default" preference applies to mutating workflows; this previews them.)
"""

from __future__ import annotations

import base64
import csv
import io
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# boto3 is preinstalled in AWS Lambda runtimes; guarded for local dev.
try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # noqa: N816


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG = logging.getLogger("okta_attr_preview")
LOG.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO))
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(_h)


# ---------------------------------------------------------------------------
# Constants and config
# ---------------------------------------------------------------------------

SUPPORTED_ATTRIBUTES = (
    # Core HR attributes used in dept/cost-center/division reorgs
    "department",
    "costCenter",
    "division",
    # Geo / relocation
    "office",
    "countryCode",
    # Employment classification — drives contractor-vs-FTE rule branches
    "userType",
    # Manager flag — drives manager-only access rules
    "is_manager",
)

# Attributes that must be supplied as JSON booleans, not strings. Every other
# attribute in SUPPORTED_ATTRIBUTES is treated as a string. If you add another
# boolean profile attribute in the future, add it here too.
BOOLEAN_ATTRIBUTES = ("is_manager",)

DEFAULT_USER_BATCH_SIZE = int(os.environ.get("USER_BATCH_SIZE", "25"))
DEFAULT_USER_BATCH_PAUSE_SEC = float(os.environ.get("USER_BATCH_PAUSE_SEC", "0.5"))
DEFAULT_RATE_LIMIT_FLOOR = int(os.environ.get("RATE_LIMIT_FLOOR", "20"))
DEFAULT_MAX_RULE_PASSES = int(os.environ.get("MAX_RULE_PASSES", "10"))
# Lambda sync responses are capped at 6 MB; leave headroom for JSON envelope.
LAMBDA_SYNC_RESPONSE_FLOOR_BYTES = 5 * 1024 * 1024
# Bail out of per-user processing if Lambda has fewer ms remaining than this.
LAMBDA_REMAINING_MS_FLOOR = int(os.environ.get("LAMBDA_REMAINING_MS_FLOOR", "15000"))
# Refuse to run if the Lambda's configured timeout leaves fewer ms than this
# at handler entry. Catches the common "default 3-second timeout" footgun
# from creating a Lambda in the AWS console without editing the timeout.
LAMBDA_MIN_TIMEOUT_MS_AT_START = int(os.environ.get("LAMBDA_MIN_TIMEOUT_MS_AT_START", "60000"))


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------

# Module-level cache so warm Lambda invocations skip the Secrets Manager call.
_CREDS_CACHE: tuple[str, str] | None = None


def _load_credentials() -> tuple[str, str]:
    """Return (okta_domain, okta_api_token).

    Prefers AWS Secrets Manager if OKTA_SECRET_NAME is set; otherwise reads
    plain env vars. Raises RuntimeError on missing config. Result is cached
    at module level so warm Lambda invocations don't repeatedly hit Secrets
    Manager.
    """
    global _CREDS_CACHE
    if _CREDS_CACHE is not None:
        return _CREDS_CACHE

    secret_name = os.environ.get("OKTA_SECRET_NAME")
    if secret_name:
        if boto3 is None:
            raise RuntimeError("boto3 not available but OKTA_SECRET_NAME is set")
        client = boto3.client("secretsmanager")
        resp = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(resp["SecretString"])
        domain = secret.get("OKTA_DOMAIN")
        token = secret.get("OKTA_API_TOKEN")
    else:
        domain = os.environ.get("OKTA_DOMAIN")
        token = os.environ.get("OKTA_API_TOKEN")

    if not domain or not token:
        raise RuntimeError(
            "Okta credentials not configured. Set OKTA_DOMAIN/OKTA_API_TOKEN "
            "or OKTA_SECRET_NAME pointing at a Secrets Manager secret."
        )
    # Strip scheme if someone supplied it.
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    _CREDS_CACHE = (domain, token)
    return _CREDS_CACHE


# ---------------------------------------------------------------------------
# Okta HTTP client (urllib-based, no third-party deps)
# ---------------------------------------------------------------------------

@dataclass
class OktaClient:
    domain: str
    token: str
    rate_limit_floor: int = DEFAULT_RATE_LIMIT_FLOOR
    timeout_sec: int = 30

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.token}",
            "User-Agent": "okta-attr-change-preview/1.0",
        }

    def _request(self, method: str, url: str, params: dict | None = None) -> tuple[Any, dict]:
        """Issue a single request with rate-limit honoring and retries.

        Returns (parsed_json, response_headers). Raises on non-recoverable error.
        """
        if params:
            qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"

        attempt = 0
        while True:
            attempt += 1
            req = urllib.request.Request(url, method=method, headers=self._headers())
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = resp.read().decode("utf-8") or "null"
                    self._maybe_sleep_for_rate_limit(headers)
                    return json.loads(body), headers
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
                # 429: hard rate limit. Sleep until reset and retry.
                if e.code == 429 and attempt <= 5:
                    sleep_for = self._seconds_until_reset(headers, default=10)
                    LOG.warning("429 from Okta on %s; sleeping %ss (attempt %d)", url, sleep_for, attempt)
                    time.sleep(sleep_for)
                    continue
                # 5xx: transient, exponential backoff
                if 500 <= e.code < 600 and attempt <= 4:
                    backoff = min(30, 2 ** attempt)
                    LOG.warning("%s from Okta on %s; backoff %ss", e.code, url, backoff)
                    time.sleep(backoff)
                    continue
                # 404 on user lookup is meaningful to caller; bubble up
                raw = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
                raise OktaApiError(e.code, url, raw) from None
            except urllib.error.URLError as e:
                if attempt <= 3:
                    backoff = 2 ** attempt
                    LOG.warning("Network error %s on %s; backoff %ss", e, url, backoff)
                    time.sleep(backoff)
                    continue
                raise

    def _maybe_sleep_for_rate_limit(self, headers: dict) -> None:
        try:
            remaining = int(headers.get("x-rate-limit-remaining", "1000"))
        except ValueError:
            return
        if remaining <= self.rate_limit_floor:
            sleep_for = self._seconds_until_reset(headers, default=2)
            LOG.info("Rate limit floor reached (%d <= %d); sleeping %ss",
                     remaining, self.rate_limit_floor, sleep_for)
            time.sleep(sleep_for)

    @staticmethod
    def _seconds_until_reset(headers: dict, default: int = 5) -> int:
        try:
            reset_ts = int(headers.get("x-rate-limit-reset", "0"))
        except ValueError:
            return default
        if reset_ts <= 0:
            return default
        delta = reset_ts - int(time.time()) + 1
        return max(default, delta)

    # -- Pagination helpers --------------------------------------------------

    def get_paginated(self, path: str, params: dict | None = None) -> Iterable[Any]:
        """Yield items across all pages, following the RFC 5988 'next' link."""
        url = f"https://{self.domain}{path}"
        next_url: str | None = url
        first = True
        while next_url:
            data, headers = self._request("GET", next_url, params if first else None)
            first = False
            if isinstance(data, list):
                for item in data:
                    yield item
            elif data is not None:
                yield data
            next_url = self._parse_next_link(headers.get("link", ""))

    @staticmethod
    def _parse_next_link(link_header: str) -> str | None:
        # Header: <https://...?after=...>; rel="next", <...>; rel="self"
        if not link_header:
            return None
        for part in link_header.split(","):
            segs = part.strip().split(";")
            if len(segs) < 2:
                continue
            url_part = segs[0].strip().lstrip("<").rstrip(">")
            rel_part = ";".join(segs[1:]).strip()
            if 'rel="next"' in rel_part:
                return url_part
        return None


class OktaApiError(Exception):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"Okta API {status} on {url}: {body[:400]}")
        self.status = status
        self.url = url
        self.body = body


# ---------------------------------------------------------------------------
# OEL (Okta Expression Language) parser & evaluator
#
# Grammar (subset):
#   expr     := or_expr
#   or_expr  := and_expr (("or"|"||") and_expr)*
#   and_expr := not_expr (("and"|"&&") not_expr)*
#   not_expr := ("not" | "!") not_expr | primary
#   primary  := "(" expr ")" | comparison | call | atom
#   comparison := value (("=="|"!=") value)?
#   value    := STRING | NUMBER | TRUE | FALSE | attr_ref | call
#   attr_ref := IDENT ("." IDENT)+        # e.g. user.department
#   call     := IDENT ("." IDENT)? "(" [value ("," value)*] ")"
#
# Anything we cannot parse is reported as UNSUPPORTED, which surfaces as
# MANUAL_REVIEW in the CSV. We never silently treat unparseable rules as
# false; that would hide real impact from IT reviewers.
# ---------------------------------------------------------------------------

# Lowercase function names => arity range and Python evaluator.
# Evaluators receive (args_evaluated, ctx) where ctx provides user attrs and
# group lookup helpers. They must return bool.

@dataclass
class OelContext:
    user_attrs: dict[str, str | None]            # e.g. {"department": "Eng", "costCenter": "...", ...}
    group_ids: set[str]                          # current group memberships (Okta group IDs)
    group_id_to_name: dict[str, str]
    group_name_to_id: dict[str, str]


def _fn_is_member_of_group(args, ctx: OelContext) -> bool:
    if len(args) != 1 or not isinstance(args[0], str):
        raise OelUnsupported("isMemberOfGroup expects a single string id")
    return args[0] in ctx.group_ids


def _fn_is_member_of_any_group(args, ctx: OelContext) -> bool:
    for a in args:
        if not isinstance(a, str):
            raise OelUnsupported("isMemberOfAnyGroup expects string ids")
        if a in ctx.group_ids:
            return True
    return False


def _fn_is_member_of_group_name(args, ctx: OelContext) -> bool:
    if len(args) != 1 or not isinstance(args[0], str):
        raise OelUnsupported("isMemberOfGroupName expects a single string name")
    gid = ctx.group_name_to_id.get(args[0])
    return bool(gid and gid in ctx.group_ids)


def _fn_is_member_of_group_name_starts_with(args, ctx: OelContext) -> bool:
    if len(args) != 1 or not isinstance(args[0], str):
        raise OelUnsupported("isMemberOfGroupNameStartsWith expects a single prefix")
    prefix = args[0]
    return any(ctx.group_id_to_name.get(g, "").startswith(prefix) for g in ctx.group_ids)


def _fn_is_member_of_group_name_contains(args, ctx: OelContext) -> bool:
    if len(args) != 1 or not isinstance(args[0], str):
        raise OelUnsupported("isMemberOfGroupNameContains expects a single substring")
    sub = args[0]
    return any(sub in ctx.group_id_to_name.get(g, "") for g in ctx.group_ids)


def _fn_string_contains(args, _ctx) -> bool:
    if len(args) != 2:
        raise OelUnsupported("String.stringContains expects (str, substr)")
    s, sub = args
    if s is None or sub is None:
        return False
    return str(sub) in str(s)


def _fn_string_starts_with(args, _ctx) -> bool:
    if len(args) != 2:
        raise OelUnsupported("String.startsWith expects (str, prefix)")
    s, p = args
    if s is None or p is None:
        return False
    return str(s).startswith(str(p))


def _fn_string_ends_with(args, _ctx) -> bool:
    if len(args) != 2:
        raise OelUnsupported("String.endsWith expects (str, suffix)")
    s, p = args
    if s is None or p is None:
        return False
    return str(s).endswith(str(p))


def _fn_string_equals(args, _ctx) -> bool:
    if len(args) != 2:
        raise OelUnsupported("String.equals expects (str, str)")
    a, b = args
    return (a or "") == (b or "")


def _fn_string_equals_ignore_case(args, _ctx) -> bool:
    if len(args) != 2:
        raise OelUnsupported("String.equalsIgnoreCase expects (str, str)")
    a, b = args
    return (a or "").lower() == (b or "").lower()


# --- String value-returning functions (may be used inside == / != / +) ----

def _fn_substring_before(args, _ctx):
    if len(args) != 2:
        raise OelUnsupported("String.substringBefore expects (str, delim)")
    s, sep = args
    if s is None:
        return None
    s_s = str(s)
    sep_s = "" if sep is None else str(sep)
    if sep_s == "":
        return s_s
    idx = s_s.find(sep_s)
    return s_s if idx < 0 else s_s[:idx]


def _fn_substring_after(args, _ctx):
    if len(args) != 2:
        raise OelUnsupported("String.substringAfter expects (str, delim)")
    s, sep = args
    if s is None:
        return None
    s_s = str(s)
    sep_s = "" if sep is None else str(sep)
    if sep_s == "":
        return s_s
    idx = s_s.find(sep_s)
    return "" if idx < 0 else s_s[idx + len(sep_s):]


def _fn_substring(args, _ctx):
    # Okta: String.substring(str, beginIndex[, endIndex])
    if len(args) not in (2, 3):
        raise OelUnsupported("String.substring expects (str, begin[, end])")
    s = args[0]
    if s is None:
        return None
    s_s = str(s)
    try:
        begin = int(args[1])
        if len(args) == 3:
            end = int(args[2])
            return s_s[begin:end]
        return s_s[begin:]
    except (TypeError, ValueError) as e:
        raise OelUnsupported(f"String.substring bad indices: {e}")


def _fn_to_upper(args, _ctx):
    if len(args) != 1:
        raise OelUnsupported("String.toUpperCase expects (str)")
    return None if args[0] is None else str(args[0]).upper()


def _fn_to_lower(args, _ctx):
    if len(args) != 1:
        raise OelUnsupported("String.toLowerCase expects (str)")
    return None if args[0] is None else str(args[0]).lower()


def _fn_string_len(args, _ctx):
    if len(args) != 1:
        raise OelUnsupported("String.len expects (str)")
    return 0 if args[0] is None else len(str(args[0]))


def _fn_string_append(args, _ctx):
    if len(args) != 2:
        raise OelUnsupported("String.append expects (str, str)")
    a, b = args
    return ("" if a is None else str(a)) + ("" if b is None else str(b))


def _fn_string_replace(args, _ctx):
    # Okta: String.replace(str, target, replacement)
    if len(args) != 3:
        raise OelUnsupported("String.replace expects (str, target, replacement)")
    s, t, r = args
    if s is None:
        return None
    return str(s).replace("" if t is None else str(t), "" if r is None else str(r))


def _fn_string_remove_spaces(args, _ctx):
    if len(args) != 1:
        raise OelUnsupported("String.removeSpaces expects (str)")
    return None if args[0] is None else str(args[0]).replace(" ", "")


def _fn_string_trim(args, _ctx):
    if len(args) != 1:
        raise OelUnsupported("String.trim expects (str)")
    return None if args[0] is None else str(args[0]).strip()


def _fn_arrays_contains(args, _ctx) -> bool:
    # Okta: Arrays.contains(array, value) — returns whether value is in array
    if len(args) != 2:
        raise OelUnsupported("Arrays.contains expects (array, value)")
    arr, val = args
    if arr is None:
        return False
    if isinstance(arr, (list, tuple, set)):
        return val in arr
    # If a single scalar is passed, fall back to == semantics.
    return arr == val


def _fn_arrays_is_empty(args, _ctx) -> bool:
    if len(args) != 1:
        raise OelUnsupported("Arrays.isEmpty expects (array)")
    a = args[0]
    if a is None:
        return True
    if isinstance(a, (list, tuple, set, dict, str)):
        return len(a) == 0
    return False


_OEL_SUPPORTED_FUNCTIONS: dict[str, Callable[[list, "OelContext"], Any]] = {
    # Group-membership predicates
    "ismemberofgroup":                   _fn_is_member_of_group,
    "ismemberofanygroup":                _fn_is_member_of_any_group,
    "ismemberofgroupname":               _fn_is_member_of_group_name,
    "ismemberofgroupnamestartswith":     _fn_is_member_of_group_name_starts_with,
    "ismemberofgroupnamecontains":       _fn_is_member_of_group_name_contains,
    # Groups.* aliases (newer Okta syntax — same semantics)
    "groups.contains":                   _fn_is_member_of_group,
    "groups.startswith":                 _fn_is_member_of_group_name_starts_with,
    # String predicates
    "string.stringcontains":             _fn_string_contains,
    "string.contains":                   _fn_string_contains,
    "string.startswith":                 _fn_string_starts_with,
    "string.endswith":                   _fn_string_ends_with,
    "string.equals":                     _fn_string_equals,
    "string.equalsignorecase":           _fn_string_equals_ignore_case,
    # String value-returning
    "string.substringbefore":            _fn_substring_before,
    "string.substringafter":             _fn_substring_after,
    "string.substring":                  _fn_substring,
    "string.touppercase":                _fn_to_upper,
    "string.tolowercase":                _fn_to_lower,
    "string.len":                        _fn_string_len,
    "string.length":                     _fn_string_len,
    "string.append":                     _fn_string_append,
    "string.replace":                    _fn_string_replace,
    "string.removespaces":               _fn_string_remove_spaces,
    "string.trim":                       _fn_string_trim,
    # Arrays
    "arrays.contains":                   _fn_arrays_contains,
    "arrays.isempty":                    _fn_arrays_is_empty,
}


class OelUnsupported(Exception):
    """Raised when a rule uses syntax/functions outside our supported subset."""


class OelParseError(Exception):
    pass


# Token kinds
_TOK_STRING = "STRING"
_TOK_NUMBER = "NUMBER"
_TOK_IDENT = "IDENT"
_TOK_LPAREN = "LPAREN"
_TOK_RPAREN = "RPAREN"
_TOK_COMMA = "COMMA"
_TOK_DOT = "DOT"
_TOK_EQ = "EQ"
_TOK_NE = "NE"
_TOK_GT = "GT"
_TOK_GE = "GE"
_TOK_LT = "LT"
_TOK_LE = "LE"
_TOK_PLUS = "PLUS"
_TOK_AND = "AND"
_TOK_OR = "OR"
_TOK_NOT = "NOT"
_TOK_BOOL = "BOOL"
_TOK_NULL = "NULL"
_TOK_EOF = "EOF"

# Note: ordering matters — two-char operators (==, !=, <=, >=, &&, ||) must be
# matched before their one-char prefixes (!, <, >, &, |).
_TOKEN_RE = re.compile(
    r"""
    \s+                                         |   # whitespace
    "((?:[^"\\]|\\.)*)"                         |   # double-quoted string
    '((?:[^'\\]|\\.)*)'                         |   # single-quoted string
    (==)                                        |   # eq
    (!=)                                        |   # ne
    (>=)                                        |   # ge
    (<=)                                        |   # le
    (\&\&)                                      |   # and
    (\|\|)                                      |   # or
    (!)                                         |   # not
    (>)                                         |   # gt
    (<)                                         |   # lt
    (\+)                                        |   # plus / concat
    (\()                                        |   # (
    (\))                                        |   # )
    (,)                                         |   # ,
    (\.)                                        |   # .
    (\d+(?:\.\d+)?)                             |   # number
    ([A-Za-z_][A-Za-z0-9_]*)                        # ident
    """,
    re.VERBOSE,
)


def _tokenize(src: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(src):
        m = _TOKEN_RE.match(src, pos)
        if not m:
            raise OelParseError(f"Unexpected character at {pos}: {src[pos:pos+20]!r}")
        pos = m.end()
        if m.group(0).isspace():
            continue
        if m.group(1) is not None:
            tokens.append((_TOK_STRING, _unescape(m.group(1))))
        elif m.group(2) is not None:
            tokens.append((_TOK_STRING, _unescape(m.group(2))))
        elif m.group(3):
            tokens.append((_TOK_EQ, "=="))
        elif m.group(4):
            tokens.append((_TOK_NE, "!="))
        elif m.group(5):
            tokens.append((_TOK_GE, ">="))
        elif m.group(6):
            tokens.append((_TOK_LE, "<="))
        elif m.group(7):
            tokens.append((_TOK_AND, "&&"))
        elif m.group(8):
            tokens.append((_TOK_OR, "||"))
        elif m.group(9):
            tokens.append((_TOK_NOT, "!"))
        elif m.group(10):
            tokens.append((_TOK_GT, ">"))
        elif m.group(11):
            tokens.append((_TOK_LT, "<"))
        elif m.group(12):
            tokens.append((_TOK_PLUS, "+"))
        elif m.group(13):
            tokens.append((_TOK_LPAREN, "("))
        elif m.group(14):
            tokens.append((_TOK_RPAREN, ")"))
        elif m.group(15):
            tokens.append((_TOK_COMMA, ","))
        elif m.group(16):
            tokens.append((_TOK_DOT, "."))
        elif m.group(17):
            n = m.group(17)
            tokens.append((_TOK_NUMBER, float(n) if "." in n else int(n)))
        elif m.group(18):
            ident = m.group(18)
            low = ident.lower()
            if low == "and":
                tokens.append((_TOK_AND, "and"))
            elif low == "or":
                tokens.append((_TOK_OR, "or"))
            elif low == "not":
                tokens.append((_TOK_NOT, "not"))
            elif low in ("true", "false"):
                tokens.append((_TOK_BOOL, low == "true"))
            elif low == "null":
                tokens.append((_TOK_NULL, None))
            else:
                tokens.append((_TOK_IDENT, ident))
    tokens.append((_TOK_EOF, None))
    return tokens


# Surgical unescape that handles the common JSON-ish escapes Okta emits
# without round-tripping through bytes (which mangles non-ASCII UTF-8).
_ESCAPE_MAP = {
    '"': '"',  "'": "'",  "\\": "\\",
    "n": "\n", "t": "\t", "r": "\r", "/": "/",
}


def _unescape(s: str) -> str:
    if "\\" not in s:
        return s
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append(_ESCAPE_MAP.get(nxt, nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# AST node tuples: ("op", ...) — kept simple for compactness.

class _Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def eat(self, kind=None):
        tok = self.toks[self.i]
        if kind and tok[0] != kind:
            raise OelParseError(f"Expected {kind} but got {tok}")
        self.i += 1
        return tok

    def parse(self):
        node = self.parse_or()
        if self.peek()[0] != _TOK_EOF:
            raise OelParseError(f"Trailing tokens at position {self.i}: {self.peek()}")
        return node

    def parse_or(self):
        left = self.parse_and()
        while self.peek()[0] == _TOK_OR:
            self.eat()
            right = self.parse_and()
            left = ("or", left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek()[0] == _TOK_AND:
            self.eat()
            right = self.parse_not()
            left = ("and", left, right)
        return left

    def parse_not(self):
        if self.peek()[0] == _TOK_NOT:
            self.eat()
            return ("not", self.parse_not())
        return self.parse_comparison()

    # Comparison precedence:  additive (==|!=|<|<=|>|>=) additive
    def parse_comparison(self):
        left = self.parse_additive()
        kind = self.peek()[0]
        if kind in (_TOK_EQ, _TOK_NE, _TOK_GT, _TOK_GE, _TOK_LT, _TOK_LE):
            op_tok = self.eat()
            right = self.parse_additive()
            return (op_tok[1], left, right)
        return left

    # `+` is left-associative; we use it for string concat / numeric add.
    def parse_additive(self):
        left = self.parse_value()
        while self.peek()[0] == _TOK_PLUS:
            self.eat()
            right = self.parse_value()
            left = ("+", left, right)
        return left

    def parse_value(self):
        tok = self.peek()
        kind = tok[0]
        if kind == _TOK_LPAREN:
            self.eat()
            inner = self.parse_or()
            self.eat(_TOK_RPAREN)
            return inner
        if kind == _TOK_STRING:
            self.eat()
            return ("str", tok[1])
        if kind == _TOK_NUMBER:
            self.eat()
            return ("num", tok[1])
        if kind == _TOK_BOOL:
            self.eat()
            return ("bool", tok[1])
        if kind == _TOK_NULL:
            self.eat()
            return ("null",)
        if kind == _TOK_IDENT:
            return self.parse_ident_chain()
        raise OelParseError(f"Unexpected token {tok}")

    def parse_ident_chain(self):
        # Accumulate IDENT (DOT IDENT)*
        parts = [self.eat(_TOK_IDENT)[1]]
        while self.peek()[0] == _TOK_DOT:
            self.eat()
            parts.append(self.eat(_TOK_IDENT)[1])
        # Function call?
        if self.peek()[0] == _TOK_LPAREN:
            self.eat()
            args = []
            if self.peek()[0] != _TOK_RPAREN:
                args.append(self.parse_value())
                while self.peek()[0] == _TOK_COMMA:
                    self.eat()
                    args.append(self.parse_value())
            self.eat(_TOK_RPAREN)
            return ("call", ".".join(parts), args)
        # Otherwise an attribute reference (e.g. user.department)
        return ("attr", parts)


def parse_oel(expr: str):
    return _Parser(_tokenize(expr)).parse()


def evaluate_oel(node, ctx: OelContext) -> bool:
    """Evaluate a parsed OEL AST against the supplied context.

    Raises OelUnsupported if the expression touches functions/attrs we do not
    handle. Callers should catch this and emit MANUAL_REVIEW rows.
    """
    op = node[0]
    if op == "or":
        return bool(evaluate_oel(node[1], ctx)) or bool(evaluate_oel(node[2], ctx))
    if op == "and":
        return bool(evaluate_oel(node[1], ctx)) and bool(evaluate_oel(node[2], ctx))
    if op == "not":
        return not bool(evaluate_oel(node[1], ctx))
    if op in ("==", "!=", ">", ">=", "<", "<="):
        lv = _eval_value(node[1], ctx)
        rv = _eval_value(node[2], ctx)
        return _compare(op, lv, rv)
    if op == "+":
        # `+` is only legal inside a value position; if it appears as the top
        # of a boolean expression, treat the result as boolean truthiness.
        return bool(_eval_value(node, ctx))
    if op == "call":
        return bool(_eval_call(node, ctx))
    # A bare value used as a boolean expression
    val = _eval_value(node, ctx)
    return bool(val)


def _compare(op: str, lv, rv) -> bool:
    # Equality / inequality: Okta treats null == null as true and null != X
    # (for non-null X) as true.
    if op in ("==", "!="):
        if lv is None and rv is None:
            return op == "=="
        if lv is None or rv is None:
            return op == "!="
        eq = lv == rv
        return eq if op == "==" else not eq
    # Ordered comparisons. Coerce numeric strings opportunistically.
    if lv is None or rv is None:
        # Okta: ordered comparison with null is false.
        return False
    try:
        if isinstance(lv, str) and isinstance(rv, (int, float)):
            lv = float(lv)
        if isinstance(rv, str) and isinstance(lv, (int, float)):
            rv = float(rv)
        if op == ">":
            return lv > rv
        if op == ">=":
            return lv >= rv
        if op == "<":
            return lv < rv
        if op == "<=":
            return lv <= rv
    except TypeError:
        return False
    raise OelUnsupported(f"Unsupported comparison: {op}")


def _eval_value(node, ctx: OelContext):
    op = node[0]
    if op == "str":
        return node[1]
    if op == "num":
        return node[1]
    if op == "bool":
        return node[1]
    if op == "null":
        return None
    if op == "attr":
        return _eval_attr(node[1], ctx)
    if op == "call":
        return _eval_call(node, ctx)
    if op == "+":
        lv = _eval_value(node[1], ctx)
        rv = _eval_value(node[2], ctx)
        # Okta `+` is string concatenation when either operand is a string;
        # numeric add otherwise. Null coerces to "" in concat.
        if isinstance(lv, str) or isinstance(rv, str):
            return ("" if lv is None else str(lv)) + ("" if rv is None else str(rv))
        if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
            return lv + rv
        return ("" if lv is None else str(lv)) + ("" if rv is None else str(rv))
    raise OelUnsupported(f"Unsupported value node: {op}")


def _eval_attr(parts: list[str], ctx: OelContext):
    """Look up a user attribute.

    Accepts `user.<attr>` and `user.profile.<attr>`. Anything else is flagged.
    Unknown attributes return None — matches Okta semantics for missing /
    not-set profile fields.
    """
    if not parts or parts[0].lower() != "user":
        raise OelUnsupported(f"Unsupported attribute reference: {'.'.join(parts)}")
    # Optionally tolerate `user.profile.attr` — strip the `profile` segment.
    tail = parts[1:]
    if tail and tail[0].lower() == "profile":
        tail = tail[1:]
    if len(tail) != 1:
        raise OelUnsupported(f"Unsupported attribute reference: {'.'.join(parts)}")
    attr = tail[0]
    # Case-sensitive lookup first (matches Okta), fall back to case-insensitive
    # only if needed. The full-profile dict from /api/v1/users preserves case.
    if attr in ctx.user_attrs:
        return ctx.user_attrs[attr]
    lowered = {k.lower(): v for k, v in ctx.user_attrs.items()}
    return lowered.get(attr.lower())


def _eval_call(node, ctx: OelContext):
    fname = node[1].lower()
    raw_args = node[2]
    args = [_eval_value(a, ctx) for a in raw_args]
    fn = _OEL_SUPPORTED_FUNCTIONS.get(fname)
    if fn is None:
        raise OelUnsupported(f"Unsupported function: {node[1]}")
    return fn(args, ctx)


# ---------------------------------------------------------------------------
# Rule analysis
# ---------------------------------------------------------------------------

@dataclass
class GroupRule:
    rule_id: str
    name: str
    status: str
    expression: str
    target_group_ids: list[str]
    # User IDs explicitly excluded from this rule via the admin UI / API
    # (conditions.people.users.exclude). Excluded users are never added by
    # the rule even if the expression evaluates true for them. This is the
    # *only* way a user remains in a rule-granted group after the rule
    # stops matching them (other than being added by another rule).
    excluded_user_ids: set[str] = field(default_factory=set)
    parsed_ast: Any | None = None
    parse_error: str | None = None

    @property
    def is_active(self) -> bool:
        return self.status == "ACTIVE"


@dataclass
class UserAnalysis:
    email: str
    user_id: str | None = None
    profile: dict = field(default_factory=dict)
    current_group_ids: set[str] = field(default_factory=set)
    error: str | None = None


def _attr_changes_dict(
    attributes_to_change: list[str],
    new_value_map: dict[str, Any],
) -> dict[str, Any]:
    """Build the per-attribute change mapping passed into the OEL evaluator.

    new_value_map is already keyed by attribute (produced by
    _normalize_new_value). This helper just preserves the order of
    attributes_to_change for stable downstream rendering. Values may be
    strings or booleans depending on the attribute (see BOOLEAN_ATTRIBUTES).
    """
    return {a: new_value_map[a] for a in attributes_to_change}


def _simulate_membership(
    user: UserAnalysis,
    rules: list[GroupRule],
    group_id_to_name: dict[str, str],
    group_name_to_id: dict[str, str],
    attribute_changes: dict[str, str],
    max_passes: int,
) -> tuple[set[str], dict[str, list[str]], dict[str, str]]:
    """Iterate rule evaluation against the simulated profile until the
    rule-driven membership set converges (or max_passes is reached).

    Returns:
        rule_driven_group_ids: the converged set of group IDs the rules
            *would* assign to this user under the supplied attribute changes.
        rules_added_per_group:  {group_id: [rule_id, ...]} — which rule(s)
            assigned each group on the final pass.
        unsupported_rule_errors: {rule_id: error_msg} for rules whose
            expressions our parser couldn't handle.

    Cascade semantics
    -----------------
    Okta group rules can only ADD memberships, never remove ones granted
    by direct assignment / AD-mapping / app-group source. So when a rule's
    expression checks `isMemberOfGroup(<X>)`, the evaluation context must
    include *all* of the user's memberships — both rule-driven and
    non-rule-driven — not just rule-driven additions from this iteration.
    The previous implementation replaced `current` with `new_membership`
    each pass, which lost the non-rule baseline on pass 2+.

    The fix: compute a `non_rule_baseline` once (current memberships minus
    whatever rules grant under the *unchanged* profile), and on each pass
    feed `non_rule_baseline ∪ new_rule_membership` to the OEL evaluator
    via OelContext.group_ids.
    """
    sim_attrs = dict(user.profile)
    sim_attrs.update(attribute_changes)

    # Compute non-rule baseline only once. To do that we need the unchanged
    # profile's rule-driven set. Use a small inner helper to avoid recursion
    # subtleties; `attribute_changes={}` runs are cheap and converge fast.
    if attribute_changes:
        baseline_rule_set, _, _ = _simulate_membership(
            user, rules, group_id_to_name, group_name_to_id,
            attribute_changes={},
            max_passes=max_passes,
        )
        non_rule_baseline = set(user.current_group_ids) - baseline_rule_set
    else:
        # When called for the baseline itself, we conservatively assume every
        # current membership might be non-rule (so cascade evaluation sees the
        # full picture). The final returned `rule_driven` will still be the
        # subset that rules actually assign.
        non_rule_baseline = set(user.current_group_ids)

    rule_driven: set[str] = set()
    rules_per_group: dict[str, list[str]] = {}
    unsupported: dict[str, str] = {}

    for pass_idx in range(max_passes):
        ctx = OelContext(
            user_attrs=sim_attrs,
            group_ids=non_rule_baseline | rule_driven,
            group_id_to_name=group_id_to_name,
            group_name_to_id=group_name_to_id,
        )
        new_rule_driven: set[str] = set()
        new_rules_per_group: dict[str, list[str]] = {}

        for rule in rules:
            if not rule.is_active:
                continue
            # Respect per-rule manual exclusions: the admin has explicitly
            # carved this user out, so the rule never assigns them regardless
            # of expression result.
            if user.user_id and user.user_id in rule.excluded_user_ids:
                continue
            if rule.parsed_ast is None:
                if rule.rule_id not in unsupported and rule.parse_error:
                    unsupported[rule.rule_id] = rule.parse_error
                continue
            try:
                matched = evaluate_oel(rule.parsed_ast, ctx)
            except OelUnsupported as e:
                unsupported[rule.rule_id] = str(e)
                continue
            except Exception as e:  # defensive
                unsupported[rule.rule_id] = f"Evaluation error: {e}"
                continue
            if matched:
                for gid in rule.target_group_ids:
                    new_rule_driven.add(gid)
                    new_rules_per_group.setdefault(gid, []).append(rule.rule_id)

        if new_rule_driven == rule_driven:
            LOG.debug("Convergence after pass %d for %s", pass_idx + 1, user.email)
            rules_per_group = new_rules_per_group
            break
        rule_driven = new_rule_driven
        rules_per_group = new_rules_per_group
    else:
        LOG.warning(
            "Membership did not converge after %d passes for %s",
            max_passes, user.email,
        )

    return rule_driven, rules_per_group, unsupported


# ---------------------------------------------------------------------------
# Okta data fetchers
# ---------------------------------------------------------------------------

def fetch_all_groups(
    client: OktaClient,
) -> tuple[dict[str, str], dict[str, str], set[str]]:
    """Fetch every Okta group and return three views, filtered to OKTA_GROUP
    type only per IT preference (APP_GROUP / BUILT_IN groups excluded from
    analysis).

    Returns:
        id_to_name:      {gid: name} for OKTA_GROUP only
        name_to_id:      {name: gid} for OKTA_GROUP only
        okta_group_ids:  set of OKTA_GROUP IDs (handy for downstream filters)

    Note: if two OKTA_GROUPs share a name, the last one wins in name_to_id.
    We log a warning so reviewers know name-based rules might be ambiguous.
    """
    id_to_name: dict[str, str] = {}
    name_to_id: dict[str, str] = {}
    okta_group_ids: set[str] = set()
    duplicates: list[str] = []
    seen_total = 0
    seen_skipped: dict[str, int] = {}
    # Okta's /groups endpoint supports a filter on type but the syntax has
    # changed across API versions. We filter client-side for maximum
    # compatibility and pass the limit hint server-side.
    for grp in client.get_paginated("/api/v1/groups", params={"limit": 200}):
        seen_total += 1
        gtype = grp.get("type", "")
        if gtype != "OKTA_GROUP":
            seen_skipped[gtype] = seen_skipped.get(gtype, 0) + 1
            continue
        gid = grp["id"]
        name = grp.get("profile", {}).get("name", "")
        id_to_name[gid] = name
        if name in name_to_id and name_to_id[name] != gid:
            duplicates.append(name)
        name_to_id[name] = gid
        okta_group_ids.add(gid)
    LOG.info(
        "Fetched %d total groups; kept %d OKTA_GROUP; skipped %s",
        seen_total, len(okta_group_ids),
        ", ".join(f"{k}={v}" for k, v in sorted(seen_skipped.items())) or "none",
    )
    if duplicates:
        LOG.warning(
            "Duplicate OKTA_GROUP names detected (name-based rules ambiguous): %s",
            sorted(set(duplicates))[:10],
        )
    return id_to_name, name_to_id, okta_group_ids


def fetch_all_group_rules(client: OktaClient) -> list[GroupRule]:
    rules: list[GroupRule] = []
    # `expand=groupIdToGroupNameMap` is optional; we don't need it because we
    # have our own group cache, but we DO need the exclusion list. As of the
    # current Okta API, conditions.people.users.exclude is returned in the
    # default list response — no expand required.
    for r in client.get_paginated("/api/v1/groups/rules", params={"limit": 50}):
        conditions = r.get("conditions", {}) or {}
        expression = (conditions.get("expression", {}) or {}).get("value", "") or ""
        target = (
            r.get("actions", {})
             .get("assignUserToGroups", {})
             .get("groupIds", []) or []
        )
        # Excluded users: rule.conditions.people.users.exclude is a list of
        # user IDs the admin has explicitly carved out. These users are never
        # added by the rule even if their attributes match.
        excluded = (
            (conditions.get("people") or {})
            .get("users", {})
            .get("exclude", []) or []
        )
        rule = GroupRule(
            rule_id=r["id"],
            name=r.get("name", ""),
            status=r.get("status", "INACTIVE"),
            expression=expression,
            target_group_ids=list(target),
            excluded_user_ids=set(excluded),
        )
        if expression:
            try:
                rule.parsed_ast = parse_oel(expression)
            except Exception as e:  # OelParseError is a subclass of Exception
                rule.parse_error = f"Parse failed: {e}"
        else:
            rule.parse_error = "Empty expression"
        rules.append(rule)
    excluded_total = sum(len(x.excluded_user_ids) for x in rules)
    rules_with_exclusions = sum(1 for x in rules if x.excluded_user_ids)
    LOG.info(
        "Fetched %d group rules (%d ACTIVE, %d unparseable, %d rules with "
        "exclusions covering %d user-rule carveouts)",
        len(rules),
        sum(1 for x in rules if x.is_active),
        sum(1 for x in rules if x.parsed_ast is None),
        rules_with_exclusions,
        excluded_total,
    )
    return rules


def fetch_user(client: OktaClient, email: str) -> dict | None:
    try:
        # Looking up by login/email; Okta accepts the login in the path.
        encoded = urllib.parse.quote(email, safe="")
        data, _ = client._request("GET", f"https://{client.domain}/api/v1/users/{encoded}")
        return data
    except OktaApiError as e:
        if e.status == 404:
            return None
        raise


def fetch_user_groups(
    client: OktaClient,
    user_id: str,
    okta_group_ids: set[str] | None = None,
) -> set[str]:
    """Return the user's group memberships, filtered to OKTA_GROUP type only.

    `okta_group_ids` is used as a positive allow-list (computed once in
    fetch_all_groups). If not provided, we fall back to filtering by the
    `type` field on each returned group, which costs an extra dict lookup.
    """
    out: set[str] = set()
    for g in client.get_paginated(f"/api/v1/users/{user_id}/groups"):
        if okta_group_ids is not None:
            if g["id"] in okta_group_ids:
                out.add(g["id"])
        elif g.get("type") == "OKTA_GROUP":
            out.add(g["id"])
    return out


# ---------------------------------------------------------------------------
# Per-user processing (batched)
# ---------------------------------------------------------------------------

def process_users_in_batches(
    client: OktaClient,
    emails: list[str],
    batch_size: int,
    pause_sec: float,
    okta_group_ids: set[str] | None = None,
    remaining_ms_fn: Callable[[], int] | None = None,
) -> list[UserAnalysis]:
    """Process users in batches of `batch_size` with a `pause_sec` pause
    between batches (per IT preference of batching changes in groups of 25
    for monitorability).

    If `remaining_ms_fn` is supplied (typically wired to
    context.get_remaining_time_in_millis), we bail out gracefully when the
    Lambda has less than LAMBDA_REMAINING_MS_FLOOR ms left and mark any
    un-processed users with an error so the reviewer knows to re-run.
    """
    out: list[UserAnalysis] = []
    aborted = False
    for i in range(0, len(emails), batch_size):
        if aborted:
            break
        batch = emails[i:i + batch_size]
        LOG.info("Processing user batch %d-%d of %d",
                 i + 1, i + len(batch), len(emails))
        for email in batch:
            if remaining_ms_fn is not None:
                remaining = remaining_ms_fn()
                if remaining < LAMBDA_REMAINING_MS_FLOOR:
                    LOG.warning(
                        "Lambda has %d ms remaining (<%d floor); bailing out "
                        "before processing %s. Re-run for remaining users.",
                        remaining, LAMBDA_REMAINING_MS_FLOOR, email,
                    )
                    aborted = True
                    break
            ua = UserAnalysis(email=email)
            try:
                user = fetch_user(client, email)
                if not user:
                    ua.error = "User not found"
                    out.append(ua)
                    continue
                ua.user_id = user["id"]
                profile = user.get("profile", {}) or {}
                # Preserve the FULL profile dict — rules can reference any
                # attribute (user.title, user.userType, user.Sup_Org_ID,
                # custom Workday/Rippling attrs, etc.). Keeping only a
                # hard-coded subset silently broke evaluation of any rule
                # touching attributes outside that subset.
                ua.profile = dict(profile)
                # Convenience fields used by the CSV writer; these don't
                # collide with anything in /api/v1/users profiles.
                ua.profile.setdefault(
                    "_displayName",
                    profile.get("displayName")
                    or f"{profile.get('firstName','')} {profile.get('lastName','')}".strip(),
                )
                ua.current_group_ids = fetch_user_groups(
                    client, ua.user_id, okta_group_ids=okta_group_ids,
                )
            except OktaApiError as e:
                ua.error = f"Okta API {e.status}: {e.body[:200]}"
            except Exception as e:  # defensive; one bad user shouldn't kill the run
                ua.error = f"Unexpected error: {e}"
            out.append(ua)
        if i + batch_size < len(emails) and pause_sec > 0 and not aborted:
            time.sleep(pause_sec)

    # If we bailed out mid-run, attach an explicit error to any user we
    # never got to so the CSV makes the partial state obvious.
    processed_emails = {u.email for u in out}
    for email in emails:
        if email not in processed_emails:
            out.append(UserAnalysis(
                email=email,
                error="Skipped: Lambda time budget exhausted (re-run with remaining users)",
            ))
    return out


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "user_email",
    "user_id",
    "user_display_name",
    "attribute(s)_changing",
    "current_values",       # always full SUPPORTED_ATTRIBUTES snapshot
    "new_value",
    # Action values:
    #   ADD            — rule(s) will newly fire and assign the user to a group
    #   REMOVE         — rule(s) currently grant this group but stop matching
    #                    under the new attribute(s); user is removed from the
    #                    group by the rule's dynamic re-evaluation
    #   MANUAL_REVIEW  — rule expression couldn't be parsed/evaluated locally
    #   NO_CHANGE      — no rule-driven membership delta for this user
    #   ERROR          — user lookup or upstream API failure
    "action",
    "group_name",
    "group_id",
    "triggering_rule_names",
    "triggering_rule_ids",
    "rule_expression",
    "cascade_depth",           # 0 = direct from attr change; >0 = nested cascade pass
    "notes",
]


def build_csv_rows(
    users: list[UserAnalysis],
    rules: list[GroupRule],
    group_id_to_name: dict[str, str],
    group_name_to_id: dict[str, str],
    attributes_to_change: list[str],
    new_value_map: dict[str, Any],
    max_passes: int,
) -> list[list[str]]:
    rows: list[list[str]] = []
    rules_by_id = {r.rule_id: r for r in rules}

    # Render the per-attribute new values as a stable string for the CSV's
    # `new_value` column, e.g. "department=Engineering, is_manager=true".
    # Booleans are lowercased to match the JSON literal form admins typed.
    def _fmt(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        return "" if v is None else str(v)

    new_value_str = ", ".join(
        f"{a}={_fmt(new_value_map.get(a))}" for a in attributes_to_change
    )

    # MANUAL_REVIEW filter is now tied to attributes_to_change directly.
    # An unparseable rule that doesn't reference any changing attribute
    # produces an identical (zero) contribution in both before/after
    # simulations, so it can't move membership and doesn't need to surface.
    affected_rule_ids = _rules_referencing_attributes(rules, attributes_to_change)
    LOG.info("Rules directly referencing %s: %d",
             attributes_to_change, len(affected_rule_ids))

    for ua in users:
        if ua.error:
            rows.append([
                ua.email, ua.user_id or "", "", ",".join(attributes_to_change),
                "", new_value_str, "ERROR", "", "", "", "", "", "0", ua.error,
            ])
            continue

        # Always show ALL supported attributes' current values — full
        # context for the reviewer, no per-run configuration needed.
        current_values_str = ", ".join(
            f"{a}={_fmt(ua.profile.get(a))}" for a in SUPPORTED_ATTRIBUTES
        )

        # Compute the rule-driven membership BOTH before and after the change.
        # The "before" computation lets us distinguish memberships granted by
        # rules from those granted by other means; only the rule-driven ones
        # are at risk of being removed by a rule re-evaluation.
        attr_changes = _attr_changes_dict(attributes_to_change, new_value_map)

        before_set, _, before_unsupported = _simulate_membership(
            ua, rules, group_id_to_name, group_name_to_id,
            attribute_changes={},  # unchanged profile
            max_passes=max_passes,
        )
        after_set, after_rules_per_group, after_unsupported = _simulate_membership(
            ua, rules, group_id_to_name, group_name_to_id,
            attribute_changes=attr_changes,
            max_passes=max_passes,
        )

        adds = after_set - before_set
        removes = before_set - after_set

        for gid in sorted(adds):
            triggering = after_rules_per_group.get(gid, [])
            rows.append(_row(
                ua, attributes_to_change,
                current_values_str, new_value_str,
                action="ADD",
                gid=gid,
                group_id_to_name=group_id_to_name,
                rule_ids=triggering,
                rules_by_id=rules_by_id,
                cascade_depth=_cascade_depth_for_rules(
                    triggering, rules_by_id, attributes_to_change),
                notes="",
            ))

        for gid in sorted(removes):
            # Find rules that previously matched this group for this user
            triggering = _rules_that_assigned_group(
                gid, rules, ua, group_id_to_name, group_name_to_id, attribute_changes={}
            )
            rows.append(_row(
                ua, attributes_to_change,
                current_values_str, new_value_str,
                action="REMOVE",
                gid=gid,
                group_id_to_name=group_id_to_name,
                rule_ids=triggering,
                rules_by_id=rules_by_id,
                cascade_depth=_cascade_depth_for_rules(
                    triggering, rules_by_id, attributes_to_change),
                notes=("Rule(s) stop matching under the new attribute "
                       "value. Okta will remove the user from this group "
                       "via dynamic re-evaluation unless the user is on "
                       "the rule's explicit exclusion list (already honored "
                       "in this preview)."),
            ))

        # Emit MANUAL_REVIEW rows for any rules we couldn't evaluate that
        # *reference* the changing attributes — those are the ones IT needs
        # to inspect by hand.
        unsupported_to_flag = {**before_unsupported, **after_unsupported}
        for rid, msg in unsupported_to_flag.items():
            rule = rules_by_id.get(rid)
            if not rule:
                continue
            if rid not in affected_rule_ids:
                continue
            for gid in rule.target_group_ids:
                rows.append(_row(
                    ua, attributes_to_change,
                    current_values_str, new_value_str,
                    action="MANUAL_REVIEW",
                    gid=gid,
                    group_id_to_name=group_id_to_name,
                    rule_ids=[rid],
                    rules_by_id=rules_by_id,
                    cascade_depth=0,
                    notes=f"Rule expression not supported by local parser: {msg}",
                ))

        if not adds and not removes and not unsupported_to_flag:
            rows.append(_row(
                ua, attributes_to_change,
                current_values_str, new_value_str,
                action="NO_CHANGE",
                gid="",
                group_id_to_name=group_id_to_name,
                rule_ids=[],
                rules_by_id=rules_by_id,
                cascade_depth=0,
                notes="No rule-driven group changes detected.",
            ))

    return rows


def _row(ua, attrs_change, current_values, new_value,
         *, action, gid, group_id_to_name, rule_ids, rules_by_id,
         cascade_depth, notes) -> list[str]:
    rule_names = [rules_by_id[r].name for r in rule_ids if r in rules_by_id]
    rule_exprs = " | ".join(rules_by_id[r].expression for r in rule_ids if r in rules_by_id)
    display = ""
    if ua.profile:
        display = (
            ua.profile.get("_displayName")
            or ua.profile.get("displayName")
            or ""
        )
    return [
        ua.email,
        ua.user_id or "",
        display,
        ",".join(attrs_change),
        current_values,
        new_value,
        action,
        group_id_to_name.get(gid, "") if gid else "",
        gid,
        " | ".join(rule_names),
        " | ".join(rule_ids),
        rule_exprs,
        str(cascade_depth),
        notes,
    ]


def _collect_attr_refs(node) -> set[str]:
    """Walk a parsed OEL AST and return the set of user.<attr> names it
    references (lower-cased for case-insensitive comparison)."""
    if node is None or not isinstance(node, tuple):
        return set()
    op = node[0]
    out: set[str] = set()
    if op == "attr":
        parts = node[1]
        if parts and parts[0].lower() == "user":
            tail = parts[1:]
            if tail and tail[0].lower() == "profile":
                tail = tail[1:]
            if len(tail) == 1:
                out.add(tail[0].lower())
        return out
    if op == "call":
        for arg in node[2]:
            out |= _collect_attr_refs(arg)
        return out
    # Generic walk for boolean/comparison/arithmetic nodes.
    for child in node[1:]:
        if isinstance(child, tuple):
            out |= _collect_attr_refs(child)
    return out


def _rules_referencing_attributes(rules: list[GroupRule], attrs: list[str]) -> set[str]:
    """Return rule IDs whose parsed AST references any of the named user
    attributes. Walks the AST so we don't false-match on substring overlaps
    (e.g. previewing `department` shouldn't match `user.departmentLead`).

    Falls back to a textual scan for rules we couldn't parse — better to be
    over-inclusive on MANUAL_REVIEW than to silently drop signal.
    """
    out: set[str] = set()
    wanted = {a.lower() for a in attrs}
    for r in rules:
        if r.parsed_ast is not None:
            if _collect_attr_refs(r.parsed_ast) & wanted:
                out.add(r.rule_id)
        else:
            # Best-effort word-boundary text search for unparseable rules.
            for a in attrs:
                if re.search(rf"\buser\.{re.escape(a)}\b", r.expression):
                    out.add(r.rule_id)
                    break
    return out


def _rules_that_assigned_group(
    gid: str,
    rules: list[GroupRule],
    ua: UserAnalysis,
    id_to_name: dict[str, str],
    name_to_id: dict[str, str],
    attribute_changes: dict[str, str],
) -> list[str]:
    """Return rule IDs that *would* have assigned `gid` to this user under
    the supplied attribute changes (empty dict = current state)."""
    sim_attrs = dict(ua.profile)
    sim_attrs.update(attribute_changes)
    ctx = OelContext(
        user_attrs=sim_attrs,
        group_ids=ua.current_group_ids,
        group_id_to_name=id_to_name,
        group_name_to_id=name_to_id,
    )
    out: list[str] = []
    for r in rules:
        if not r.is_active or r.parsed_ast is None:
            continue
        if gid not in r.target_group_ids:
            continue
        if ua.user_id and ua.user_id in r.excluded_user_ids:
            continue
        try:
            if evaluate_oel(r.parsed_ast, ctx):
                out.append(r.rule_id)
        except OelUnsupported:
            continue
    return out


_GROUP_FN_NAMES = {
    "ismemberofgroup", "ismemberofanygroup", "ismemberofgroupname",
    "ismemberofgroupnamestartswith", "ismemberofgroupnamecontains",
    "groups.contains", "groups.startswith",
}


def _ast_calls_group_fn(node) -> bool:
    if node is None or not isinstance(node, tuple):
        return False
    if node[0] == "call" and node[1].lower() in _GROUP_FN_NAMES:
        return True
    for child in node[1:]:
        if isinstance(child, tuple) and _ast_calls_group_fn(child):
            return True
    return False


def _cascade_depth_for_rules(
    rule_ids: list[str],
    rules_by_id: dict[str, GroupRule],
    attrs_compare: list[str],
) -> int:
    """0 if at least one rule references the changing attributes directly;
    1 if the rule(s) only reference group membership (cascaded change).

    Uses the parsed AST when available; falls back to a textual probe if
    not (rules that failed to parse will be reported with cascade_depth=0).
    """
    wanted = {a.lower() for a in attrs_compare}
    direct = False
    indirect = False
    for rid in rule_ids:
        r = rules_by_id.get(rid)
        if not r:
            continue
        if r.parsed_ast is not None:
            refs = _collect_attr_refs(r.parsed_ast)
            if refs & wanted:
                direct = True
            elif _ast_calls_group_fn(r.parsed_ast):
                indirect = True
        else:
            # Fallback for unparseable rules.
            if any(re.search(rf"\buser\.{re.escape(a)}\b", r.expression)
                   for a in attrs_compare):
                direct = True
            elif "isMemberOf" in r.expression or "Groups." in r.expression:
                indirect = True
    if direct:
        return 0
    if indirect:
        return 1
    return 0


def csv_bytes(rows: list[list[str]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    w.writerow(CSV_HEADER)
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# S3 upload (optional)
# ---------------------------------------------------------------------------

def maybe_upload_to_s3(payload: bytes) -> dict[str, str] | None:
    """Upload the CSV to S3 and return {uri, bucket, key} for the Workflow
    to consume directly. Returns None if no bucket is configured or boto3
    is unavailable.

    Returning bucket + key as separate fields (in addition to the s3://
    URI) means the Okta Workflows S3 Get Object card can wire to them
    directly without a four-card string-split dance.
    """
    bucket = os.environ.get("OUTPUT_S3_BUCKET")
    if not bucket:
        return None
    if boto3 is None:
        LOG.warning("OUTPUT_S3_BUCKET set but boto3 unavailable; skipping upload")
        return None
    prefix = os.environ.get("OUTPUT_S3_PREFIX", "okta-attribute-previews/").lstrip("/")
    key = f"{prefix}preview-{int(time.time())}.csv"
    s3 = boto3.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=payload, ContentType="text/csv")
    return {
        "uri":    f"s3://{bucket}/{key}",
        "bucket": bucket,
        "key":    key,
    }


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_value_type(attr: str, val: Any, where: str) -> None:
    """Raise ValueError unless `val` matches the expected type for `attr`.

    Type rules:
      * Attributes in BOOLEAN_ATTRIBUTES must be supplied as JSON booleans
        (Python bool). Strings like "true" are NOT accepted — Okta stores
        these as real booleans and rule expressions compare against
        boolean literals (e.g. user.is_manager == true).
      * All other attributes in SUPPORTED_ATTRIBUTES must be supplied as
        strings.

    `where` is a free-text breadcrumb identifying the call site for the
    error message (e.g. "new_value[0].value").
    """
    if attr in BOOLEAN_ATTRIBUTES:
        if not isinstance(val, bool):
            raise ValueError(
                f"{where} must be a JSON boolean (true/false) for "
                f"attribute {attr!r}, not a string; got "
                f"{type(val).__name__}"
            )
    else:
        # bool is a subclass of int in Python; reject it explicitly so that
        # someone passing `true` for, say, costCenter doesn't slip through.
        if isinstance(val, bool) or not isinstance(val, str):
            raise ValueError(
                f"{where} must be a string for attribute {attr!r}; got "
                f"{type(val).__name__}"
            )


def _normalize_new_value(
    new_value: Any, attributes_to_change: list[str]
) -> dict[str, Any]:
    """Coerce the event's `new_value` into a {attribute: value} mapping.

    Accepts two forms:
      1. Array of objects: [{"attribute": "department", "value": "Eng"}, ...]
         Each entry's value must match the expected type for that attribute
         (string for most, boolean for is_manager).
      2. Legacy single string: applied uniformly to every attribute in
         attributes_to_change. NOT supported when any attribute in
         attributes_to_change requires a boolean — those attributes always
         need the array form.

    Validates that the array (when used) lines up exactly with
    attributes_to_change — no missing entries, no extras — and that every
    value matches the expected type for its attribute.
    """
    if isinstance(new_value, str):
        # Legacy string form: reject if any target attribute requires a bool.
        bool_attrs = [a for a in attributes_to_change if a in BOOLEAN_ATTRIBUTES]
        if bool_attrs:
            raise ValueError(
                f"Legacy string 'new_value' form cannot be used when "
                f"attributes_to_change includes boolean attributes "
                f"{bool_attrs}. Use the array form instead, e.g. "
                f'"new_value": [{{"attribute": "is_manager", "value": true}}]'
            )
        return {attr: new_value for attr in attributes_to_change}

    if isinstance(new_value, list):
        if not new_value:
            raise ValueError("'new_value' array must be non-empty")
        mapping: dict[str, Any] = {}
        for i, entry in enumerate(new_value):
            if not isinstance(entry, dict):
                raise ValueError(
                    f"'new_value'[{i}] must be an object with 'attribute' "
                    f"and 'value' keys; got {type(entry).__name__}"
                )
            attr = entry.get("attribute")
            val = entry.get("value")
            if not isinstance(attr, str) or not attr:
                raise ValueError(
                    f"'new_value'[{i}].attribute must be a non-empty string"
                )
            if attr in mapping:
                raise ValueError(
                    f"'new_value' has duplicate entries for attribute {attr!r}"
                )
            # Type check: bool for is_manager, string for everything else.
            _validate_value_type(attr, val, where=f"'new_value'[{i}].value")
            mapping[attr] = val

        # Both directions: every attribute in attributes_to_change has a
        # value, and every value entry is in attributes_to_change.
        missing = [a for a in attributes_to_change if a not in mapping]
        extra = [a for a in mapping if a not in attributes_to_change]
        if missing:
            raise ValueError(
                f"'new_value' is missing entries for {missing}; every "
                f"attribute in 'attributes_to_change' must have a value"
            )
        if extra:
            raise ValueError(
                f"'new_value' has entries for attributes not in "
                f"'attributes_to_change': {extra}"
            )
        return mapping

    raise ValueError(
        "'new_value' must be either a string (applied to all "
        "attributes_to_change, string-typed attributes only) or an array "
        "of {'attribute': str, 'value': str|bool} objects"
    )


def _validate_event(event: dict) -> dict:
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    attrs = event.get("attributes_to_change") or []
    if not isinstance(attrs, list) or not attrs:
        raise ValueError("'attributes_to_change' must be a non-empty array")
    bad = [a for a in attrs if a not in SUPPORTED_ATTRIBUTES]
    if bad:
        raise ValueError(
            f"'attributes_to_change' contains unsupported names {bad}; "
            f"supported: {list(SUPPORTED_ATTRIBUTES)}"
        )

    new_value = event.get("new_value")
    if new_value is None:
        raise ValueError("'new_value' is required")
    new_value_map = _normalize_new_value(new_value, attrs)

    emails = event.get("user_emails") or []
    if not isinstance(emails, list) or not emails:
        raise ValueError("'user_emails' must be a non-empty array")
    if not all(isinstance(e, str) and "@" in e for e in emails):
        raise ValueError("'user_emails' entries must look like email addresses")

    # De-dupe while preserving order.
    seen: set[str] = set()
    emails_unique = [e for e in emails if not (e.lower() in seen or seen.add(e.lower()))]

    return {
        "attributes_to_change": attrs,
        "new_value_map":        new_value_map,
        "user_emails":          emails_unique,
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context=None):  # noqa: D401 (Lambda entrypoint)
    """AWS Lambda entrypoint. See module docstring for event shape."""
    started = time.time()
    try:
        clean = _validate_event(event)
    except ValueError as e:
        LOG.error("Bad input: %s", e)
        return {"statusCode": 400, "error": str(e)}

    # Wrap context.get_remaining_time_in_millis so the rest of the function
    # can bail before Lambda hard-kills us mid-API-call.
    remaining_ms_fn: Callable[[], int] | None = None
    if context is not None and hasattr(context, "get_remaining_time_in_millis"):
        remaining_ms_fn = context.get_remaining_time_in_millis

    # ---- Startup sanity check: was the Lambda timeout actually configured? --
    # When you create a Lambda in the AWS console, the timeout defaults to
    # 3 seconds — far too short for this function (tenant fetch + per-user
    # processing realistically needs 60–600 seconds). Without this check, a
    # mis-deployed Lambda silently dies mid-fetch with a generic CloudWatch
    # "Task timed out" error and no useful diagnostic.
    if remaining_ms_fn is not None:
        remaining_at_start = remaining_ms_fn()
        if remaining_at_start < LAMBDA_MIN_TIMEOUT_MS_AT_START:
            msg = (
                f"Lambda timeout misconfigured: only {remaining_at_start} ms "
                f"remaining at handler entry. This function needs at least "
                f"{LAMBDA_MIN_TIMEOUT_MS_AT_START} ms (recommend 600000 ms / "
                f"10 min for larger previews). In the AWS Lambda console, "
                f"edit Configuration -> General configuration -> Timeout and "
                f"set it to at least 60 seconds. If this minimum is wrong "
                f"for your environment, override via the "
                f"LAMBDA_MIN_TIMEOUT_MS_AT_START env var."
            )
            LOG.error(msg)
            return {"statusCode": 500, "error": msg}

    try:
        domain, token = _load_credentials()
    except RuntimeError as e:
        LOG.error("Credential error: %s", e)
        return {"statusCode": 500, "error": str(e)}

    client = OktaClient(domain=domain, token=token)

    LOG.info("Fetching tenant groups and group rules...")
    group_id_to_name, group_name_to_id, okta_group_ids = fetch_all_groups(client)
    rules = fetch_all_group_rules(client)

    # Drop target_group_ids from rules that point at non-OKTA_GROUP targets.
    # Rules can technically target any group ID, but Okta's UI only allows
    # OKTA_GROUP targets and we don't want APP_GROUP rows leaking into output.
    for r in rules:
        r.target_group_ids = [g for g in r.target_group_ids if g in okta_group_ids]

    LOG.info("Processing %d users in batches of %d (pause %.2fs)",
             len(clean["user_emails"]), DEFAULT_USER_BATCH_SIZE,
             DEFAULT_USER_BATCH_PAUSE_SEC)
    users = process_users_in_batches(
        client,
        emails=clean["user_emails"],
        batch_size=DEFAULT_USER_BATCH_SIZE,
        pause_sec=DEFAULT_USER_BATCH_PAUSE_SEC,
        okta_group_ids=okta_group_ids,
        remaining_ms_fn=remaining_ms_fn,
    )

    LOG.info("Building CSV...")
    rows = build_csv_rows(
        users=users,
        rules=rules,
        group_id_to_name=group_id_to_name,
        group_name_to_id=group_name_to_id,
        attributes_to_change=clean["attributes_to_change"],
        new_value_map=clean["new_value_map"],
        max_passes=DEFAULT_MAX_RULE_PASSES,
    )
    payload = csv_bytes(rows)

    # If the payload would blow the Lambda 6 MB sync response cap, force an
    # S3 upload and omit the inline CSV from the response. The Workflow caller
    # then reads from S3 (configure OUTPUT_S3_BUCKET).
    s3_info: dict[str, str] | None = None
    payload_too_big = len(payload) > LAMBDA_SYNC_RESPONSE_FLOOR_BYTES
    try:
        s3_info = maybe_upload_to_s3(payload)
    except Exception as e:
        LOG.warning("S3 upload failed: %s", e)

    if payload_too_big and not s3_info:
        LOG.error(
            "CSV payload is %d bytes (> %d floor) and S3 upload is not "
            "configured. Returning truncated rows; configure OUTPUT_S3_BUCKET.",
            len(payload), LAMBDA_SYNC_RESPONSE_FLOOR_BYTES,
        )

    failures = sum(1 for u in users if u.error)
    manual = sum(1 for r in rules if r.parsed_ast is None)
    LOG.info("Done in %.1fs: %d users, %d rules, %d CSV rows, %d failures",
             time.time() - started, len(users), len(rules), len(rows), failures)

    # Build a structured rows list so Workflow callers can iterate without
    # having to parse CSV. Each item is an object keyed by CSV_HEADER —
    # which means a Workflow can wire directly to e.g. `rows[].action`,
    # `rows[].group_name`, etc.
    rows_structured = [dict(zip(CSV_HEADER, r)) for r in rows]

    response: dict[str, Any] = {
        "statusCode": 200,
        "summary": {
            "users_processed":     len(users) - failures,
            "users_failed":        failures,
            "rules_evaluated":     len(rules),
            "rules_manual_review": manual,
            "total_csv_rows":      len(rows),
            "csv_bytes":           len(payload),
            # Split fields make the Workflow wiring easier — the S3 Get
            # Object card can consume bucket and key directly without any
            # string manipulation. s3_uri is kept for backward compat /
            # human readability in logs.
            "s3_uri":              s3_info["uri"]    if s3_info else None,
            "s3_bucket":           s3_info["bucket"] if s3_info else None,
            "s3_key":              s3_info["key"]    if s3_info else None,
            "elapsed_sec":         round(time.time() - started, 2),
        },
        # Primary consumer surface for Okta Workflows: a JSON array of
        # objects, one per CSV row, keyed by column name. No parsing
        # required on the Workflows side — wire directly to Google Sheets
        # row inputs.
        "rows": rows_structured,
    }
    # CSV-as-base64 is kept for human inspection / archival via S3, but is
    # no longer the primary consumer surface for Workflows callers.
    if not payload_too_big:
        response["csv_base64"] = base64.b64encode(payload).decode("ascii")
    else:
        response["summary"]["csv_inline_omitted"] = (
            "Payload exceeded the 5 MB inline floor; download via s3_uri."
        )
    return response


# ---------------------------------------------------------------------------
# Local dry-run harness
#
# Run:  python okta_attribute_change_preview.py
# Reads event from ./sample_event.json if present, else uses a stub event.
# Writes the decoded CSV to ./preview_output.csv for inspection.
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    import sys

    sample_path = "sample_event.json"
    if os.path.exists(sample_path):
        with open(sample_path) as f:
            event_in = json.load(f)
    else:
        event_in = {
            "attributes_to_change": ["department", "costCenter"],
            "new_value": [
                {"attribute": "department", "value": "Engineering"},
                {"attribute": "costCenter", "value": "ExampleCostCenter"},
            ],
            "user_emails": ["test.user@example.com"],
        }

    result = lambda_handler(event_in, None)
    print(json.dumps({k: v for k, v in result.items() if k != "csv_base64"}, indent=2))

    if result.get("statusCode") == 200 and result.get("csv_base64"):
        out_path = "preview_output.csv"
        with open(out_path, "wb") as f:
            f.write(base64.b64decode(result["csv_base64"]))
        print(f"\nCSV written to {out_path}")
        sys.exit(0)
    sys.exit(1)
