#!/bin/bash
# =============================================================================
# jamf_okta_attribute_preview_v1.sh
# Okta Attribute Change Preview Tool — Jamf Self Service · swiftDialog UI
#
# WHAT THIS DOES
# ──────────────
# Provides a swiftDialog-driven interface that lets an IT admin assemble
# the payload for the okta_attribute_change_preview Lambda (invoked via
# an Okta Workflow API Endpoint trigger). The flow is:
#   1. macOS file picker (osascript "choose file") — admin selects a CSV
#      containing the users to preview. The CSV must be a single column
#      with header `email`.
#   2. Selection dialog — checkboxes to pick one or more supported
#      profile attributes and confirm the admin email.
#   3. Value dialog — admin enters the new value for each selected
#      attribute.
#   4. The script POSTs a JSON body to the Workflows API Endpoint URL
#      with bearer auth, and surfaces the response in a final dialog.
#
# OUTBOUND JSON SHAPE
# ───────────────────
# {
#   "attributes_to_change": ["department", "costCenter"],
#   "new_value": [
#       {"attribute": "department", "value": "Engineering"},
#       {"attribute": "costCenter", "value": "ExampleCostCenter"}
#   ],
#   "user_emails": ["alice@example.com", "bob@example.com"],
#   "admin_email": "admin@example.com"
# }
#
# The Workflow API Endpoint trigger maps attributes_to_change / new_value
# / user_emails into the Lambda action card's payload object, and routes
# admin_email separately (e.g. to an email action card). admin_email is
# deliberately NOT included in the Lambda payload — the Lambda's input
# validator rejects unknown keys.
#
# AUTH
# ────
# The Workflows API Endpoint trigger is configured with the "Client Token
# in URL" auth mode, so the client token is appended to the invoke URL as
# the `clientToken` query parameter:
#     https://<tenant>.workflows.okta.com/api/flo/<id>/invoke?clientToken=<token>
# No separate Authorization header is sent — Workflows reads the token
# from the query string and rejects the request if it's missing/wrong.
# The script accepts the full URL (token included) as Jamf parameter $4.
#
# Threat model: any Jamf admin with view rights on this policy can read
# the URL — and therefore the token — from the Jamf Pro UI. Scope policy
# view permissions accordingly. The URL also briefly appears in argv to
# /usr/bin/curl during the POST (visible to a `ps` snapshot that lands
# inside that millisecond window). On an IT-managed Mac with no untrusted
# local processes this is not a meaningful exposure.
#
# Logging: the script strips the query string from the URL before
# writing it to /var/log/jamf_okta_attribute_preview.log so the token
# does not get persisted to disk in plain text.
#
# DEPENDENCIES
# ────────────
#  swiftDialog >= 2.3  at /usr/local/bin/dialog
#  plutil              (base macOS — parses swiftDialog --json output)
#  curl                (base macOS — Workflow API POST)
#  /usr/bin/osascript  (base macOS — file picker via Standard Additions
#                       'choose file'. No PPPC required: choose file does
#                       not send AppleEvents to another app.)
#  Pre-stage swiftDialog via a scoped Jamf policy before users trigger this.
#
# CSV INPUT FORMAT
# ────────────────
# The admin attaches a CSV whose FIRST column has the header `email`
# (case-insensitive). Additional columns to the right are ignored —
# pasting from a multi-column spreadsheet export is fine as long as the
# email addresses are in column 1. Every row's first column is read as
# one email address. Blank rows and rows with a blank first column are
# skipped. Addresses are lowercased and deduplicated. UTF-8 BOM is
# tolerated. The CSV is read in the console user's GUI context via
# `run_as_user cat` so macOS's powerbox grants implicit file access for
# whatever the user picked — root reading TCC-protected user folders
# directly (Documents, Desktop, Downloads, iCloud Drive) is unreliable
# on modern macOS, so we route through the user's process.
#
# JAMF PARAMETERS
# ───────────────
#  $4 — Workflow API endpoint URL (with client token)    (required)
#       Paste the full Invoke URL from the API Endpoint trigger card,
#       including the `?clientToken=<token>` query parameter. Example:
#         https://example.workflows.okta.com/api/flo/abc.../invoke?clientToken=...
#       Treat as a secret; visible to Jamf admins with view rights on
#       this policy.
#
# SECURITY NOTES
# ──────────────
#  • $4 contains both the URL and the client token. The variable
#    WORKFLOW_URL is treated as sensitive — zeroed in the cleanup trap
#    on any exit path.
#  • The URL briefly appears in argv to curl during the POST. See AUTH
#    section above for threat-model commentary.
#  • Logged POST line strips the query string so the token never lands
#    in /var/log/jamf_okta_attribute_preview.log.
#  • JSON payload is built in memory and piped to curl via --data-binary @-
#    so it never hits disk.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Jamf Parameters ────────────────────────────────────────────────────────
WORKFLOW_URL="${4:-}"                                # SENSITIVE — contains client token; zeroed in cleanup

# ── Constants ──────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="Okta Attribute Change Preview"
readonly SCRIPT_VERSION="2.3"
# v2.3 — Two related fixes:
#        (1) post_to_workflow now sets a global WORKFLOW_OUTCOME instead
#            of echoing the result token, so the function's own info()
#            log lines (which go through `tee`) don't contaminate the
#            captured value. Previously every workflow run hit the
#            generic *) "Unexpected Response" branch instead of the
#            correct error-class dialog.
#        (2) SERVER_ERROR (HTTP 5xx) result dialog rewritten to
#            acknowledge the common false-negative case where Okta
#            Workflows' synchronous response window times out but the
#            flow keeps running in the background and completes
#            normally. The dialog now tells the user to check Slack
#            before assuming failure.
# v2.2 — Workflow auth via URL query parameter. The Workflows API
#        Endpoint trigger is configured for "Client Token in URL", so
#        $4 now holds the full Invoke URL including the
#        `?clientToken=<token>` query string and no separate Authorization
#        header is sent. Removed: $5 (token), $6/$7 (header name/prefix),
#        AUTH_HEADER_NAME, AUTH_HEADER_PREFIX, WORKFLOW_API_KEY. The
#        URL itself is now treated as sensitive (zeroed in cleanup,
#        query string stripped from log output via log_safe_url).
# v2.1 — Loosened CSV validation. The script previously required a
#        single-column CSV with header exactly `email`; multi-column
#        spreadsheet exports were rejected. Now we only check that the
#        FIRST column header is `email` (case-insensitive) and only
#        read the first column on each data row — additional columns
#        are silently ignored.
# v2.0 — Drop System Keychain credential staging entirely. Token is now
#        passed directly as Jamf script parameter $5 on this policy.
#        Removed: load_workflow_api_key, keychain_has_entry, KC_* constants,
#        install-tool-keychain auto-trigger, Credential Missing dialog,
#        and the companion jamf_deploy_workflow_credential.sh script.
#        Rationale: the token was already pasted into a Jamf policy
#        (the deployer), so the keychain layer was added complexity
#        without a meaningful threat-model improvement — same admins,
#        same view rights, same exposure surface.
# v1.1 — bash 3.2 compatibility (macOS /bin/bash). Replaced `declare -A`
#        with case-statement lookup functions + parallel arrays. Without
#        this, the script crashed at parse time with
#        "<attrname>: unbound variable" because bash 3.2 treats
#        `[name]=value` as an arithmetic-index expression that
#        evaluates `name` as a variable reference.
readonly LOG_FILE="/var/log/jamf_okta_attribute_preview.log"
readonly DIALOG_BIN="/usr/local/bin/dialog"
readonly SD_RES_PREFIX="/var/tmp/jamf_oap_res"
readonly PLUTIL="/usr/bin/plutil"
readonly CURL="/usr/bin/curl"
readonly OKTA_EMAIL_DOMAIN="example.com"
readonly SD_INSTALL_TRIGGER="install-swiftdialog"
readonly SD_INSTALL_WAIT=60          # max seconds to wait for swiftDialog install
readonly HTTP_TIMEOUT=60             # workflow POST timeout (workflows can take a while)

# ── Attribute catalogue ────────────────────────────────────────────────────
# Friendly label, type, and prompt for every Lambda-supported attribute.
# Display order is preserved via ATTR_ORDER. Types: "string" or "bool".
#
# IMPORTANT: macOS ships /bin/bash 3.2.57, which does NOT support
# associative arrays (`declare -A`). We use case-statement lookup
# functions here so the script runs unmodified on stock macOS bash
# without requiring Homebrew bash.
ATTR_ORDER=(department costCenter division office countryCode userType is_manager)

attr_label() {
    case "$1" in
        department)  printf '%s' "Department" ;;
        costCenter)  printf '%s' "Cost Center" ;;
        division)    printf '%s' "Division" ;;
        office)      printf '%s' "Office Location" ;;
        countryCode) printf '%s' "Country Code (ISO 2-letter)" ;;
        userType)    printf '%s' "User Type" ;;
        is_manager)  printf '%s' "Manager Flag" ;;
        *)           printf '%s' "$1" ;;
    esac
}

attr_type() {
    case "$1" in
        is_manager) printf '%s' "bool" ;;
        *)          printf '%s' "string" ;;
    esac
}

attr_prompt() {
    case "$1" in
        department)  printf '%s' "e.g. Engineering" ;;
        costCenter)  printf '%s' "e.g. ExampleCostCenter" ;;
        division)    printf '%s' "e.g. Technology" ;;
        office)      printf '%s' "e.g. San Francisco" ;;
        countryCode) printf '%s' "e.g. US" ;;
        userType)    printf '%s' "e.g. Employee" ;;
        is_manager)  printf '%s' "must be true or false" ;;
        *)           printf '%s' "" ;;
    esac
}

# ── Runtime globals ────────────────────────────────────────────────────────
# SELECTED_ATTRS and SELECTED_VALUES are parallel arrays — index i of one
# corresponds to index i of the other (instead of an associative array,
# which bash 3.2 doesn't support).
CONSOLE_USER=""
ADMIN_EMAIL_DETECTED=""              # auto-detected from JC / dscl; user can override
SELECTED_ATTRS=()                    # populated from selection dialog
SELECTED_VALUES=()                   # populated from value dialog (parallel to SELECTED_ATTRS)
ADMIN_EMAIL=""                       # populated from selection dialog
USER_EMAILS_NORMALISED=()            # populated from CSV pick step
CSV_PATH=""                          # full path to the picked CSV
CSV_BASENAME=""                      # basename of the picked CSV (for UI display)
VALIDATION_ERROR_MSG=""              # shared error sink for validator functions
WORKFLOW_OUTCOME=""                  # outcome token set by post_to_workflow
TEE_PID=""                           # PID of the tee process substitution in main()

# =============================================================================
# LOGGING
# =============================================================================
log()  { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${*:2}" \
             | tee -a "$LOG_FILE"; }
info() { log "INFO " "$@"; }
warn() { log "WARN " "$@"; }
error(){ log "ERROR" "$@"; }

# =============================================================================
# CLEANUP TRAP
# =============================================================================
cleanup() {
    local code=$?
    WORKFLOW_URL="$(head -c "${#WORKFLOW_URL}" /dev/zero 2>/dev/null || true)"
    unset WORKFLOW_URL
    rm -f "${SD_RES_PREFIX}."* 2>/dev/null || true
    [[ $code -ne 0 && $code -ne 130 ]] && \
        error "Script exited with code $code — review $LOG_FILE"
    [[ -n "${TEE_PID:-}" ]] && wait "$TEE_PID" 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# HELPERS
# =============================================================================

run_as_user() {
    local user="$1"; shift
    local uid; uid=$(id -u "$user")
    launchctl asuser "$uid" sudo -u "$user" "$@"
}

# Escape a string for embedding in a JSON string literal.
json_escape() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Extract a scalar from a JSON document via plutil.
json_extract() {
    local json="$1" keypath="$2" val=""
    val=$(printf '%s' "$json" | "$PLUTIL" -extract "$keypath" raw - 2>/dev/null) || val=""
    [[ "$val" == "null" || "$val" == "<null>" ]] && val=""
    printf '%s' "$val"
}

# Parse a swiftDialog --json textfield value (handles v2 flat and v3 nested).
parse_sd_textfield() {
    local json="$1" idx="$2" label="$3" val
    val=$(json_extract "$json" "textfield.$idx.value")
    if [[ -z "$val" ]]; then
        val=$(json_extract "$json" "$label")
    fi
    printf '%s' "$val"
}

# Parse a swiftDialog --json checkbox value. Returns "true" or "false".
# swiftDialog v3.x: checkbox.<idx>.checked is a bool
# swiftDialog v2.x: top-level "<label>" is "true"/"false" string
parse_sd_checkbox() {
    local json="$1" idx="$2" label="$3" val
    val=$(json_extract "$json" "checkbox.$idx.checked")
    if [[ -z "$val" ]]; then
        val=$(json_extract "$json" "$label")
    fi
    case "$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')" in
        true|1|yes) printf 'true'  ;;
        *)          printf 'false' ;;
    esac
}

# Trim leading and trailing whitespace.
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Lowercase a string.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Basic email sanity check: contains an @, at least 1 char before and after,
# at least one dot after the @. Not RFC 5322 perfect — defensive enough to
# catch finger trouble in a Self Service form.
is_valid_email() {
    local e="$1"
    [[ "$e" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

# Strip the query string from a URL for safe logging — the workflow URL
# contains the client token as ?clientToken=<secret>, and we don't want
# the token to land in the log file. Anything after the first '?' is
# replaced with "?<redacted>".
log_safe_url() {
    local u="$1"
    if [[ "$u" == *\?* ]]; then
        printf '%s?<redacted>' "${u%%\?*}"
    else
        printf '%s' "$u"
    fi
}

# =============================================================================
# CSV PICKER + PARSER
#
# pick_csv echoes the chosen POSIX path on stdout and returns 0; returns 1
# when the user cancels the open panel.
#
# We run "choose file" via Standard Additions inside osascript launched as
# the console user. This does NOT need a PPPC AppleEvents entitlement —
# choose file presents an NSOpenPanel inside the osascript process and
# does not send an event to System Events or any other app.
#
# Filtering by file type:
#   {"csv", "public.comma-separated-values-text"}
# Some CSVs claim a generic UTI ("public.plain-text") so we offer that
# too rather than locking the picker.
# =============================================================================
pick_csv() {
    local path
    path=$(run_as_user "$CONSOLE_USER" /usr/bin/osascript <<'APPLESCRIPT' 2>/dev/null
try
    set theFile to choose file ¬
        with prompt "Choose a CSV with a single 'email' column" ¬
        of type {"csv", "public.comma-separated-values-text", "public.plain-text", "txt"}
    return POSIX path of theFile
on error number -128
    return ""
end try
APPLESCRIPT
)
    [[ -n "$path" ]] || return 1
    printf '%s' "$path"
    return 0
}

# Read a file's contents in the console user's GUI context.
# macOS's powerbox grants the user's process implicit access to a file the
# user just picked via NSOpenPanel; root can be denied for TCC-protected
# paths (Documents / Desktop / Downloads / iCloud Drive). Routing the read
# through the user's process avoids that whole class of failure.
#
# stdout: full file contents
# return: cat's exit code
read_file_as_user() {
    local path="$1"
    run_as_user "$CONSOLE_USER" /bin/cat "$path"
}

# Parse the picked CSV.
# $1 = absolute path to CSV
# Returns 0 on success and populates USER_EMAILS_NORMALISED.
# Returns 1 on failure and sets VALIDATION_ERROR_MSG to a swiftDialog-ready
# block. Caller decides whether to surface the error and re-prompt.
parse_csv_emails() {
    local path="$1"
    VALIDATION_ERROR_MSG=""
    USER_EMAILS_NORMALISED=()

    if [[ ! -f "$path" ]]; then
        VALIDATION_ERROR_MSG="**Could not read the CSV file:**\n\n• Path does not exist: \`${path}\`"
        return 1
    fi

    local content
    if ! content=$(read_file_as_user "$path" 2>/dev/null); then
        VALIDATION_ERROR_MSG="**Could not read the CSV file:**\n\n• \`${path}\` is not readable. macOS may have blocked access — try copying the file to your Desktop and picking it again."
        return 1
    fi

    if [[ -z "$content" ]]; then
        VALIDATION_ERROR_MSG="**The CSV file is empty:**\n\n\`${path}\`"
        return 1
    fi

    # Strip UTF-8 BOM if present.
    content="${content#$'\xef\xbb\xbf'}"

    # Read line-by-line. Tolerate both LF and CRLF line endings.
    local -a lines=()
    local line
    while IFS= read -r line; do
        line="${line%$'\r'}"
        lines+=("$line")
    done <<< "$content"
    # Account for content that doesn't end in a newline (the while loop
    # above misses the last line in that case for some inputs).
    if [[ "${content: -1}" != $'\n' ]]; then
        :  # heredoc <<< form already includes the trailing line; no-op
    fi

    if [[ ${#lines[@]} -lt 2 ]]; then
        VALIDATION_ERROR_MSG="**The CSV needs at least one data row:**\n\n• Row 1 must be the header \`email\`.\n• Rows 2+ each contain one email address."
        return 1
    fi

    # Extract just the FIRST CSV field of a row, naive-CSV-safe enough for
    # email columns (which don't contain commas or embedded quotes).
    # Trims surrounding whitespace and a single pair of surrounding quotes.
    _csv_first_field() {
        local s="${1%%,*}"          # everything before the first comma
        s=$(trim "$s")
        s="${s#\"}"
        s="${s%\"}"
        trim "$s"
    }

    # Validate that the FIRST column header is `email` (case-insensitive).
    # Additional columns to the right are ignored.
    local header_raw first_header
    header_raw=$(trim "${lines[0]}")
    first_header=$(_csv_first_field "$header_raw")
    first_header=$(lower "$first_header")
    if [[ "$first_header" != "email" ]]; then
        VALIDATION_ERROR_MSG="**The first column must have the header \`email\`:**\n\n• Row 1 of your file is: \`${header_raw}\`\n• Expected: \`email\` as the first column. Additional columns to the right are ignored, so it's fine to use a multi-column export — but column 1 has to be the email column."
        return 1
    fi

    # Parse data rows. For each row, read only the first column and ignore
    # the rest (matches the header validation above). Rows with a blank
    # first column are treated as blank rows and skipped silently.
    local errors=()
    local seen=""
    local lineno=1
    local row addr
    local idx2
    for (( idx2=1; idx2 < ${#lines[@]}; idx2++ )); do
        lineno=$((idx2 + 1))
        row="${lines[$idx2]}"
        addr=$(_csv_first_field "$row")
        [[ -z "$addr" ]] && continue
        local raw_for_error="$addr"
        addr=$(lower "$addr")
        if ! is_valid_email "$addr"; then
            errors+=("• Row ${lineno}: \`${raw_for_error}\` (first column) is not a valid email.")
            continue
        fi
        if [[ $'\n'"$seen"$'\n' != *$'\n'"$addr"$'\n'* ]]; then
            USER_EMAILS_NORMALISED+=("$addr")
            seen="${seen}"$'\n'"$addr"
        fi
    done

    if [[ ${#errors[@]} -gt 0 ]]; then
        local cap=15 shown=0 msg=""
        local e
        for e in "${errors[@]}"; do
            msg+="${e}\n"
            (( shown += 1 ))
            (( shown >= cap )) && { msg+="• …and $(( ${#errors[@]} - cap )) more\n"; break; }
        done
        VALIDATION_ERROR_MSG="**CSV validation failed (${#errors[@]} error$([[ ${#errors[@]} -ne 1 ]] && printf 's')):**\n\n${msg}"
        return 1
    fi

    if [[ ${#USER_EMAILS_NORMALISED[@]} -eq 0 ]]; then
        VALIDATION_ERROR_MSG="**No usable email addresses found in the CSV.**\n\nMake sure the file has a header row \`email\` followed by one address per line."
        return 1
    fi

    return 0
}

# Show a "CSV invalid — try again?" dialog. Returns 0 if the user wants to
# pick a different file, 1 to cancel out of the tool.
show_csv_error_dialog() {
    local err="$1"
    local ec=0
    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "$SCRIPT_NAME — CSV Problem" \
        --icon         "sf=doc.badge.ellipsis" \
        --iconcolour   "orange" \
        --iconsize     80 \
        --message      "${err}\n\n---\n\nPick a different CSV or cancel." \
        --messagefont  "size=12" \
        --button1text  "Choose Another CSV…" \
        --button2text  "Cancel" \
        --width        680 \
        --height       460 \
        || ec=$?
    return $ec
}

# Drive the full pick → parse → re-prompt-on-error loop until the user
# either provides a valid CSV (return 0) or cancels (return 1). On
# success USER_EMAILS_NORMALISED, CSV_PATH, and CSV_BASENAME are set.
collect_csv() {
    while :; do
        local picked
        if ! picked=$(pick_csv); then
            info "User cancelled the file picker."
            return 1
        fi
        info "User picked CSV: $picked"
        if parse_csv_emails "$picked"; then
            CSV_PATH="$picked"
            CSV_BASENAME=$(basename "$picked")
            info "CSV parsed OK — ${#USER_EMAILS_NORMALISED[@]} unique email(s)."
            return 0
        fi
        warn "CSV invalid: ${VALIDATION_ERROR_MSG//$'\n'/ | }"
        if ! show_csv_error_dialog "$VALIDATION_ERROR_MSG"; then
            info "User cancelled at CSV error dialog."
            return 1
        fi
    done
}

# =============================================================================
# FALLBACK DIALOG (osascript) — used before swiftDialog is confirmed present
# =============================================================================
show_osascript_dialog() {
    local title="$1" message="$2" buttons="${3:-OK}" icon="${4:-caution}"
    local as_buttons
    as_buttons=$(echo "$buttons" | sed 's/|/", "/g')
    local result
    result=$(run_as_user "$CONSOLE_USER" /usr/bin/osascript -e "
        display dialog \"${message}\" buttons {\"${as_buttons}\"} default button 1 with icon ${icon} with title \"${title}\"
        set theButton to button returned of result
        return theButton
    " 2>/dev/null || echo "")
    echo "$result"
}

# =============================================================================
# PRE-FLIGHT
# =============================================================================
preflight_checks() {
    info "=== Pre-flight checks ==="

    [[ $(id -u) -eq 0 ]] || { error "Must run as root."; exit 1; }

    CONSOLE_USER=$(stat -f "%Su" /dev/console)
    [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]] \
        || { error "No non-root console user."; exit 1; }
    info "Console user: $CONSOLE_USER ✓"

    [[ -x "$PLUTIL" ]] || { error "plutil not found at $PLUTIL."; exit 1; }
    [[ -x "$CURL"   ]] || { error "curl not found at $CURL.";   exit 1; }
    info "plutil ✓ · curl ✓"

    if [[ -z "$WORKFLOW_URL" ]]; then
        error "Workflow URL not set (Jamf parameter \$4 missing)."
        show_osascript_dialog \
            "$SCRIPT_NAME — Configuration Error" \
            "This Self Service policy is misconfigured (missing workflow URL).\\n\\nContact Example Co IT at itsupport@example.com" \
            "OK" "stop"
        exit 1
    fi
    [[ "$WORKFLOW_URL" =~ ^https:// ]] || {
        error "Workflow URL is not HTTPS: $(log_safe_url "$WORKFLOW_URL")"
        exit 1
    }
    info "Workflow URL: $(log_safe_url "$WORKFLOW_URL") ✓"

    if [[ "$WORKFLOW_URL" != *\?clientToken=* ]]; then
        warn "Workflow URL does not contain a clientToken query parameter — the workflow may reject the request as unauthenticated."
    fi

    # ── swiftDialog: install on demand ────────────────────────────────────
    if [[ ! -x "$DIALOG_BIN" ]]; then
        info "swiftDialog not found — triggering Jamf install policy: $SD_INSTALL_TRIGGER"
        if command -v jamf &>/dev/null; then
            jamf policy -event "$SD_INSTALL_TRIGGER" 2>&1 | tee -a "$LOG_FILE"
            local elapsed=0
            while [[ ! -x "$DIALOG_BIN" && $elapsed -lt $SD_INSTALL_WAIT ]]; do
                sleep 5
                (( elapsed += 5 )) || true
            done
        else
            warn "jamf binary not found — cannot auto-install swiftDialog"
        fi
        if [[ ! -x "$DIALOG_BIN" ]]; then
            error "swiftDialog install failed/timeout."
            show_osascript_dialog \
                "$SCRIPT_NAME — Component Missing" \
                "swiftDialog could not be installed automatically. Contact Example Co IT." \
                "OK" "stop"
            exit 1
        fi
    fi
    info "swiftDialog ✓"

    info "=== Pre-flight passed ==="
}

# =============================================================================
# ADMIN EMAIL DETECTION
# =============================================================================
detect_admin_email() {
    local email=""
    # 1. dscl EMailAddress (Jamf Connect syncs the Okta email attribute here)
    email=$(dscl . -read "/Users/$CONSOLE_USER" EMailAddress 2>/dev/null \
        | awk '/^EMailAddress:/{print $2}' | head -1) || true
    # 2. Jamf Connect user-level preference
    if [[ -z "$email" ]]; then
        email=$(defaults read \
            "/Users/$CONSOLE_USER/Library/Preferences/com.jamf.connect.plist" \
            OIDCUsername 2>/dev/null || true)
    fi
    # 3. Last-resort guess (shortname@example.com)
    if [[ -z "$email" ]]; then
        email="${CONSOLE_USER}@${OKTA_EMAIL_DOMAIN}"
    fi
    ADMIN_EMAIL_DETECTED="$email"
    info "Admin email auto-detected: $ADMIN_EMAIL_DETECTED (user can override)"
}

# =============================================================================
# SELECTION DIALOG: Attribute checkboxes + Admin email
#
# Called AFTER the CSV has been picked and parsed. USER_EMAILS_NORMALISED,
# CSV_BASENAME are expected to be populated; this dialog displays a summary
# of the loaded users at the top of the message body.
#
# Returns 0 if user clicks Next; 1 on Cancel.
# Populates: SELECTED_ATTRS, ADMIN_EMAIL
# $1 = optional error message to prepend to dialog body
# =============================================================================
show_selection_dialog() {
    local error_prefix="${1:-}"
    local body

    # Build the "loaded N users from filename" summary, with the first
    # three addresses shown verbatim so the admin can spot a wrong file.
    local n=${#USER_EMAILS_NORMALISED[@]}
    local preview=""
    local i
    for (( i=0; i<n && i<3; i++ )); do
        preview+="• \`${USER_EMAILS_NORMALISED[$i]}\`\n"
    done
    if (( n > 3 )); then
        preview+="• …and $((n - 3)) more\n"
    fi

    local csv_summary
    csv_summary="**Loaded ${n} user$( [[ $n -ne 1 ]] && printf 's' ) from \`${CSV_BASENAME}\`**\n\n${preview}"

    if [[ -n "$error_prefix" ]]; then
        body="${error_prefix}\n\n---\n\n${csv_summary}"
    else
        body="${csv_summary}\n---\n\nThis tool calculates which groups each user would gain or lose if the selected profile attributes were changed to the values you specify — nothing is written to Okta. On the next screen you can input the new values for each of the selected attributes.\n\nResults are sent as a CSV attachment in a Slack message to the admin running this script."
    fi

    local -a args=(
        --title        "$SCRIPT_NAME"
        --icon         "sf=person.crop.rectangle.stack.fill"
        --iconsize     80
        --message      "$body"
        --messagefont  "size=12"
        --button1text  "Next"
        --button2text  "Cancel"
        --width        720
        --height       720
        --json
    )

    # Checkboxes — one per supported attribute, all unchecked by default.
    local attr
    for attr in "${ATTR_ORDER[@]}"; do
        args+=(--checkbox "$(attr_label "$attr")")
    done

    # Admin email textfield (pre-filled with detection). swiftDialog textfield
    # options are comma-delimited, so strip commas defensively from the value.
    local detected_clean="${ADMIN_EMAIL_DETECTED//,/}"
    args+=(--textfield "Your admin email,required,value=${detected_clean}")

    local raw_json ec=0
    raw_json=$(run_as_user "$CONSOLE_USER" "$DIALOG_BIN" "${args[@]}" 2>/dev/null) \
        || ec=$?
    [[ $ec -eq 0 ]] || return 1

    info "Selection dialog JSON length: ${#raw_json} chars"

    # Parse checkboxes in declared order — each checkbox.<idx> matches
    # ATTR_ORDER[idx]. parse_sd_checkbox falls back to the v2 flat key.
    SELECTED_ATTRS=()
    local idx=0
    for attr in "${ATTR_ORDER[@]}"; do
        local checked
        checked=$(parse_sd_checkbox "$raw_json" "$idx" "$(attr_label "$attr")")
        if [[ "$checked" == "true" ]]; then
            SELECTED_ATTRS+=("$attr")
        fi
        (( idx += 1 )) || true
    done

    # Single textfield in this dialog now, so it's textfield.0.
    ADMIN_EMAIL=$(parse_sd_textfield "$raw_json" 0 "Your admin email")

    info "Selected attrs: ${SELECTED_ATTRS[*]:-<none>}"
    info "Admin email   : ${ADMIN_EMAIL}"

    return 0
}

# =============================================================================
# Validate selection dialog inputs.
#
# USER_EMAILS_NORMALISED is populated separately by the CSV-pick step; this
# validator only enforces that the user has picked at least one attribute,
# that a CSV was loaded (≥1 valid row), and that the admin email is valid.
#
# Returns 0 on success, 1 on failure. On failure sets VALIDATION_ERROR_MSG.
# Mutates ADMIN_EMAIL (trim + lowercase) — must NOT be called inside $(...).
# =============================================================================
validate_selection() {
    VALIDATION_ERROR_MSG=""
    local errors=()

    if [[ ${#SELECTED_ATTRS[@]} -eq 0 ]]; then
        errors+=("• Select at least one attribute to preview.")
    fi

    if [[ ${#USER_EMAILS_NORMALISED[@]} -eq 0 ]]; then
        errors+=("• No users loaded — re-run the policy and pick a CSV first.")
    fi

    # Admin email
    ADMIN_EMAIL=$(trim "$ADMIN_EMAIL")
    ADMIN_EMAIL=$(lower "$ADMIN_EMAIL")
    if [[ -z "$ADMIN_EMAIL" ]]; then
        errors+=("• Your admin email is required.")
    elif ! is_valid_email "$ADMIN_EMAIL"; then
        errors+=("• Admin email '$ADMIN_EMAIL' does not look valid.")
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        local IFS_BAK2="$IFS"; IFS=$'\n'
        VALIDATION_ERROR_MSG="**Please fix the following:**\n\n${errors[*]}"
        IFS="$IFS_BAK2"
        return 1
    fi
    return 0
}

# =============================================================================
# DIALOG 2: Per-attribute value entry
#
# Builds one text field per SELECTED_ATTRS entry, in display order. For
# bool-typed attributes (is_manager), the prompt explicitly states the
# value must be "true" or "false"; the value is validated after the
# dialog closes.
#
# Returns 0 on Run Preview, 1 on Cancel.
# Populates SELECTED_VALUES (parallel to SELECTED_ATTRS).
# $1 = optional error message
# =============================================================================
show_value_dialog() {
    local error_prefix="${1:-}"
    local body

    local selected_list=""
    local a
    for a in "${SELECTED_ATTRS[@]}"; do
        selected_list+="\n• $(attr_label "$a")"
    done

    if [[ -n "$error_prefix" ]]; then
        body="${error_prefix}\n\n---\n\nProvide a new value for each selected attribute:${selected_list}"
    else
        body="Provide the new value to preview for each selected attribute. The preview calculates group impact **as if** each user had these values — nothing is written to Okta.${selected_list}"
    fi

    local -a args=(
        --title        "$SCRIPT_NAME — Values"
        --icon         "sf=pencil.and.list.clipboard"
        --iconsize     80
        --message      "$body"
        --messagefont  "size=12"
        --button1text  "Run Preview"
        --button2text  "Cancel"
        --width        720
        --height       680
        --json
    )

    for a in "${SELECTED_ATTRS[@]}"; do
        local prompt; prompt=$(attr_prompt "$a")
        args+=(--textfield "$(attr_label "$a"),required,prompt=${prompt}")
    done

    local raw_json ec=0
    raw_json=$(run_as_user "$CONSOLE_USER" "$DIALOG_BIN" "${args[@]}" 2>/dev/null) \
        || ec=$?
    [[ $ec -eq 0 ]] || return 1

    info "Dialog 2 JSON length: ${#raw_json} chars"

    # Parse each textfield in declared order. SELECTED_VALUES[i] holds
    # the value for SELECTED_ATTRS[i].
    SELECTED_VALUES=()
    local i
    for (( i=0; i < ${#SELECTED_ATTRS[@]}; i++ )); do
        local a="${SELECTED_ATTRS[$i]}"
        local v
        v=$(parse_sd_textfield "$raw_json" "$i" "$(attr_label "$a")")
        v=$(trim "$v")
        SELECTED_VALUES[$i]="$v"
        info "Value[${a}] = '${v}'"
    done
    return 0
}

# =============================================================================
# Validate Dialog 2 values.
# Returns 0 on success, 1 on failure. On failure sets VALIDATION_ERROR_MSG.
# Mutates SELECTED_VALUES (normalises booleans to lowercase). Must NOT be
# called inside $(...) — the mutation would be lost in a subshell.
# =============================================================================
validate_values() {
    VALIDATION_ERROR_MSG=""
    local errors=()
    local i
    for (( i=0; i < ${#SELECTED_ATTRS[@]}; i++ )); do
        local a="${SELECTED_ATTRS[$i]}"
        local v="${SELECTED_VALUES[$i]:-}"
        if [[ -z "$v" ]]; then
            errors+=("• '$(attr_label "$a")' value is required.")
            continue
        fi
        case "$(attr_type "$a")" in
            bool)
                local lv; lv=$(lower "$v")
                if [[ "$lv" != "true" && "$lv" != "false" ]]; then
                    errors+=("• '$(attr_label "$a")' must be \`true\` or \`false\` (got '${v}').")
                else
                    SELECTED_VALUES[$i]="$lv"
                fi
                ;;
            string)
                # No further constraint beyond non-empty
                ;;
        esac
    done

    if [[ ${#errors[@]} -gt 0 ]]; then
        local IFS_BAK="$IFS"; IFS=$'\n'
        VALIDATION_ERROR_MSG="**Please fix the following:**\n\n${errors[*]}"
        IFS="$IFS_BAK"
        return 1
    fi
    return 0
}

# =============================================================================
# Build the outbound JSON payload.
# Echoes the JSON to stdout.
# =============================================================================
build_payload() {
    local attrs_json="" newval_json="" users_json=""
    local first=true v a i

    # attributes_to_change : JSON array of strings
    attrs_json="["
    first=true
    for a in "${SELECTED_ATTRS[@]}"; do
        $first || attrs_json+=","
        first=false
        attrs_json+="\"$(json_escape "$a")\""
    done
    attrs_json+="]"

    # new_value : JSON array of {attribute,value} objects (parallel arrays)
    newval_json="["
    first=true
    for (( i=0; i < ${#SELECTED_ATTRS[@]}; i++ )); do
        $first || newval_json+=","
        first=false
        a="${SELECTED_ATTRS[$i]}"
        v="${SELECTED_VALUES[$i]}"
        case "$(attr_type "$a")" in
            bool)
                newval_json+="{\"attribute\":\"$(json_escape "$a")\",\"value\":${v}}"
                ;;
            *)
                newval_json+="{\"attribute\":\"$(json_escape "$a")\",\"value\":\"$(json_escape "$v")\"}"
                ;;
        esac
    done
    newval_json+="]"

    # user_emails : JSON array of strings
    users_json="["
    first=true
    for v in "${USER_EMAILS_NORMALISED[@]}"; do
        $first || users_json+=","
        first=false
        users_json+="\"$(json_escape "$v")\""
    done
    users_json+="]"

    printf '{"attributes_to_change":%s,"new_value":%s,"user_emails":%s,"admin_email":"%s"}' \
        "$attrs_json" "$newval_json" "$users_json" "$(json_escape "$ADMIN_EMAIL")"
}

# =============================================================================
# POST to workflow.
# Sets WORKFLOW_OUTCOME to one of:
#   OK            HTTP 2xx
#   AUTH_ERROR    HTTP 401 / 403 — bad client token
#   NOT_FOUND     HTTP 404 — bad workflow URL
#   RATE_LIMITED  HTTP 429
#   SERVER_ERROR  HTTP 5xx (often a sync-response timeout; flow may still
#                 succeed in the background — see show_result_dialog)
#   NETWORK_ERROR curl failure / HTTP 000
#   HTTP_<code>   any other status
# Writes the raw response body to the supplied tempfile path ($1).
#
# This function deliberately does NOT echo the outcome on stdout. It used
# to (so the caller could `outcome=$(post_to_workflow …)`), but the
# function's own info() lines go through the same `tee` subshell as the
# captured stdout, so the captured value ended up multi-line and broke
# the caller's case-statement match. Using a global instead is cleaner.
# =============================================================================
post_to_workflow() {
    WORKFLOW_OUTCOME=""
    local body_out="$1"
    local payload="$2"
    local response http_code curl_rc=0

    info "POST $(log_safe_url "$WORKFLOW_URL")  (payload ${#payload} bytes)"

    # Auth is via the ?clientToken= query parameter already baked into
    # $WORKFLOW_URL. No Authorization header needed.
    response=$(printf '%s' "$payload" | "$CURL" -sS \
        --max-time "$HTTP_TIMEOUT" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "User-Agent: JamfAttrPreview/${SCRIPT_VERSION} macOS" \
        -X POST \
        --data-binary @- \
        -w $'\n__HTTP_CODE__%{http_code}' \
        "$WORKFLOW_URL" 2>/dev/null) || curl_rc=$?

    if [[ $curl_rc -ne 0 ]]; then
        : > "$body_out"
        WORKFLOW_OUTCOME="NETWORK_ERROR"
        return
    fi

    http_code="${response##*__HTTP_CODE__}"
    printf '%s' "${response%$'\n'__HTTP_CODE__*}" > "$body_out"

    info "Workflow responded HTTP $http_code"

    case "$http_code" in
        2*)              WORKFLOW_OUTCOME="OK" ;;
        401|403)         WORKFLOW_OUTCOME="AUTH_ERROR" ;;
        404)             WORKFLOW_OUTCOME="NOT_FOUND" ;;
        429)             WORKFLOW_OUTCOME="RATE_LIMITED" ;;
        5*)              WORKFLOW_OUTCOME="SERVER_ERROR" ;;
        000|"")          WORKFLOW_OUTCOME="NETWORK_ERROR" ;;
        *)               WORKFLOW_OUTCOME="HTTP_${http_code}" ;;
    esac
}

# =============================================================================
# Show progress dialog while the workflow runs.
# Workflow + Lambda can take 30-90s for a multi-user preview.
# =============================================================================
SD_PROG_CMD=""
SD_PROG_PID=""
launch_progress_dialog() {
    SD_PROG_CMD=$(mktemp "${SD_RES_PREFIX}.prog.XXXXXX")
    chmod 644 "$SD_PROG_CMD"

    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "$SCRIPT_NAME — Running" \
        --icon         "sf=arrow.triangle.2.circlepath.circle.fill" \
        --iconsize     80 \
        --message      "Submitting your preview request to Okta Workflows and waiting for the response…\n\nThis can take 30–90 seconds depending on how many users you selected." \
        --messagefont  "size=12" \
        --progress \
        --progresstext "Contacting workflow…" \
        --commandfile  "$SD_PROG_CMD" \
        --button1text  "Please wait…" \
        --button1disabled \
        --width        560 \
        --height       320 \
        &
    SD_PROG_PID=$!
    sleep 0.5
}

close_progress_dialog() {
    [[ -z "$SD_PROG_CMD" ]] && return
    printf 'progress: complete\nprogresstext: Done\n' >> "$SD_PROG_CMD"
    sleep 0.3
    printf 'quit:\n' >> "$SD_PROG_CMD"
    wait "${SD_PROG_PID:-}" 2>/dev/null || true
    rm -f "$SD_PROG_CMD"
    SD_PROG_CMD=""
    SD_PROG_PID=""
}

# =============================================================================
# Final result dialog.
# =============================================================================
show_result_dialog() {
    local outcome="$1"
    local body_file="$2"
    local title icon iconcolour msg

    local body_summary=""
    if [[ -s "$body_file" ]]; then
        local sz; sz=$(wc -c < "$body_file" | tr -d ' ')
        if [[ $sz -gt 600 ]]; then
            body_summary=$'\n\n**Response (first 600 chars):**\n\`\`\`\n'"$(head -c 600 "$body_file")"$'\n…\n\`\`\`'
        else
            body_summary=$'\n\n**Response:**\n\`\`\`\n'"$(cat "$body_file")"$'\n\`\`\`'
        fi
    fi

    case "$outcome" in
        OK)
            title="$SCRIPT_NAME — Submitted"
            icon="sf=checkmark.seal.fill"
            iconcolour="green"
            msg="**Preview request accepted by Okta Workflows.**\n\nThe workflow is generating your CSV and will send it as a Slack attachment to **${ADMIN_EMAIL}** when complete.${body_summary}"
            ;;
        AUTH_ERROR)
            title="$SCRIPT_NAME — Auth Failed"
            icon="sf=lock.trianglebadge.exclamationmark.fill"
            iconcolour="red"
            msg="**Authentication to the workflow failed (HTTP 401/403).**\n\nThe \`clientToken\` embedded in the workflow URL is missing or invalid. The full Invoke URL (including \`?clientToken=<token>\`) is configured as Jamf policy parameter \$4 — verify it matches the current Invoke URL on the Workflows API Endpoint trigger, or contact **itsupport@example.com**.${body_summary}"
            ;;
        NOT_FOUND)
            title="$SCRIPT_NAME — Endpoint Not Found"
            icon="sf=link.badge.minus"
            iconcolour="orange"
            msg="**The workflow endpoint URL returned 404.**\n\nThe URL in this Self Service policy is wrong or the workflow has been deleted/disabled. Contact **itsupport@example.com**.${body_summary}"
            ;;
        RATE_LIMITED)
            title="$SCRIPT_NAME — Rate Limited"
            icon="sf=hourglass.bottomhalf.filled"
            iconcolour="orange"
            msg="**The workflow endpoint is rate-limited right now (HTTP 429).**\n\nWait a minute and try again.${body_summary}"
            ;;
        SERVER_ERROR)
            title="$SCRIPT_NAME — Likely Timeout"
            icon="sf=hourglass.badge.exclamationmark"
            iconcolour="orange"
            msg="**The workflow endpoint returned HTTP 5xx.**\n\nFor this tool this is most often a *synchronous response timeout*: the flow took longer to finish than the Okta Workflows gateway will wait, so the gateway returned an error to this script — but the flow itself typically keeps running in the background and completes normally.\n\n**Check Slack in a minute or two for the CSV.** If it doesn't arrive, review the workflow's execution history to see whether the run actually failed or is still in progress.${body_summary}"
            ;;
        NETWORK_ERROR)
            title="$SCRIPT_NAME — Network Error"
            icon="sf=wifi.exclamationmark"
            iconcolour="red"
            msg="**Could not reach the workflow endpoint.**\n\nCheck your network connection (VPN if required) and try again."
            ;;
        *)
            title="$SCRIPT_NAME — Unexpected Response"
            icon="sf=questionmark.diamond.fill"
            iconcolour="orange"
            msg="**Workflow returned: \`${outcome}\`**${body_summary}"
            ;;
    esac

    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "$title" \
        --icon         "$icon" \
        --iconcolour   "$iconcolour" \
        --iconsize     80 \
        --message      "$msg" \
        --messagefont  "size=12" \
        --button1text  "Done" \
        --width        660 \
        --height       460 \
        >/dev/null 2>&1 || true
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    # Tee both stdout and stderr to the log file for the whole run.
    exec > >(tee -a "$LOG_FILE") 2>&1
    TEE_PID=$!

    info "=== $SCRIPT_NAME v$SCRIPT_VERSION starting ==="

    preflight_checks
    detect_admin_email

    # ── CSV picker (with re-prompt on validation failure) ─────────────────
    if ! collect_csv; then
        info "User cancelled CSV selection."
        exit 0
    fi
    info "Users loaded from CSV: ${#USER_EMAILS_NORMALISED[@]} from ${CSV_BASENAME}"

    # ── Selection dialog with re-prompt on validation failure ─────────────
    local err=""
    while :; do
        if ! show_selection_dialog "$err"; then
            info "User cancelled at selection dialog."
            exit 0
        fi
        if validate_selection; then
            err=""
            break
        fi
        err="$VALIDATION_ERROR_MSG"
        info "Selection validation failed — re-prompting."
    done
    info "Validated selection. Attrs=${SELECTED_ATTRS[*]} · Users=${#USER_EMAILS_NORMALISED[@]} · Admin=${ADMIN_EMAIL}"

    # ── Dialog 2 with re-prompt on validation failure ─────────────────────
    err=""
    while :; do
        if ! show_value_dialog "$err"; then
            info "User cancelled at value dialog."
            exit 0
        fi
        if validate_values; then
            break
        fi
        err="$VALIDATION_ERROR_MSG"
        info "Value validation failed — re-prompting."
    done

    # ── Build payload + POST ──────────────────────────────────────────────
    local payload
    payload=$(build_payload)
    info "Payload built (${#payload} bytes)."

    local body_tmp
    body_tmp=$(mktemp "${SD_RES_PREFIX}.body.XXXXXX")

    launch_progress_dialog
    # post_to_workflow assigns WORKFLOW_OUTCOME globally — capturing via
    # $() would intermix the function's own info() output (which goes
    # through `tee`) with the outcome token and break the case match.
    post_to_workflow "$body_tmp" "$payload"
    close_progress_dialog

    # Zero the payload variable now that it's been sent.
    payload="$(head -c "${#payload}" /dev/zero 2>/dev/null || true)"
    unset payload

    info "Workflow outcome: $WORKFLOW_OUTCOME"
    show_result_dialog "$WORKFLOW_OUTCOME" "$body_tmp"
    rm -f "$body_tmp"

    info "=== Complete ==="
}

main "$@"
