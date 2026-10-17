"""Canonical field schema for the SOC lab.

Field names follow the Elastic Common Schema (ECS) conventions, which map very
closely onto Splunk CIM (Common Information Model) data models.  Keeping the
schema ECS-like means that the same field name works in:

  * this lab's Python detection engine
  * the exported SPL for a Splunk Enterprise / Splunk Security trial
  * the exported Sigma rules for a real SIEM

Keeping one vocabulary across all three is the single most important habit a
Tier-1 analyst can build, because it is what lets you move between SIEMs
without relearning the job.
"""

from __future__ import annotations

# --- Timestamps -------------------------------------------------------------
TIMESTAMP = "@timestamp"
INGESTED = "@timestamp_ingested"

# --- Event metadata ---------------------------------------------------------
EVENT_CATEGORY = "event.category"
EVENT_TYPE = "event.type"
EVENT_ACTION = "event.action"
EVENT_ID = "event.id"
EVENT_CODE = "event.code"
EVENT_OUTCOME = "event.outcome"
EVENT_SEVERITY = "event.severity"
MESSAGE = "message"
SOURCE_NAME = "source.name"  # which telemetry source produced the event

# --- Host -------------------------------------------------------------------
HOST_NAME = "host.name"
HOST_IP = "host.ip"
HOST_OS = "host.os.name"

# --- Identity ---------------------------------------------------------------
USER_NAME = "user.name"
USER_DOMAIN = "user.domain"
USER_ID = "user.id"

# --- Network ----------------------------------------------------------------
SRC_IP = "source.ip"
SRC_PORT = "source.port"
DST_IP = "destination.ip"
DST_PORT = "destination.port"
URL = "url.original"
DNS_QUERY = "dns.question.name"

# --- Process / file / registry ---------------------------------------------
PROCESS_NAME = "process.name"
PROCESS_PATH = "process.executable"
PROCESS_CMD = "process.command_line"
PROCESS_PARENT = "process.parent.name"
PROCESS_USER = "process.user"
FILE_PATH = "file.path"
FILE_NAME = "file.name"
FILE_HASH = "file.hash.sha256"
REG_PATH = "registry.path"
REG_VALUE = "registry.value"

# --- Email ------------------------------------------------------------------
MAIL_FROM = "mail.from"
MAIL_TO = "mail.to"
MAIL_SUBJECT = "mail.subject"
MAIL_ATTACH = "mail.file.name"
MAIL_ATTACH_SIZE = "mail.file.size"
MAIL_ATTACH_COUNT = "mail.attachment.count"
MAIL_RULE = "mail.rule_triggered"
SPF_RESULT = "mail.spf_result"
DKIM_RESULT = "mail.dkim_result"
DMARC_RESULT = "mail.dmarc_result"
MAIL_REPLY_TO = "mail.reply_to"

# --- Cloud ------------------------------------------------------------------
CLOUD_PROVIDER = "cloud.provider"
CLOUD_ACCOUNT = "cloud.account.id"
CLOUD_RESOURCE = "cloud.resource.name"
CLOUD_ACTION = "cloud.action"
CLOUD_REGION = "cloud.region"
CLOUD_SOURCE_IP = "cloud.source.ip"
API_CALL = "api.operation"
HTTP_STATUS = "http.response.status_code"

# --- Network telemetry ------------------------------------------------------
PROXY_URL = "proxy.url"
PROXY_BYTES = "proxy.bytes"
PROXY_VERB = "http.request.method"
FIREWALL_ACTION = "firewall.action"
FIREWALL_RULE = "firewall.rule"

# --- Auth -------------------------------------------------------------------
AUTH_TYPE = "winlog.logon_type"  # 2 = interactive, 3 = network, 10 = RDP
AUTH_PACKAGE = "winlog.logon_package"
FAILED_ATTEMPTS = "winlog.failed_attempts"
PRIVILEGES = "winlog.privileges"
TICKET_OPTIONS = "winlog.ticket_options"

# --- Categories used across rules ------------------------------------------
CAT_AUTH = "authentication"
CAT_PROCESS = "process"
CAT_FILE = "file"
CAT_NETWORK = "network"
CAT_EMAIL = "email"
CAT_CLOUD = "cloud"
CAT_DNS = "dns"
CAT_PROXY = "web"
CAT_CONFIG = "configuration"

# Source names for each telemetry pipeline
SRC_WINDOWS = "windows_security"
SRC_SYSLOG = "linux_syslog"
SRC_SYSMON = "sysmon"
SRC_EMAIL = "email_gateway"
SRC_PROXY = "proxy"
SRC_CLOUD = "cloud_audit"
SRC_FIREWALL = "firewall"
SRC_EDR = "edr"

ALL_SOURCES = (
    SRC_WINDOWS,
    SRC_SYSLOG,
    SRC_SYSMON,
    SRC_EMAIL,
    SRC_PROXY,
    SRC_CLOUD,
    SRC_FIREWALL,
    SRC_EDR,
)

# Canonical field order used when rendering a raw event for a human.
DISPLAY_ORDER = (
    TIMESTAMP,
    SOURCE_NAME,
    EVENT_CATEGORY,
    EVENT_TYPE,
    EVENT_ACTION,
    EVENT_CODE,
    EVENT_OUTCOME,
    HOST_NAME,
    USER_NAME,
    SRC_IP,
    DST_IP,
    PROCESS_NAME,
    PROCESS_CMD,
    URL,
    FILE_NAME,
    MAIL_FROM,
    MAIL_SUBJECT,
    MESSAGE,
)
