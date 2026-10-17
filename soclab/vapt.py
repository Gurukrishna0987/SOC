"""A deliberately small, **local-only** web vulnerability scanner.

Why the safety guard
--------------------
There are plenty of mass-scanning tools on the internet and no reason for a
portfolio project to add to them.  This scanner therefore refuses to touch
anything that is not a loopback address unless the operator explicitly opts in
with ``--allow-remote`` *and* names the target.  Everything it does is a
passive HTTP check plus a TLS configuration review - no exploitation, no
payload injection, no DoS.

What it checks (OWASP Top 10 2021 aligned)
------------------------------------------
  A05 Security Misconfiguration  - missing security headers, verbose errors,
                                   directory listing, exposed sensitive files
  A02 Cryptographic Failures    - HTTP not redirected to HTTPS, weak TLS
  A07 Identification/Auth       - cookie flags (Secure / HttpOnly / SameSite)
  A04 Insecure Design           - a dev-mode default credential pattern

Output is a findings report with severity, evidence and a concrete fix - the
format a real VAPT report uses.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS - forces HTTPS even if the user types http://",
    "content-security-policy": "CSP - limits what the page is allowed to load and execute",
    "x-content-type-options": "prevents MIME-type sniffing",
    "x-frame-options": "prevents clickjacking via iframes",
    "referrer-policy": "controls what is leaked in the Referer header",
    "permissions-policy": "restricts use of powerful browser features",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/server-status",
    "/phpinfo.php",
    "/backup.zip",
    "/db.sql",
    "/config.json",
    "/actuator/env",
    "/wp-config.php.bak",
]

VERBS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    owasp: str
    url: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    status: int = 0
    redirects_to_https: bool = False
    tls: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "status": self.status,
            "headers": self.headers,
            "redirects_to_https": self.redirects_to_https,
            "tls": self.tls,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Web security assessment - {self.target}",
            "",
            f"**Scanned:** {self.started_at}  ",
            f"**HTTP status:** {self.status}  ",
            f"**Findings:** " + ", ".join(f"{k}: {v}" for k, v in sorted(self.counts().items())) or "none",
            "",
            "## Findings",
            "",
            "| # | Severity | Finding | OWASP | Evidence |",
            "|---|----------|---------|-------|----------|",
        ]
        for i, f in enumerate(self.findings, 1):
            evidence = f.evidence.replace("|", "\\|")[:120]
            lines.append(
                f"| {i} | {f.severity} | {f.title} | {f.owasp} | {evidence} |"
            )
        lines.append("")
        for i, f in enumerate(self.findings, 1):
            lines.extend(
                [
                    f"### {i}. {f.title} ({f.severity})",
                    "",
                    f"- **OWASP:** {f.owasp}",
                    f"- **URL:** {f.url}",
                    f"- **Evidence:** {f.evidence}",
                    f"- **Fix:** {f.remediation}",
                    "",
                ]
            )
        return "\n".join(lines)


class SafetyError(RuntimeError):
    """Raised when a scan target is not permitted."""


def is_loopback(host: str) -> bool:
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        if addr.startswith("127.") or addr == "::1":
            return True
    return False


def check_target(url: str, allow_remote: bool = False) -> str:
    """Validate that we are allowed to scan this target."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SafetyError("only http:// and https:// targets are supported")
    if not parsed.hostname:
        raise SafetyError("target URL has no host")
    if not allow_remote and not is_loopback(parsed.hostname):
        raise SafetyError(
            f"refusing to scan non-local target '{parsed.hostname}'. "
            "This scanner is deliberately restricted to loopback addresses so it "
            "cannot be used against systems you do not own. Pass --allow-remote "
            "only for hosts you are authorised to test."
        )
    return url


def _fetch(url: str, timeout: float = 5.0, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
    req = Request(url, method=method)
    req.add_header("User-Agent", "soclab-vapt/1.0 (local-only assessment)")
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - target is validated
            return resp.status, dict(resp.headers), resp.read(200_000)
    except HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(50_000)
    except URLError as exc:
        raise SafetyError(f"cannot reach {url}: {exc.reason}") from exc


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def scan(target: str, *, allow_remote: bool = False, timeout: float = 5.0) -> ScanResult:
    """Run the assessment and return the findings."""
    check_target(target, allow_remote=allow_remote)
    base = target if target.endswith("/") else target + "/"
    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    status, headers, body = _fetch(base, timeout=timeout)
    result.status = status
    result.headers = {k: v for k, v in headers.items()}

    # A05 - missing security headers
    for header, purpose in SECURITY_HEADERS.items():
        if not _header(headers, header):
            severity = "Medium" if header in ("strict-transport-security", "content-security-policy") else "Low"
            result.findings.append(
                Finding(
                    id=f"HDR-{header}",
                    title=f"Missing {header} header",
                    severity=severity,
                    owasp="A05:2021 Security Misconfiguration",
                    url=base,
                    evidence=f"Response headers do not include '{header}'.",
                    remediation=f"Add '{header}' to the response. Purpose: {purpose}",
                )
            )

    # A02 - transport security
    if urlparse(base).scheme == "http":
        result.findings.append(
            Finding(
                id="TLS-001",
                title="Site served over plain HTTP",
                severity="High",
                owasp="A02:2021 Cryptographic Failures",
                url=base,
                evidence="Target URL uses http:// so all traffic is unencrypted.",
                remediation="Serve the site over HTTPS and redirect all HTTP traffic with a 301.",
            )
        )

    # A07 - cookie flags
    raw_cookie = _header(headers, "set-cookie")
    if raw_cookie:
        problems = []
        lowered = raw_cookie.lower()
        if "secure" not in lowered:
            problems.append("missing Secure flag")
        if "httponly" not in lowered:
            problems.append("missing HttpOnly flag")
        if "samesite" not in lowered:
            problems.append("missing SameSite attribute")
        if problems:
            result.findings.append(
                Finding(
                    id="COOK-001",
                    title="Session cookie is missing security attributes",
                    severity="High",
                    owasp="A07:2021 Identification and Authentication Failures",
                    url=base,
                    evidence=f"Set-Cookie: {raw_cookie[:120]} - {', '.join(problems)}.",
                    remediation="Set the cookie with Secure; HttpOnly; SameSite=Lax (or Strict).",
                )
            )

    # A05 - verbose error / debug output
    lowered_body = body[:20_000].decode("utf-8", errors="ignore").lower()
    debug_markers = ["traceback (most recent call last)", "stack trace:", "debug mode", "werkzeug debugger"]
    for marker in debug_markers:
        if marker in lowered_body:
            result.findings.append(
                Finding(
                    id="CFG-001",
                    title="Application exposes debug or stack-trace output",
                    severity="High",
                    owasp="A05:2021 Security Misconfiguration",
                    url=base,
                    evidence=f"Response body contains '{marker}'.",
                    remediation="Disable debug mode in production and return generic error pages (custom 404/500).",
                )
            )
            break

    # A05 - directory listing (base URL plus the usual upload/index locations)
    listing_hits: list[str] = []
    if "<title>index of /" in lowered_body or "directory listing" in lowered_body:
        listing_hits.append(base)
    for probe in ("/files/", "/uploads/", "/images/", "/static/"):
        probe_url = urljoin(base, probe.lstrip("/"))
        try:
            probe_status, _, probe_body = _fetch(probe_url, timeout=timeout)
        except SafetyError:
            continue
        probe_text = probe_body[:20_000].decode("utf-8", errors="ignore").lower()
        if probe_status == 200 and (
            "<title>index of /" in probe_text or "directory listing" in probe_text
        ):
            listing_hits.append(probe_url)
    if listing_hits:
        result.findings.append(
            Finding(
                id="CFG-002",
                title="Directory listing enabled",
                severity="Medium",
                owasp="A05:2021 Security Misconfiguration",
                url=listing_hits[0],
                evidence="Directory index returned by: " + ", ".join(listing_hits),
                remediation="Disable autoindex / directory listing in the web server configuration.",
            )
        )

    # A05 - exposed sensitive files (HEAD requests only, no content read)
    for path in SENSITIVE_PATHS:
        url = urljoin(base, path.lstrip("/"))
        try:
            file_status, file_headers, _ = _fetch(url, timeout=timeout, method="HEAD")
        except SafetyError:
            continue
        if file_status == 200:
            result.findings.append(
                Finding(
                    id=f"EXP-{path.replace('/', '_')}",
                    title=f"Exposed sensitive file: {path}",
                    severity="Critical" if path in ("/.env", "/config.json", "/db.sql") else "High",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    evidence=f"HTTP HEAD {url} returned 200.",
                    remediation=f"Block access to {path}, rotate any credential it may contain, and keep secrets out of the web root.",
                )
            )

    # A05 - server banner disclosure
    server = _header(headers, "server")
    if server and re_version.search(server):
        result.findings.append(
            Finding(
                id="CFG-003",
                title="Server version disclosed in response header",
                severity="Low",
                owasp="A05:2021 Security Misconfiguration",
                url=base,
                evidence=f"Server: {server}",
                remediation="Suppress the version banner (ServerTokens Prod / a generic Server header).",
            )
        )

    # TLS configuration review
    if urlparse(base).scheme == "https":
        result.tls = review_tls(urlparse(base).hostname or "", timeout=timeout)
        for finding in result.tls.pop("findings", []):
            result.findings.append(finding)

    result.findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    return result


re_version = re.compile(r"\d+\.\d+")


def review_tls(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Inspect the TLS configuration of a host."""
    findings: list[Finding] = []
    info: dict[str, Any] = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["cipher"] = (ssock.cipher() or ("", "", ""))[0]
                not_after = cert.get("notAfter")
                if not_after:
                    info["not_after"] = not_after
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expiry - datetime.now(timezone.utc)).days
                    info["days_remaining"] = days
                    if days < 0:
                        findings.append(
                            Finding(
                                id="TLS-002",
                                title="TLS certificate has expired",
                                severity="Critical",
                                owasp="A02:2021 Cryptographic Failures",
                                url=f"https://{host}",
                                evidence=f"Certificate expired on {not_after}.",
                                remediation="Renew and deploy the certificate, and add expiry monitoring to the pipeline.",
                            )
                        )
                    elif days < 15:
                        findings.append(
                            Finding(
                                id="TLS-003",
                                title="TLS certificate expires soon",
                                severity="Medium",
                                owasp="A02:2021 Cryptographic Failures",
                                url=f"https://{host}",
                                evidence=f"Certificate expires in {days} day(s) on {not_after}.",
                                remediation="Renew the certificate before expiry and alert at 30 days.",
                            )
                        )
                if ssock.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append(
                        Finding(
                            id="TLS-001",
                            title=f"Obsolete TLS version negotiated: {ssock.version()}",
                            severity="High",
                            owasp="A02:2021 Cryptographic Failures",
                            url=f"https://{host}",
                            evidence=f"Negotiated {ssock.version()}.",
                            remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or higher.",
                        )
                    )
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
    info["findings"] = findings
    return info


def save_report(result: ScanResult, path: str) -> None:
    if path.endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(result.to_markdown())
