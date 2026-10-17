# Lab environment

Two things live here:

| Path | What it is | Safety |
|---|---|---|
| `insecure_demo/` | An **intentionally vulnerable** Flask app used as a scan target for practising web-security findings | Binds to `127.0.0.1` only. Never deploy it. |

---

## Run the vulnerable app

```bash
.venv/bin/python lab/insecure_demo/app.py
# -> http://127.0.0.1:5001
```

It is deliberately broken in eight ways:

1. No security headers (no CSP, HSTS, X-Frame-Options…)
2. Session cookie without `Secure` / `HttpOnly` / `SameSite`
3. Debug mode on, so tracebacks render in the browser
4. Directory listing under `/files/`
5. A `.env` file inside the web root, served to anyone
6. A version banner in the `Server` header
7. **IDOR** — `/profile?id=N` returns any user's profile
8. A hard-coded default credential (`admin` / `admin123`)

---

## Scan it

```bash
.venv/bin/python -m soclab vapt http://127.0.0.1:5001 --out data/vapt-report.md
```

Expected result: **11 findings** — 1 Critical (exposed `.env`), 2 High
(plain HTTP, insecure cookie), 3 Medium (missing HSTS/CSP, directory
listing), 5 Low (missing headers, version banner).

The report is written as Markdown (or JSON with a `.json` extension) and maps
every finding to OWASP Top 10 2021 with the evidence and a concrete fix.

---

## The safety guard

The scanner refuses any target that is not a loopback address:

```bash
$ .venv/bin/python -m soclab vapt https://example.com
Refused: refusing to scan non-local target 'example.com'. This scanner is
deliberately restricted to loopback addresses so it cannot be used against
systems you do not own.
```

`--allow-remote` exists for authorised engagements only. The scanner performs
no exploitation, no injection and no denial-of-service — it reads headers,
makes `HEAD` requests to a fixed list of well-known sensitive paths, and
inspects the TLS configuration.

---

## Practise writing findings

The point of this lab is not the scanner — it is you. For each finding,
write a report entry the way you would in a real engagement:

- **Title** an engineer can act on ("Session cookie missing HttpOnly")
- **Severity** with a justification, not a feeling
- **OWASP category** and CWE
- **Evidence**: the exact request and response
- **Reproduction steps** someone else can follow
- **Remediation** at the level of a code change, not "use HTTPS"
- **Business impact** in one sentence

Two findings from the same scan should not have the same remediation, and a
finding you cannot explain to a developer is a finding you do not understand.
