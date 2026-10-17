# Resume template — SOC / Cybersecurity fresher

One page. Save as `Gurukrishna_Resume.pdf`. Keep it **one page** — Indian
fresher resumes that run to two pages get skimmed, not read.

> **Job title line matters.** Use a title recruiters actually search for.
> Do **not** write "Cybersecurity and Blockchain Engineer" — it belongs in your
> degree line, not the title. Use: `SOC Analyst | Security Operations | VAPT`.

---

```
GURUKRISHNA [Last Name]
Cyber Security & Blockchain Engineering | B.E. 7th Semester (2027)
Bengaluru, Karnataka | +91 XXXXX XXXXX | yourname@gmail.com
linkedin.com/in/yourhandle | github.com/Gurukrishna0987

TARGET ROLE: SOC Analyst (L1/L2)  |  Security Operations Centre  |  VAPT Analyst

────────────────────────────────────────────────────────────────────────
PROFESSIONAL SUMMARY  (3 lines, no adjectives you cannot defend)
────────────────────────────────────────────────────────────────────────
Final-year B.E. student (Cyber Security & Blockchain) with hands-on experience
building and running a Security Operations Centre pipeline: 29 custom detection
rules in Sigma format, a triage engine that scored 100% coverage across 24
simulated attack stages, and 8 incident-response playbooks mapped to MITRE
ATT&CK. Seeking a SOC Analyst internship (Dec 2026 - May 2027) with potential
for a pre-placement offer.

────────────────────────────────────────────────────────────────────────
PROJECTS / INTERNSHIP EXPERIENCE
────────────────────────────────────────────────────────────────────────
SOC Home Lab - Detection Engineering, Triage & Response | Python, Splunk SPL,
Sigma, Flask, YAML, MITRE ATT&CK                        github.com/Gurukrishna0987/SOC
  • Built an end-to-end SOC pipeline (log generation → detection → triage →
    response) that processes 300+ events and surfaces 28 prioritised incidents
    with risk scoring, ATT&CK mapping and per-alert response playbooks.
  • Authored 29 detection rules in Sigma format covering credential access,
    execution, persistence, phishing, exfiltration, cloud misconfiguration and
    ransomware; measured coverage as 100% of 24 modelled attack stages at 92.9%
    alert precision against a labelled ground-truth corpus.
  • Implemented a Sigma-compatible rule engine (boolean conditions, field
    modifiers, threshold aggregation and cross-event sequence correlation) and
    exported every rule to Splunk as scheduled saved searches + a dashboard.
  • Wrote 8 incident-response playbooks with containment, eradication and
    escalation steps mapped to MITRE ATT&CK (T1110, T1566, T1059, T1486 ...).

Web Application Security Assessment (VAPT) | Python, OWASP Top 10, Burp Suite
  • Built a local-only scanner that identifies missing security headers,
    insecure cookies, exposed secrets, directory listing and TLS misconfig,
    producing findings mapped to OWASP Top 10 2021 with remediation steps.
  • Validated the scanner against an intentionally vulnerable reference
    application; documented 11 findings including a critical exposed secret
    file.

[ADD YOUR INTERNSHIP HERE - see the template below]

────────────────────────────────────────────────────────────────────────
SKILLS
────────────────────────────────────────────────────────────────────────
Security Operations   Alert triage, incident handling, escalation, SLA
                      management, log analysis, threat hunting (basic)
SIEM & Detection     Splunk SPL, Sigma rules, Elastic/Kibana, MITRE ATT&CK
                      (T1059, T1110, T1566, T1486, T1048), alert correlation
Networking            TCP/IP, DNS, HTTP/TLS, subnetting, Wireshark, OSI model
Cloud Security       AWS IAM, S3 bucket policies, CloudTrail, Azure basics
VAPT                  OWASP Top 10, Burp Suite, Nikto, Nmap, TLS analysis
Tools & Languages     Python, Bash, PowerShell, Linux, Git, Docker (basics)

────────────────────────────────────────────────────────────────────────
CERTIFICATIONS
────────────────────────────────────────────────────────────────────────
• CompTIA Security+ (SY0-701) - [IN PROGRESS | exam scheduled <date>]
• [Add: CEH / eJPT / AWS Cloud Practitioner - only if you have actually sat it]

────────────────────────────────────────────────────────────────────────
EDUCATION
────────────────────────────────────────────────────────────────────────
B.E. - Cyber Security & Blockchain Engineering
[Your College Name], Bengaluru | 2022 - 2027 | CGPA: X.XX/10
Relevant coursework: Cryptography, Network Security, Digital Forensics,
Blockchain Security, Secure Coding, Cloud Computing

────────────────────────────────────────────────────────────────────────
ACHIEVEMENTS & ACTIVITIES        (only if they are real)
────────────────────────────────────────────────────────────────────────
• [CTF team / rank] - [e.g. ranked 120/4000 in HackTheBox CTF, Mar 2026]
• [College cybersecurity club] - [e.g. led a 30-participant CTF workshop]
```

---

## The internship placeholder — fill this in

Once you have one, this section becomes your most valuable block. Put it
**above** the projects. Keep the same structure: what the team was, what you
owned, what you changed, and a number.

```
Cyber Security Analyst Intern | [Company Name], [City]        [Month 2026] - [Present]
  • Triaged 40-60 SIEM alerts per shift across Windows, Linux and cloud
    telemetry, escalating 8 confirmed incidents (phishing with credential
    submission, brute-force account takeover, ransomware file-encryption
    precursor) to L2 within the 15-minute P1 SLA.
  • Reduced false positives on [rule/alert type] by [X%] by correlating
    [signal] and adding an allow-list, measured over [N] days of alert volume.
  • Documented 6 new playbooks for recurring alert types, reducing average
    handling time on those from [X] to [Y] minutes.
```

---

## ATS rules for Indian fresher resumes

These are the mechanical rules that decide whether your resume is even read.

1. **No tables, no columns, no text boxes, no icons.** Applicant tracking
   systems parse a single column of text. A two-column layout loses half
   your bullets.
2. **Use a real .docx or .pdf with selectable text.** Not an image, not a
   canvas. Export to PDF from Word, not from a design tool.
3. **Mirror the JD's exact vocabulary.** If the JD says "SIEM", "alert
   triage", "incident response" and "MITRE ATT&CK", your resume must contain
   those exact words. Mirror, don't paraphrase.
4. **Spell out the acronyms once.** "Splunk SPL (Structured Processing
   Language for Search and Analysis)" reads as knowledgeable; "SPL" alone
   reads as noise to a non-specialist recruiter.
5. **Numbers everywhere.** "Triaged alerts" is nothing. "Triaged 50+ alerts
   per shift" is something. "100% of 24 modelled attack stages" is much
   better.
6. **Name the tools.** "SIEM" is a category; "Splunk, Elastic Security,
   Microsoft Sentinel" are tools. Recruiters filter on tool names.
7. **Keep the file name professional:** `Gurukrishna_CyberSecurity_Resume.pdf`.
8. **One page.** If it spills, cut the coursework list and the activities
   section, not the projects.

---

## Two versions, not one

Apply with **two** variants:

- **Version A — SOC-focused** (for SOC L1/L2, MSSP, GCC roles): keep the
  detection engineering, triage, playbooks, Splunk, ATT&CK. Move the VAPT
  project to the bottom and make it one line.
- **Version B — VAPT/AppSec-focused** (for security consulting, product
  security, AppSec roles): lead with the assessment work, OWASP, Burp, and
  your software-engineering background from blockchain (smart-contract
  security is a genuine differentiator — most candidates cannot read code).

Use the job title in the application to pick the version. A "Security
Operations Centre Analyst" posting gets Version A; a "Vulnerability
Assessment Analyst" posting gets Version B.

---

## Where to get the numbers to put on this resume

Do not invent any of them. Here is where each honest number comes from:

| Claim | Where it comes from |
|---|---|
| 29 detection rules | `rules/*.yaml` in this repo |
| 100% of 24 attack stages | `python -m soclab evaluate` |
| 92.9% alert precision | same command |
| 28 prioritised incidents | `python -m soclab demo` |
| 8 response playbooks | `playbooks/*.yaml` |
| 11 VAPT findings | `python -m soclab vapt http://127.0.0.1:5001` |
| 48 automated tests | `pytest tests/ -q` |

Run the commands, copy the real outputs, and keep the screenshots. If an
interviewer asks "show me the 100%", you open a terminal and it runs in two
seconds. That is the difference between a claim and evidence.
