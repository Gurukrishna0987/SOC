# Getting the internship: the pitch

The hardest part of a fresher SOC internship search is that you have nothing
to point at. This document fixes that with three assets you actually have:
a finished project, a GitHub profile, and the fact that you can *do the work*
already. Every template below is designed to be sent to a stranger and still
read.

---

## The three messages you will send

| Message | Where it goes | Volume | Reply rate target |
|---|---|---|---|
| **Cold email to a hiring manager** | Company careers page + LinkedIn | 5 / week | 5–15% |
| **LinkedIn connection request** | Target analysts and recruiters | 30 / week | 10–20% accept, 2–5% conversation |
| **Referral request to alumni** | LinkedIn | 5 / week | 30–50% |

Do all three. A role is usually filled by *one* application that had a
referral, a name, or a strong first impression. Everything else is noise.

---

## 1. Cold email to a hiring manager / SOC lead

**Subject line matters more than the body. Test these:**

- `SOC Analyst Intern (Dec 2026 – May 2027) — Bengaluru — built a SOC lab`
- `Final-year Cyber Security student, SOC intern, no experience but a working SOC lab`
- `SOC internship application — I already run a detection & triage pipeline`

**Body (fill the brackets, keep it under 150 words):**

> Dear [Name / Hiring Team],
>
> I am a final-year B.E. student in Cyber Security & Blockchain at [College],
> and I am looking for a SOC Analyst internship starting December 2026, ideally
> with a pre-placement offer.
>
> I do not have commercial SOC experience, so I built one. My project is a
> working Security Operations Centre pipeline: 29 detection rules written in
> Sigma format (credential access, phishing, ransomware, cloud
> misconfiguration), a triage engine that scores and prioritises every alert,
> 8 incident-response playbooks mapped to MITRE ATT&CK, and an export that
> turns every rule into a scheduled Splunk saved search. It detects 100% of
> the 24 attack stages in my simulated intrusion corpus, and I have published
> the rules, the playbooks and the tests.
>
> Repo and a 4-minute demo: github.com/Gurukrishna0987/SOC
>
> I am looking for a 6-month internship where I can work the alert queue
> alongside your L1 team and be evaluated for a full-time role. I am flexible
> on location and shifts, and I am completing CompTIA Security+ in [month].
>
> Would a 20-minute call next week be possible? I am happy to demo the lab
> and walk through one of my detection rules.
>
> Thank you for your time.
> Gurukrishna
> +91 XXXXX XXXXX | linkedin.com/in/[handle]

**Why this works:**

- It opens with the *gap* (no commercial experience) and immediately closes
  it with evidence, instead of hiding it.
- It contains the exact keywords a SOC manager screens for: detection rules,
  Sigma, triage, playbooks, MITRE ATT&CK, Splunk, alert queue, L1.
- It asks for a **small, specific** thing (a 20-minute call), not a job.
- It states the shift flexibility, which removes the most common objection for
  a 24×7 SOC.
- It is short enough to be read on a phone between alerts.

**Send it:** Tuesday to Thursday, 9–11 am. Follow up **once**, 5 working days
later, in a *new* email (do not reply to your own — recruiters ignore
replies to their own email). The follow-up is 3 lines:

> Hi [Name], following up on my note below. The short version: I have built a
> working SOC detection and triage pipeline (open source, linked below) and I
> am looking for a Dec 2026 SOC internship. If the timing is wrong, I would
> still appreciate 10 minutes of feedback on what your L1 team looks for in a
> fresher. — [link]

---

## 2. LinkedIn connection request (320 characters max)

> Hi [Name] — I am a final-year Cyber Security student in Bengaluru. I built
> an open-source SOC home lab (29 Sigma detection rules, triage engine,
> ATT&CK-mapped response playbooks, Splunk export) and I am looking for a SOC
> Analyst internship from December 2026. Would love 15 minutes of your
> time on what Tier-1 triage actually looks like day to day. — Gurukrishna

Do **not** send "I would like to connect with you to expand my network."
Everyone ignores that. Ask for something specific and small.

---

## 3. Referral request to a college alum or contact

> Hi [Name], hope you are well. I am in my final year of B.E. Cyber Security
> & Blockchain and I am applying for SOC Analyst internships (Dec 2026
> start). Could I ask you two things?
>
> 1. If your team at [Company] is hiring SOC interns, would you be comfortable
>    forwarding my resume? I have built a working SOC lab — 29 detection
>    rules, a triage engine with a measured 100% attack-stage coverage, and
>    ATT&CK-mapped response playbooks — with a 4-minute demo here:
>    github.com/Gurukrishna0987/SOC
> 2. If not, who else in your network should see it?
>
> No pressure at all — and thank you either way.

---

## 4. Message to a recruiter on Naukri/LinkedIn

> Hi [Name], I am a final-year Cyber Security & Blockchain student applying
> for SOC Analyst roles. My profile matches your [Job title] posting on
> [platform]. Two things that may be unusual for a fresher: I have built a
> working SOC pipeline (detection rules in Sigma, ATT&CK-mapped response
> playbooks, Splunk export) and I am Security+ certified. I have applied
> through [platform] and would love to be considered. Happy to demo the
> project. — Gurukrishna, +91 XXXXX XXXXX

---

## 5. The "apply to a small company" email that gets a reply

Small MSSPs and security firms (10–200 people) are where freshers get real
work fastest, and their hiring managers read their own inbox. Send this to
the founder or the security lead directly:

> Dear [Name],
>
> I am a final-year cyber security student and I am looking for a SOC
> internship. Rather than only applying through a portal, I wanted to write
> to you directly, because [Company] is one of the few firms in [City] where
> an intern actually gets to own an alert type rather than just watch.
>
> To show I am serious, I built a working SOC home lab — detection rules in
> Sigma format, a triage engine, 8 incident-response playbooks mapped to MITRE
> ATT&CK, and an export to Splunk saved searches. It is open source:
> github.com/Gurukrishna0987/SOC
>
> I am looking for December 2026 to May 2027, and I am happy to start with a
> short trial task (for example, writing detections for one of your alert
> types) so you can see the work before committing.
>
> Would you be open to a 20-minute call?
> — Gurukrishna, [phone], [LinkedIn]

That last paragraph — **offering a short trial task** — is the single highest
reply-rate trick in this document. It removes the employer's risk.

---

## 6. What to do when they reply "send us your resume"

- Send a PDF, named properly, with the cover note in the body of the email.
- In the cover note, name the **one** thing from *their* JD that your project
  proves. Example: *"Your JD mentions alert triage for cloud misconfiguration —
  my lab includes three AWS CloudTrail rules (public bucket, wildcard IAM
  policy, MFA removal) and the triage engine that prioritised them."*
- Attach nothing else. One resume. If you have a demo video, link it, do not
  attach a 200 MB file.

---

## 7. The internship proposal (attach to a formal application)

One page. Send it as a PDF alongside the resume when the company has a
"cover letter" or "supporting document" field. Structure:

```
INTERNSHIP PROPOSAL - SOC ANALYST
Gurukrishna [Last Name] | [Email] | [Phone] | github.com/Gurukrishna0987/SOC

OBJECTIVE
    To join [Company]'s Security Operations Centre as an L1 analyst for
    6 months (Dec 2026 - May 2027) with the intent of converting to a
    full-time Security Analyst role.

WHAT I ALREADY DO (so you can judge me quickly)
    • 29 detection rules in Sigma format covering credential access,
      phishing, execution, persistence, exfiltration and cloud
      misconfiguration - with MITRE ATT&CK mapping.
    • A triage engine that scores alerts on rule severity, asset
      criticality, ATT&CK tactic, confidence and event volume, and
      assigns a P1-P4 priority with an SLA for each tier.
    • 8 incident-response playbooks with containment, eradication and
      escalation steps, and a ticket template for each.
    • A Splunk export: every rule becomes a scheduled saved search, plus
      a dashboard and 12 hunting queries.
    • A 48-test suite, run in CI on every commit.

HOW I WOULD CONTRIBUTE IN THE FIRST 30 DAYS
    Week 1-2 : Shadow the L1 queue, learn your runbooks, and take the
                alert type with the most false positives.
    Week 3-4 : Triage under supervision; own one alert type end to end.
    Month 2  : Tune that rule to cut its false-positive rate, and write
                up the before/after numbers for the team.
    Month 3  : Draft one playbook for a recurring alert type that the team
                does not have documented yet.

WHY THIS MATTERS FOR [COMPANY]
    [One specific sentence: e.g. "Your 2026 hiring plan mentions building
    an in-house detection library, which is exactly what I have been
    practising - my rules are in a portable Sigma format so they can be
    converted to whatever SIEM you run."]

WORKING STYLE & COMMITMENT
    Available [date] to [date], [X] hours per week, on-site or hybrid.
    Comfortable with shift work. [Do not write anything you cannot do.]

CONTACT
```

**Why this works:** a fresher who arrives with a written plan for their first
30 days is a different proposition from a fresher who says "I want to learn".
Managers hire the one who reduces their uncertainty.

---

## 8. The reply-handling script

| What they say | What you send |
|---|---|
| "Send your resume" | Resume + one-line cover note naming the JD point you prove. |
| "Do you have any work experience?" | "No commercial SOC experience yet — which is why I built a full pipeline to prove I can do the work. Happy to demo it." |
| "What certifications do you have?" | "CompTIA Security+ (date/expected), and [CEH/eJPT] if relevant. I can sit it in the notice period." |
| "What is your current CTC expectation?" | "I am flexible within the market range for a fresher SOC L1 role, and I am prioritise the training and the conversion path. Could you share the band for this role?" |
| "Do you know [tool]?" | "Not [tool], but here is how I would learn it — my rules are in Sigma format and convert to [Splunk/Sentinel/Elastic], and I have already exported to Splunk SPL." |
| "Why should we pick you over someone with experience?" | "They can start on day one. I can start on day one too, and I can also show you, on a laptop, a detection pipeline that already detects 24 of 24 attack stages in my test corpus. Give me a trial task and I will show you." |
| Silence after 7 days | One follow-up (3 lines). Then stop. Move on. |

**Never say:** "I am a hard worker and a team player." Everyone says it. Say
what you built, what you measured, and what you would do in their first
month.

---

## 9. Weekly metrics — track these, not feelings

| Metric | Target | Why |
|---|---|---|
| Applications sent | 10 / week | 60 per 6 weeks covers the market without burning out |
| Cold emails to hiring managers | 5 / week | 30 by graduation; this is where most fresher offers come from |
| LinkedIn connections (targeted) | 30 / week | Recruiter reach compounds |
| Referral requests to alumni | 5 / week | Highest conversion channel that exists |
| Mock interviews | 2 / week | Interview skill decays fast without practice |
| Public posts | 1 / week | Visibility is a channel, not a vanity metric |
| Tracker rows updated | every application | You cannot improve what you do not measure |

After 60 applications with 3% response rate you should have 2 calls. If you
have zero, the problem is almost never the market — it is the targeting, the
resume keywords, or the first line of your email. Fix those, not your
effort.
