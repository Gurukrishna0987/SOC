# Application tracker

Copy this into a spreadsheet (Google Sheets / Excel) or a Notion table. The
point of a tracker is not organisation — it is **measuring your funnel** and
finding out within three weeks whether your targeting or your resume is the
problem.

---

## The tracker table

| # | Date applied | Company | Role | Type | Location | Source (link) | JD keywords matched | Resume version | Contact (name) | Applied via | Status | Follow-up date | Response | Notes / learnings | Next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-02 | CloudSEK | Security Analyst Intern | Internship | Bengaluru | Careers page | SIEM, Splunk, triage, ATT&CK | A | R. Iyer | Portal | Applied | 2026-11-09 | — | JD wants CloudTrail; add a cloud rule | Add AWS rule to repo |
| 2 | 2026-11-02 | Quick Heal | Security Analyst | Internship | Pune | LinkedIn | malware, reverse, Linux | B | — | Cold email | Replied | 2026-11-04 | Call on 11-05 | Wants OSCP later; good sign | Prepare CVP talk |
| 3 | 2026-11-03 | Paladion | L1 SOC Analyst | Internship | Bengaluru | Naukri | Splunk, alert triage, SLA | A | — | Portal | Rejected | — | — | "No experience" — expected | Keep applying |

**Column rules**

- **Type** — `Internship` / `Fresher job` / `Referral`. Track them separately;
  they have different conversion rates.
- **Status** — `Planned` → `Applied` → `Screening call` → `Technical round` →
  `HR` → `Offer` / `Rejected` / `Ghosted`.
- **Source** — paste the actual URL, not the company name. Later you will
  analyse which *source* produces interviews, and you cannot do that from
  memory.
- **JD keywords matched** — the 3–5 exact words from the JD that also appear
  in your resume. If this cell is empty, your resume is not tailored.
- **Resume version** — A (SOC) or B (VAPT). Never send the wrong one.
- **Follow-up date** — set it at application time, 5–7 days out. If the cell
  is empty, you will forget.
- **Response** — the actual reply, pasted in. Keep the rejection emails; they
  are the best feedback you will ever get.
- **Next action** — one concrete thing. A row with an empty "next action" is
  a row that dies.

---

## Weekly review (Sunday, 30 minutes)

Copy this block into a note and fill it in every week.

```
WEEK ___ (dates: ____ to ____)

Applications sent this week:      ___   (target: 10)
Cold emails to hiring managers:    ___   (target: 5)
LinkedIn connections (targeted):   ___   (target: 30)
Alumni referral requests:          ___   (target: 5)
Mock interviews:                   ___   (target: 2)
Public posts:                      ___   (target: 1)

FUNNEL
  Planned            ___
  Applied            ___
  Screening call     ___
  Technical round    ___
  HR round           ___
  Offer              ___
  Rejected           ___
  Ghosted            ___

RESPONSE RATE
  Applications -> any response:  ___%   (healthy: 5-15%)
  Call -> technical round:        ___%   (healthy: 40%+)
  Round -> offer:                 ___%   (healthy: 20%+)

THIS WEEK'S ONE PROBLEM
  (e.g. "3 of 4 rejections said 'no Splunk experience'.
   Fix: finish the Splunk trial, take 12 screenshots, add to resume.")

NEXT WEEK'S ONE EXPERIMENT
  (e.g. "Send 5 cold emails that open with a specific finding instead of
   'I built a SOC lab' and compare the reply rate.")
```

**The one-problem / one-experiment rule is the whole point.** Fix one thing
per week, measure it, keep the change if it worked. This is exactly how you
would run a detection-tuning exercise — and it is the same discipline a SOC
manager expects from you.

---

## The monthly funnel analysis (end of Nov, end of Feb, end of Apr)

Answer these five questions with real numbers from the table:

1. **Which application source produced the most interviews?** (careers page
   vs Naukri vs LinkedIn vs cold email vs referral). Double down on the
   winner next month.
2. **Which role title converts best?** (SOC Analyst Intern vs Security
   Analyst Intern vs VAPT Analyst vs Cyber Security Trainee.)
3. **Which resume version wins?** (A vs B.) If VAPT is converting better,
   pivot your targeting to VAPT-heavy employers.
4. **What is my rejection reason distribution?** Tag every rejection: *no
   experience* / *cert required* / *not eligible (batch)* / *salary* /
   *location* / *no response*. The most common reason tells you exactly what
   to fix.
5. **Is my response rate improving?** If it is flat at 0% after 40
   applications, the problem is the resume or the targeting, not your effort.

---

## Weekly checklist (the actual routine)

**Monday — 45 min**
- [ ] 2 applications to Tier-A firms (careers portal, tailored resume)
- [ ] 2 applications to Tier-B SMEs (careers portal)
- [ ] 1 application to a GCC
- [ ] 2 cold emails to hiring managers
- [ ] Update the tracker with the new rows

**Tuesday — 30 min**
- [ ] 3 cold emails (aim for Tuesday–Thursday, 9–11 am)
- [ ] 10 targeted LinkedIn connection requests
- [ ] Reply to anything from yesterday, within 24 hours

**Wednesday — 45 min**
- [ ] 3 applications
- [ ] 2 alumni/referral messages
- [ ] Follow up on anything due today
- [ ] 1 hour of hands-on lab work (this is the part you will be tempted to
      skip. Do not skip it.)

**Thursday — 30 min**
- [ ] 2 applications
- [ ] 10 more LinkedIn connections
- [ ] Publish 1 post (or schedule 2 for the week)

**Friday — 60 min**
- [ ] 1 mock interview (record it, watch the recording, note the 3 things you
      would answer better)
- [ ] 30 min of hands-on lab work
- [ ] Update the tracker statuses
- [ ] Write the week's one-problem / one-experiment note

**Sunday — 30 min**
- [ ] Weekly review block filled in
- [ ] Plan next week's applications from the company target list
- [ ] Rest. Seriously. Burnout in a 6-month search is a real failure mode.

---

## Funnel benchmarks (so you know if you are on track)

| Stage | Healthy for a fresher | Worry if |
|---|---|---|
| Applications sent | 10/week | < 5/week (you are not in the market) or > 25/week (you are spamming) |
| Response rate | 5–15% | < 2% after 40+ applications |
| Screening call | 1–3/week | 0 after 40 applications |
| Interview -> offer | 15–30% | < 10% (your technical interview prep is the gap) |
| Total applications before an offer | 60–150 | > 200 (targeting or resume is wrong) |
| Time from first application to offer | 6–12 weeks | > 12 weeks (widen the role types) |

**If you are at 0 responses after 40 applications**, do not apply to more
roles. Change one of these:
1. Resume version (use the JD's exact words, 3-line summary).
2. Targeting (apply to firms that publish "fresher" or "trainee" in the
   title).
3. The first line of the email (lead with the specific JD requirement).
4. Add a certificate if the rejections are all "cert required" — then get
   Security+ scheduled within a week.

**If you are getting calls but no offers**, the problem is the technical
interview, not the market. Do 2 mocks a week and drill
[INTERVIEW_QA.md](INTERVIEW_QA.md) until the answers are automatic.
