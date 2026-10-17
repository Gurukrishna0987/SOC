# LinkedIn profile optimisation

A recruiter searching for "SOC analyst" in India will not find you unless your
profile contains the words they typed. This is not vanity — it is how the
screening works. Most recruiter searches look for: `SOC`, `Security Operations`,
`SIEM`, `Splunk`, `incident response`, `triage`, `MITRE ATT&CK`, `VAPT`.

---

## 1. Headline (220 characters — do not waste it)

**Do not** write: `Student at XYZ College | Cybersecurity and Blockchain | Aspiring security professional`

**Do** write:

```
SOC Analyst | Security Operations Centre (L1/L2) | Detection Engineering &
Incident Response | Splunk • MITRE ATT&CK • VAPT | B.E. Cyber Security &
Blockchain, 2027 | Open to SOC internship (Dec 2026 – May 2027) with pre-placement
```

Why this works: recruiter keyword searches hit every term; the hiring window
and the conversion intent are stated up front; the tools are visible without
clicking.

---

## 2. About section

Three short paragraphs. No "passionate self-learner". No "I am a hardworking
student". Show, don't claim.

```text
I build things that detect attacks, and I document what happens next.

My focus is the blue team: log analysis, detection engineering, alert triage
and incident response. I built a Security Operations Centre home lab from
scratch — a detection engine that evaluates 29 Sigma-format rules against
synthetic telemetry, a triage layer that scores and prioritises every alert
with an explainable risk model, and 8 incident-response playbooks mapped to
MITRE ATT&CK. It currently detects 100% of the 24 attack stages in my
simulated intrusion corpus at 92.9% alert precision, and every rule exports
to Splunk as a scheduled saved search.

The part I enjoy most is the boring middle: validating a rule against real
traffic, tuning out the false positives, and writing down exactly what an
analyst should do at 3am so the next person does not have to figure it out.

Final-year B.E. in Cyber Security & Blockchain (2027). Looking for a SOC
Analyst internship starting December 2026, ideally with a pre-placement offer.
Happy to talk — my calendar is open.
```

---

## 3. Experience section

Create these entries even though they are not employment:

### "SOC Home Lab - Detection Engineering & Incident Response" *(Personal project)*
`Oct 2026 – Present` · `github.com/Gurukrishna0987/SOC`

Write it as a job description, because recruiters read it the same way. Use
the same bullets as your resume — 4 to 6 bullets, each with a number and a
verb. Put the repo link first.

### "Cyber Security & Blockchain Engineering" *(Education)*
Add to your existing education entry:
- Relevant coursework
- **Add a "Projects" or "Activities" section** inside the education entry for
  academic projects, CTFs and workshop leadership. Recruiters scroll there.

### Any internships, freelance work, or college IT work
List them. If you have done *any* IT work — college lab admin, a friend's
small business website, a campus network — it counts. Frame it in security
terms: "maintained the campus Wi-Fi captive portal and logged 40+ client
devices" is a security-adjacent line of work.

---

## 4. Featured section (the most-clicked part of the profile)

Add these three, in this order:

1. **"SOC Home Lab"** — link the repo. Add a one-line description and the
   dashboard screenshot.
2. **"Detection Rules in Sigma format"** — link to `rules/` in the repo. This
   is unusual for a fresher, and it is what makes a technical recruiter stop
   scrolling.
3. **"Incident Response Playbooks"** — link to `playbooks/`. Shows you
   understand the job is not just detection.

Use the **"Add a link"** option for 1 and 3 (pointing at the repo subfolder),
and a **post** for 2 if you want the reach.

---

## 5. Skills section (and enable the endorsements)

Add these exact skills, top to bottom, so the first ten are the ones that
matter:

```
Security Information & Event Management (SIEM) · Splunk · Incident Response ·
MITRE ATT&CK · Security Operations Center (SOC) · Alert Triage · Log Analysis ·
Threat Detection · Penetration Testing · OWASP Top 10 · Ethical Hacking ·
Network Security · Cybersecurity · Windows Security Events · Sigma Rules ·
Cloud Security · AWS IAM · Python · Wireshark · Linux · PowerShell
```

**Security+** and **CEH** only after you have them — do not list a cert you
have not passed.

---

## 6. Certifications section

Only what you have earned. Put the exam date. If a cert is in progress, write
`CompTIA Security+ (SY0-701) — expected [Month 2026]` with the exam date.
Recruiters filter on this, and a false claim is a rejection later.

---

## 7. The activity that gets you found

Post **weekly** for the first two months. Recruiter searches surface active
candidates, and a fresher who posts about security every week is
indistinguishable from someone with 2 years of experience in terms of
visibility.

### Post templates that work

**Week 1 — the project launch**
> I built a Security Operations Centre home lab while looking for a SOC
> internship, and I want to show the work rather than just describe it.
>
> It generates synthetic Windows/Sysmon/email/proxy/cloud telemetry, runs 29
> detection rules written in Sigma format, triages every alert with an
> explainable risk score, and maps each alert to an incident-response
> playbook and MITRE ATT&CK technique.
>
> The number I care about: 100% of the 24 attack stages in my simulated
> intrusion scenarios get detected — and I know exactly which two false
> positives fire and why.
>
> Repo: github.com/Gurukrishna0987/SOC
> What should I build next in it?
>
> \#SOC #SOCanalyst #Cybersecurity #MITREATT\&CK #Splunk #DetectionEngineering

**Week 2 — a mini technical post (this is the highest-value format)**
> What a "password spray" actually looks like in Windows logs, and why it is
> not the same as a brute force.
>
> A spray is one password attempt against many accounts from one source. A
> brute force is many attempts against one account. A rule that says "10
> failed logons" catches the second and misses the first entirely.
>
> The fix is to count *distinct accounts* per source, not total events:
> `| stats dc(user) as accounts count as attempts by src_ip | where accounts > 5`
>
> I built both into my SOC lab and measured the difference. [screenshot]
>
> \#ThreatDetection #Sigma #SOC

**Week 3 — a lessons-learned post**
> Three detection rules I wrote that were wrong, and what the logs taught me.
> 1. My "brute force" rule fired on users mistyping their password. It was
>    the same signal, different intent. Fixed by correlating the *source* and
>    adding a 24×7 SOC's most important accessory: an allow-list.
> 2. My threshold was off by one. `count() > 10` means eleven, not ten. I
>    only noticed because I wrote a test for it.
> 3. I matched on the wrong host field. In a 4624 the host is the machine
>    that *received* the logon, not the source. My lateral-movement rule was
>    blind for a week.
>
> Detection engineering is mostly being wrong, carefully, on purpose.

**Week 4 — an internship-hunt post (this one gets you recruiters)**
> I am looking for a SOC Analyst internship starting December 2026, ideally
> with a pre-placement offer, in Bengaluru or Hyderabad.
>
> I have built a full SOC pipeline (detection rules in Sigma, triage engine,
> ATT&CK-mapped response playbooks, Splunk export) and I am working through
> CompTIA Security+.
>
> If your team runs a SOC and trains juniors, I would love 20 minutes of your
> time — and I am happy to demo the lab. DM me or comment.
>
> \#SOC #Internship #Hiring #Freshers

---

## 8. Network deliberately, do not just connect

- **Connect with 30 people per week** in your target roles: SOC analysts,
  security engineers, IT managers, hiring recruiters at MSSPs. Use a
  personalised note (3 lines, not "I'd like to connect").
- **Follow and comment** on posts by people who work at your target
  companies. Recruiters notice engagement from candidates.
- **Find your college alumni** in security on LinkedIn and ask for 15 minutes.
  A referral from a senior analyst is worth more than 50 cold applications.
- **Join the right Discord/Slack communities**: Indian security communities,
  Splunk user groups, and the local CERT-In / NASSCOM cybersecurity
  communities. Ask questions, answer questions.

**Message template for a senior analyst (the one that gets replies):**
> Hi [Name] — I am a final-year Cyber Security student in Bengaluru building a
> SOC home lab (detection rules + triage engine + ATT&CK playbooks:
> github.com/Gurukrishna0987/SOC). I am trying to move from theory to
> practice and would value 15 minutes of your time on where freshers usually
> get stuck in Tier-1 triage. Happy to work around your schedule. — Gurukrishna

---

## 9. Job hunting settings

- **Open to Work** → turn it on, set to "Security Analyst" / "Cyber Security
  Analyst", add Bengaluru + Hyderabad + Pune + Remote.
- **Signal to the right recruiters.** Find the recruiters who posted SOC
  roles in Bengaluru on Naukri/LinkedIn and connect with them *before* you
  apply. When you apply, they see a familiar name.
- **Turn on "Share profile with hiring companies"** — this is what makes
  recruiters reach out to you.

---

## 10. The 30-minute setup checklist

- [ ] Headline rewritten with SOC + tool keywords
- [ ] About section replaced (use the template above)
- [ ] SOC Home Lab added as experience, with bullets
- [ ] 3 items in Featured
- [ ] 20+ skills added, top 10 as listed
- [ ] Certifications only what you have earned
- [ ] Open to Work enabled
- [ ] First post published
- [ ] 30 targeted connections sent with personalised notes
- [ ] 2 alumni messages sent
