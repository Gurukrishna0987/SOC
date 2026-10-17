# Your roadmap: 7th sem → internship → SOC job

**You are here:** B.E. 7th semester, Cybersecurity & Blockchain, India, 17 Oct 2026.
**Graduation:** ~May 2027.
**Target:** SOC Analyst (L1) internship starting Dec 2026 → pre-placement offer at graduation.

---

## The strategy in one paragraph

You picked the right entry point. SOC L1 is the single highest-volume entry
role in Indian cybersecurity — roughly 12,000 active Bangalore postings on its
own in 2026, and job-seeker interest in SOC roles up 225% year on year
([Business Standard, Oct 2026](https://www.business-standard.com/finance/personal-finance/cybersecurity-careers-boom-in-india-jobseeker-interest-jumps-up-to-225-126100700206_1.html)).
Freshers with a Security+ foundation, ~40+ hours of hands-on Splunk, and a
3-month internship letter move from a ₹3.5–5.5 LPA offer to a ₹5–8 LPA offer
([networkershome](https://www.networkershome.com/cybersecurity-fresher-salary-india-2026/)).
So the plan is: **one strong portfolio project + Splunk hands-on + a visible
internship**, applied to aggressively but selectively, over the next 10 weeks.

**One important warning to internalise:** analysts expect AI to compress
Tier-1 triage hiring volume by 30–40% over the next 5–7 years, and the
fresher L1 market is already crowded ([networkershome](https://www.networkershome.com/soc-analyst-salary-india-freshers-vs-experienced/)).
This is exactly why your second choice — **SOC + VAPT** — is the right hedge.
A VAPT background lets you pivot into AppSec, cloud security or red team
later, and it makes you a far more credible candidate than "I only watched
alerts." Plan to reach L2 within 24 months, not to rest in L1.

---

## Phase 0 — The next 6 weeks (17 Oct – 30 Nov 2026)

**Goal: be apply-ready by 1 December, while finishing 7th-sem exams.**

| Week | Focus | Concrete deliverable | Hours |
|---|---|---|---|
| 1 | Finish this SOC lab | Ship this repo: 29 detection rules, dashboard, 100% attack-stage coverage, green CI. Commit to `main` with a clean README. | 12 |
| 1 | Profile hygiene | GitHub bio + profile README + pinned repos. LinkedIn headline rewritten (template in [LINKEDIN.md](LINKEDIN.md)). | 3 |
| 2 | Splunk hands-on | Install the **Splunk Enterprise 30-day trial**. Load `splunk/savedsearches.conf`, import `splunk/dashboard_soc_lab.xml`, run all 12 hunting queries. **Screenshot each one.** This is the single highest-ROI hour of the whole plan. | 10 |
| 2 | Resume | Write the one-page resume from [RESUME.md](RESUME.md). Get it reviewed by a senior or a mentor. Apply to 5 roles. | 5 |
| 3 | Foundations, fast | CompTIA Security+ SY0-701. Study 2 h/day, book the exam for December. (Cost ~₹12–18k; if money is tight, do the free ISC2 CC training + practice tests instead and take the exam later.) | 12 |
| 3 | First applications | 10 applications/week. Track every one in [APPLICATION_TRACKER.md](APPLICATION_TRACKER.md). | 5 |
| 4 | 7th-sem exams | Exams first. Keep 2 h/day on Security+ and the lab. | 20 |
| 4 | Applications | 10 more applications. Start cold-emailing 5 small MSSPs/week using [INTERNSHIP_PITCH.md](INTERNSHIP_PITCH.md). | 4 |
| 5 | Portfolio polish | Write the lab blog post, record a 4-minute demo video, add the dashboard screenshots to LinkedIn. | 10 |
| 5 | Applications | 10 more applications. Review every rejection. | 4 |
| 6 | Interviews | Mock interviews: 2 per week using [INTERVIEW_QA.md](INTERVIEW_QA.md). | 10 |
| 6 | Applications | 10 more applications. Target 60 total by 30 Nov. | 4 |

**Phase 0 exit criteria (all must be true by 30 Nov 2026):**
- [ ] This repo is public, has a professional README, and CI is green.
- [ ] Splunk trial loaded with your own saved searches, 12 screenshots taken.
- [ ] Security+ booked (exam in Dec 2026 or Jan 2027).
- [ ] 60 applications sent, 100% logged in the tracker.
- [ ] 6 mock interviews done.
- [ ] LinkedIn profile complete with the SOC Lab featured.
- [ ] At least 3 interview calls booked.

---

## Phase 1 — Internship (Dec 2026 – May 2027)

**Goal: convert the internship into a full-time offer.**

### Which internships to target

Rank your applications in this order:

1. **Pre-placement / full-time offer internships** — the JDs literally say
   "full-time offer after internship" or "conversion". These are the ones that
   lead to a job. Read the last line of every JD and skip it if it says
   "only for students who can complete 6 months" *without* a conversion clause.
2. **MSSP / SOC-in-a-box roles** at security service providers — you get to
   touch real alerts, real customers and real escalation paths. Firms like
   Tech Mahindra, Paladion, Atos, NTT DATA, Tata Communications Security,
   Cloud4C, Infosys Security and Wipro CyberDefense run 24×7 SOCs and hire
   freshers into them.
3. **Product-company SOCs** — Quick Heal (Pune), K7 Computing (Chennai),
   CloudSEK, TAC Security, Sequretek, Kratikal Tech, Certcube Labs. Smaller
   teams, so you touch more; often they will hire you outright if you are good.
4. **GCC / global capability centre security teams** in Hyderabad (Hitec City,
   Gachibowli), Bengaluru and Pune. Strongest fresher pipeline, best training.

### The internship itself — how to actually get the job out of it

- **Own one alert type end to end.** In week 1, ask: *"Which alert type do you
  get the most false positives on?"* Then make that type yours. Write the
  tuning, document it, show the before/after numbers. A fresher who reduced
  false positives on one rule by 80% is more valuable than one who quietly
  closed 200 tickets.
- **Keep a private log of everything.** Every incident you triage, the query
  you wrote, the decision you made, the outcome. Convert it to a one-page
  "SOC internship report" — your strongest interview story.
- **Ask for a conversion conversation in month 3**, not month 6. Ask your
  manager: *"What would I need to show to be ready for the L2 role?"* Write
  the answer down and execute it.
- **Get the offer letter.** An internship completion certificate is worth far
  less than a pre-placement offer letter. Push for the letter in writing.

### Time split during the internship

| Work | Hours/week | Why |
|---|---|---|
| On the job | 40 | Do the job properly — this is the interview. |
| Security+ exam prep | 5 | Finish the cert; it is a hard filter on many fresher JDs. |
| Portfolio + blog | 3 | Turn the internship into public proof. |
| VAPT side practice | 4 | Keeps your second career track alive (Burp, OWASP ZAP, PortSwigger). |
| Interview practice | 2 | Stay sharp. |

---

## Phase 2 — Graduation & offer (May 2027)

- [ ] Convert the internship into a full-time offer, in writing.
- [ ] Keep the fallback: if the conversion falls through, you now have a
      *verified* SOC internship plus Security+ plus a published project —
      which is materially better than where you are today.
- [ ] Apply to 15 fresher SOC L1 roles in the first two weeks of May, even
      if you have an offer. Offers evaporate.
- [ ] Negotiate using the market data, not your hope:
      - No SOC internship letter: ₹3.5–5.5 LPA
      - With Security+ and a verified SOC internship: ₹5–8 LPA
      - Bangalore and Hyderabad product companies pay at the top of the band
      ([networkershome](https://www.networkershome.com/cybersecurity-fresher-salary-india-2026/))

---

## The skill stack, in priority order

Do these in this order. Each one is worth more than the one after it.

| Priority | Skill | Why it is on the list | Time to "job-ready" |
|---|---|---|---|
| 1 | **Windows Security event IDs** (4624, 4625, 4672, 4720, 4732, 4688, 4104, 5007, 7045, 5140, 1102) | The SOC analyst's first language. If you can read raw Windows event logs, you can triage. | 3 weeks |
| 2 | **Splunk SPL** (search, `stats`, `transaction`, `eval`, `rex`, `tstats`, `lookup`, subsearches) | Appears in most Indian SOC JDs. Your Splunk trial work is the proof. | 3 weeks |
| 3 | **Networking for security** (TCP/IP, DNS, HTTP/TLS, routing, Wireshark basics) | Half of triage is understanding what the log is describing. | 2 weeks (mostly already done in engineering) |
| 4 | **MITRE ATT&CK** | Every serious SOC JD and every interview asks about it. Learn tactics → techniques, not the whole matrix. | 1 week |
| 5 | **Linux + shell + Python for log parsing** | `journalctl`, `grep/awk/sed`, a 100-line Python parser. | 2 weeks |
| 6 | **CompTIA Security+** | The standard fresher filter. SY0-701. | 4–6 weeks of study |
| 7 | **VAPT basics** (OWASP Top 10, Burp Suite, PortSwigger Academy, Nmap, Nikto) | Your hedge. Also gives you real VAPT interviews. | 4 weeks |
| 8 | **Cloud security** (AWS IAM, S3 policy, CloudTrail, Azure Sentinel) | "Information Security, Cloud Security and NIST Standards" are the top three skills Indian postings are asking for right now ([Business Standard, Oct 2026](https://www.business-standard.com/finance/personal-finance/cybersecurity-careers-boom-in-india-jobseeker-interest-jumps-up-to-225-126100700206_1.html)). | 3 weeks |

**Deliberately last:** OSCP. It is excellent, but it is a red-team cert and
you are targeting blue-team work. Get Security+ first, CEH only if VAPT
interviews materialise. If you have money and time later, OSCP is the single
biggest salary multiplier in the table — but only after you have a job.

---

## Common traps for freshers in this field

1. **Collecting certifications instead of shipping proof.** Ten certs with no
   project loses to one cert plus a project you can demo in 4 minutes.
2. **Only watching videos.** "I know what a SIEM is" is worth nothing.
   "Here is a rule I wrote, here is the alert it produced, here is the
   playbook I ran" is worth an internship.
3. **Applying to 200 jobs in one week.** 60 targeted applications with a
   tailored cover note beats 200 generic ones.
4. **Waiting for the 8th semester to start hunting.** Every week you wait is
   a week a fresher with a working portfolio takes your slot.
5. **Learning offensive security before you can read logs.** A pentester
   without triage experience is a pentester without a job. Blue-team first.
6. **Ignoring the shift-based reality.** A lot of SOC L1 work is 24×7 rota
   work, including nights. Ask about the shift pattern *before* you accept —
   this is a legitimate question and a common source of early resignations.
7. **Not keeping the internship report.** The single best interview asset you
   will ever have is a sanitised story from real work. Write it as it happens.

---

## Your weekly non-negotiables

- **3 hours** hands-on with logs, SIEMs or tools — every week, no exceptions.
- **5 applications** and 5 tracker updates — every week.
- **1 written artifact** published (blog post, rule, CTF writeup, lab commit).
- **1 conversation** with someone who works in security (LinkedIn, Discord,
  college alumni, a mentor). Informational interviews are how you find roles
  that are not advertised.

---

## Where to go next in this repo

| File | What it gives you |
|---|---|
| [RESUME.md](RESUME.md) | A one-page fresher resume, written for SOC + VAPT roles |
| [LINKEDIN.md](LINKEDIN.md) | Profile that gets found by recruiters |
| [INTERVIEW_QA.md](INTERVIEW_QA.md) | 40 questions with model answers |
| [COMPANY_TARGETS.md](COMPANY_TARGETS.md) | Who to apply to, in priority order |
| [INTERNSHIP_PITCH.md](INTERNSHIP_PITCH.md) | Cold emails and LinkedIn messages that get replies |
| [APPLICATION_TRACKER.md](APPLICATION_TRACKER.md) | The system that makes your search measurable |
| [HUNTING_NOTES.md](HUNTING_NOTES.md) | Day-1 hunts and the daily SOC rhythm |
| [PROFILE_README.md](PROFILE_README.md) | GitHub profile README, copy-paste ready |
