# Interview question bank — SOC Analyst & VAPT (fresher level)

**How to use this:** the model answer is a *shape*, not a script. Memorising
words gets you nothing; understanding the reasoning gets you hired. For each
question, the note after the answer says what the interviewer is actually
testing.

**The rule for every technical question:** answer in three beats —
*what it is (one sentence) → why it matters (one sentence) → what you would
do about it (one sentence)*. Candidates who only define things look like they
read Wikipedia. Candidates who define, explain the impact, and propose an
action sound like analysts.

**If you do not know:** say so, then show how you would find out.
> *"I don't know the exact event ID, but I know it's in the Security log and
> it's under the 'Account Logon' category — I'd search the Microsoft docs and
> build a rule on it. Can I show you how I'd approach it?"*

That answer scores higher than a confident wrong number. SOC managers hire
people who are honest about their gaps and fast about closing them.

---

## Part 1 — SOC fundamentals

**1. What is a SOC, and what does a Tier-1 analyst actually do?**
A Security Operations Centre is the team and the tooling that monitors an
organisation's security telemetry 24×7. A Tier-1 analyst owns the alert
queue: validate each alert, decide whether it is a true or false positive,
enrich it with asset and user context, respond using a playbook, and escalate
what is beyond their scope. The job is triage, not deep investigation — T2 and
T3 do the investigation, but T1 decides what *is* an incident.

*Tests:* whether you understand the tiering and the daily reality.

**2. SIEM vs SOAR vs EDR — what is the difference?**
SIEM collects and correlates logs from across the estate and raises alerts.
EDR is endpoint protection that records detailed host activity (processes,
network connections, file writes) and can isolate a host. SOAR is automation:
it plays a predefined response when a trigger fires. In most SOCs: EDR feeds
the SIEM, the SIEM raises alerts, SOAR handles the boring containment.

*Tests:* basic architecture vocabulary.

**3. Alert vs incident — what is the difference?**
An alert is a notification that a rule matched. An incident is a confirmed
(and often ongoing) security event that requires a response. Many alerts are
not incidents; a single incident can generate many alerts. Your first job is
to convert alerts into incidents — that conversion rate is how a SOC measures
its own noise.

*Tests:* the distinction that separates L1 from a button-pusher.

**4. What is a false positive and why is it the SOC's biggest enemy?**
A false positive is an alert with no real security event behind it. Too many
and the analysts get desensitised — they start ignoring alerts, and the one
that mattered gets ignored too. It is the classic alert fatigue problem, and
it is why detection tuning (and allow-lists) is a real engineering task and
not busywork.

*Tests:* whether you know why rule tuning is a skill.

**5. A benign true positive — what is it?**
A rule correctly fires, and there really was a notable event — but it is
authorised and not a threat. Someone logging in from a new city, a backup
running at 2 am, a scheduled task. The rule is right; the *context* says it is
fine. These are suppressed with a documented exception, not by weakening the
rule.

*Tests:* maturity. Most freshers only know true/false positive.

**6. What do you do when you get an alert you do not understand?**
Never silently close it. Four steps: (1) capture what the alert actually
says — the raw fields, not the summary; (2) identify the asset, the user and
the technique; (3) look for corroborating context — 30 minutes of logs around
the event, the user's history, the asset's baseline; (4) if still unclear,
escalate to L2 with everything you gathered and a clear question. An
unresolved alert handed over well is good work; an alert quietly closed is
not.

*Tests:* escalation discipline.

**7. What is an SLA in a SOC, and what happens if you miss one?**
A Service Level Agreement on a priority tier: P1 acknowledged in 15 minutes,
P2 in an hour, and so on. Missing a P1 SLA is an escalation to the incident
manager and usually a post-incident review. The reason SLAs exist is that
some attacks are still in progress, and every minute of delay is more data
exfiltrated.

*Tests:* whether you understand urgency and accountability.

**8. Explain the kill chain / MITRE ATT&CK in one minute.**
ATT&CK is a knowledge base of how real intrusions happen, organised as
tactics (the *why*) and techniques (the *how*): Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Command and Control →
Exfiltration → Impact. Its value to you is that it tells you what to look for
next: an encoded PowerShell (Execution) is very often followed by credential
access and lateral movement, so a good analyst hunts for the next stage
rather than closing the first alert.

*Tests:* whether you can explain a framework rather than recite it.

**9. What is the difference between a benign true positive and an incident?**
A benign true positive is real and authorised — nothing happened. An incident
is real and unauthorised. Both are "true positives"; only one is a security
event. Your judgement has to distinguish "the rule worked" from "something
bad happened".

---

## Part 2 — Windows log analysis (the bread and butter)

**10. Which Windows Security event IDs do you know, and what do they mean?**
The five I would expect a fresher to know cold: **4624** logon success,
**4625** logon failure, **4672** special privileges assigned, **4720** user
account created, **4732** member added to a privileged group. Also useful:
**4688** process creation (with command line, if audit policy is on),
**4104** PowerShell script block, **5007** antivirus configuration changed,
**7045** service installed, **5140** network share accessed, **1102** audit
log cleared, **4672/4768/4769** Kerberos events.

*Tests:* hands-on reality. If you can name these cold, you have clearly done
actual work.

**11. What is the difference between logon type 2, 3 and 10?**
Type 2 is interactive (someone at the console, or via RDP/VDI), type 3 is
network (SMB, RPC, WMI — the type used by remote administration and lateral
movement), type 10 is RemoteInteractive (RDP). Type 3 is the one that matters
for lateral movement: a workstation account authenticating to a server over
the network is worth investigating.

*Tests:* whether you read logs as a human story rather than pattern-matching.

**12. Explain logon type 3, 2 and 10 and the attack angle.**
Already covered above — expect a follow-up: *"A type 3 logon to a file server
from a user's laptop at 2 am. What do you do?"* Answer: check whether that
user normally does type 3 logons to that server, check for 5140 share access
around the same time, check for 7045 service installs on the target, and
check whether the source host shows any other unusual activity.

**13. What is 4688 and why is it often missing?**
Process creation in the Security log. It only includes the full command line
if "Audit Process Creation" and "Include command line in process creation
events" are enabled in the advanced audit policy — and by default it is off.
That is why Sysmon (Event ID 1) is deployed on most estates: it gives full
command lines, hashes and parent processes by default. If the command line is
missing, that is an auditing gap to report, not a missing event to ignore.

*Tests:* deep practical knowledge; this is a classic senior-interview probe.

**14. What does 4625 tell you beyond "a logon failed"?**
The sub-status code: 0xC000006A = wrong password, 0xC0000064 = no such
user, 0xC0000234 = account locked out, 0xC0000072 = account disabled,
0xC0000071 = password expired. Wrong password across many accounts = spray.
"No such user" across many accounts = username enumeration. Locked out
repeatedly = someone already tried hard, or the account is being abused.

*Tests:* whether you read the detail or just the event ID.

**15. What is 1102 and why is it critical?**
The Security audit log was cleared. It is anti-forensic: the attacker is
removing the evidence of their own actions. In an incident, treat the whole
host as compromised — you cannot trust that timeline.

**16. How would you investigate an encoded PowerShell command?**
Get the full command line, base64-decode it (`powershell -enc` is UTF-16LE
base64), read the decoded script, then pivot: check for script block logging
(4104) on the host for the de-obfuscated content, check the parent process
(`winword.exe` → macro; `explorer.exe` → user ran something), check for a
downloaded second stage, check network connections from that host, and look
for credential-access events on the same host in the same window.

*Tests:* the full investigate-respond loop, in order.

---

## Part 3 — Linux, network and cloud

**17. How would you find failed SSH logins on a Linux server?**
`journalctl -u sshd | grep "Failed password"` or `grep "Failed password" /var/log/auth.log`, then aggregate by source IP to spot a spray or a brute force. For a fleet, that becomes a SIEM query grouped by `src_ip` with a threshold. In a hunt I would also check `last -a` and `/var/log/auth.log` for successful logons from the same IP — that is the interesting event.

**18. Explain DNS tunnelling and how you would detect it.**
Data is encoded into DNS query subdomains, which defeats web proxies because
DNS is allowed everywhere. Detection: very long subdomain labels, high
entropy (random-looking characters), a large number of unique queries to the
same parent domain, and TXT/NULL record types. Response: block the domain at
the resolver, isolate the host, and decode the exfiltrated data to scope it.

*Tests:* conceptual clarity — you can explain it without a diagram.

**19. How do you investigate a suspicious S3 bucket?**
CloudTrail: who called `PutBucketAcl`/`PutBucketPolicy` (principal, source
IP, `userIdentity`), whether it was via the console or the API, whether CI/CD
did it, then the bucket access logs to see what was exposed and for how long.
Then check whether the principal was itself compromised, and whether the
bucket contained regulated data. That last point is what turns it into a
notification obligation.

**20. What does an IAM wildcard policy mean and why is it dangerous?**
`"Action": "*", "Resource": "*"` grants every action on every resource — it is
equivalent to administrator. One attached wildcard policy is a full account
compromise. The defence is least privilege plus permission boundaries and
SCPs, and detecting the *attachment* of such a policy is a high-priority
cloud detection.

**21. What is MFA fatigue / MFA bombing and how do you spot it?**
An attacker who already has the password repeatedly prompts the victim's
authenticator; the user, annoyed, approves one. Detection: many
authentication attempts with MFA challenges for one account in a short window,
or many `MFA challenge` events with a successful approval after a burst.
Response: block the source, reset the credential, and tell the user to deny
the prompt — training matters more than tooling here.

---

## Part 4 — Detection engineering

**22. What is a detection rule, and what makes a good one?**
A detection rule is a query over telemetry that fires when a specific
condition is met. A good rule has: a clear **intent** (the behaviour you are
detecting, not the technique name), a **specific** selection (so it does not
fire on everything), a **documented false-positive profile** (you know what
benign activity looks like), an **ATT&CK mapping**, a **severity** that
reflects real risk in your environment, and a **response** attached to it.
Most of my work on this project was exactly that last part — every rule links
to a playbook with containment and escalation steps.

*Tests:* whether you think beyond "write a query".

**23. What is Sigma and why would you use it?**
A vendor-neutral format for detection rules: YAML, with a standard structure
(logsource, detection with selection/filter/condition, fields, false
positives, ATT&CK tags). The value is portability — the same rule can be
converted to Splunk SPL, Elastic, Sentinel KQL or Chronicle. It means your
detection content is not locked to one vendor, and it is reviewable by
peers. I wrote all 29 rules for my lab in Sigma format for exactly that
reason.

**24. How do you tune a rule without weakening it?**
1. Pull the raw events that fired it over a representative period.
2. Classify them: true positive, benign true positive, false positive.
3. For the benign ones, find the *distinguishing field* — a service account, a
   management host, a business-hours window.
4. Narrow the selection with that field, or add a documented exception with
   an expiry date and an owner.
5. Re-measure. The rule should keep every true positive and drop the noise.
   If you cannot separate them on a field, the rule is too broad — split it
   rather than loosening it.

**25. What is correlation, and what are the common forms?**
Combining separate events into one meaningful detection. Forms: threshold
(N failures from one source), sequence (failure then success), cross-entity
(alert on one host linked to an alert on another), time-window (events within
5 minutes), and asset-context (this only matters on a critical asset). The
first correlation I wrote was "failed logons followed by a success from the
same source" — that one rule turns a spray plus a success into a single P1
instead of forty L3 alerts.

**26. How do you know your detection coverage is good?**
Measure it. For my lab I generated a labelled corpus where every attack event
carries ground-truth labels, then measured **stage recall** (was every stage
of every simulated intrusion detected?) and **alert precision** (were the
alerts real?). Right now it is 100% of 24 attack stages at 92.9% precision,
and the two false positives are users mistyping passwords — which I then
suppress with an allow-list. In a real SOC the equivalent measurement is
red-team emulation coverage, purple-team exercises, and reviewing the
tickets that came from nothing.

*This is your strongest answer. Lead with it.*

**27. What is the difference between a rule and a hunt?**
A rule is continuous and automatic; it answers "is this happening right now?"
A hunt is a question you ask of the data — "has this ever happened?" — often
over a long period, and it finds things no rule is watching for. A good SOC
does both: rules for the known, hunts for the unknown. My lab has 29 rules
and 12 hunting queries for exactly this reason.

---

## Part 5 — VAPT / web security

**28. What are the OWASP Top 10 (2021) categories?**
A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04
Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and
Outdated Components, A07 Identification and Authentication Failures, A08
Software and Data Integrity Failures, A09 Security Logging and Monitoring
Failures, A10 Server-Side Request Forgery. For SOC work, A05, A07, A02 and
A09 matter most.

**29. What is an IDOR and how do you test for it?**
Insecure Direct Object Reference: the server trusts an identifier the client
supplies without checking that the user is allowed to access that object. Test
by authenticating, requesting a resource, then swapping the identifier for
another user's (`/profile?id=2`, `/api/invoice/883`) while logged in as
user 1. If you get user 2's data, it is an IDOR. Fix: server-side
authorisation check on every request, never trust a client-supplied ID.

**30. What is the OWASP Testing Guide, and how do you plan a VAPT?**
The Testing Guide is OWASP's catalogue of test cases (WSTG), organised into
testing phases: information gathering, configuration and deployment
management, identity management, authentication, authorisation, session
management, input validation, error handling, data encryption, business logic
and client-side testing. Plan by mapping the client application to WSTG
categories, then prioritise by OWASP Top 10 plus business risk (what would
actually hurt this business?).

**31. Why is Burp Suite useful in a VAPT?**
It is an intercepting proxy: it lets you see and modify HTTP traffic between
your browser and the server, run automated scanners (Spider, Scanner) and
manual tests, and replay requests with modified parameters. It is how you
test for IDOR, broken access control, injection and authentication
bypass. Community Edition is free and covers the manual testing workflow
that matters at junior level.

**32. What would you do if you found a critical vulnerability?**
1. **Verify** it is real and reproduce it cleanly (a critical that turns out
   to be a false positive costs credibility).
2. **Assess impact** in business terms — what data, how many users, is it
   internet-facing.
3. **Report immediately** to the appropriate contact, not at the end of the
   engagement. A critical with an active exploitation window is measured in
   hours.
4. **Preserve evidence** — request, response, timestamps, reproduction steps.
5. **Recommend a fix and a retest**, and offer to verify the remediation.
6. Write it up in plain language for a non-technical stakeholder *and* in
   technical detail for the engineer who has to fix it.

---

## Part 6 — Your project (expect 5–10 minutes on this)

**33. Walk me through your SOC lab project.**
The short version: I built an end-to-end SOC pipeline because I could not
find a fresher-level project that showed the actual job. It generates
synthetic Windows, Sysmon, Linux, email, proxy and cloud telemetry — 300+
events, with every attack event labelled as ground truth. A Sigma-compatible
rule engine evaluates 29 detection rules against that stream, producing 28
alerts. A triage layer scores each alert on rule severity, asset
criticality, ATT&CK tactic, confidence and event volume, assigns a P1–P4
priority with an SLA, and suppresses documented false positives. Every alert
links to one of 8 incident-response playbooks, and every rule exports to
Splunk as a scheduled saved search. The point of the labelling is that I can
measure the rules instead of asserting them: 100% of the 24 attack stages
across 7 intrusion scenarios are detected, at 92.9% alert precision.

*Tests:* whether you actually built it, and whether you can explain design
choices.

**34. What is the hardest bug you hit in it?**
Have a real one ready. Examples that came out of this build: my condition
parser silently dropped custom clause names, so a rule with
`selection and suspicious_path` never fired — and the detection coverage
metric is what exposed it. The threshold operator was off by one (`count() > 10`
means eleven, not ten). And a 4624 logon event records the machine that
*received* the logon, not the source — my lateral-movement rule was blind
because I had it backwards. The lesson I took: write the test for the
threshold, and measure against labelled data, because "it looks right" is not
evidence.

*Tests:* honesty, debugging process, and whether you can learn from a mistake.

**35. Why did you choose Sigma instead of just writing SPL?**
Portability and reviewability. Sigma is vendor-neutral, so the rules convert
to Splunk, Elastic, Sentinel or Chronicle, and they can be reviewed by other
people without reading a vendor-specific query. I also export them to Splunk
SPL, which forced me to confront the field-name mapping between ECS-style
names and Splunk CIM names — a translation every SOC engineer has to do, and
one that is invisible until you hit it in production.

**36. If you had two more weeks, what would you add?**
Order by value: (1) a real SIEM rather than my own engine — running the same
rules in Splunk to compare, because the point of a SIEM is scale and I have
not tested that; (2) SOAR-style automated playbooks so containment is
consistent; (3) a second corpus with benign variations to measure how the
rules behave under noise; (4) detection coverage for the stages I know are
weak; (5) writing the rules as a proper Sigma contribution so someone else
can use them.

---

## Part 7 — Behavioural & fresher questions

**37. Why do you want to work in a SOC?**
Because I want to work on the part of security where you actually see the
attack. I have spent this year building detection and response systems, and
what I like is the loop: something fires, you work out what really happened,
you fix the control so it cannot happen the same way again. It is the same
loop I built in my own project. I am also aware that Tier-1 is a filter role
and I want to be pushed quickly into investigation and detection work.

**38. Why cybersecurity, when you are a blockchain engineer?**
Blockchain gave me the engineering foundation — I have written and audited
smart contracts, which is security applied to value, not just to systems. But
I find the defensive side more interesting than the protocol side. If I am
honest, the blockchain degree is what got me into security; the SOC is where
I want to go.

**39. You have no experience. Why should we hire you?**
Two honest reasons. First, I have already done the work: I can walk you
through a detection rule, a triage decision and a containment procedure
today, because I built them. Second, I am cheap to train and I will not need
a year to become useful — a fresher who already understands the pipeline is
faster than a fresher who is learning it. What I would need from you is a
mentor and a real alert queue, and I will give you an intern who asks good
questions and writes things down.

**40. What is a question you want to ask us?**
Ask two of these, and pick based on what you have heard:
- "What is the split of the alert queue between true and false positives
  right now, and which alert type would you most like to own?"
- "How does an intern get evaluated for conversion to a full-time role?"
- "What is the biggest gap in your current detection coverage?"
- "Which SIEM and which EDR do you run, and how do rules get into
  production here?"
- "What happened to the last P1 incident — what was the root cause?"

Those five signal that you are already thinking like a SOC analyst, and they
also give you information you need for the job.

**41. What if you make a mistake and miss an alert?**
I report it immediately and honestly, with what I know, and I make sure the
timeline is accurate — hiding a miss is far more damaging than the miss. Then
I work out why: was the rule too broad, was the log not collected, was the
triage wrong, or was the context missing? Then I fix that specific failure
mode and add a test or a rule for it. In my own project I have a rule that
was silently dropping a clause name, and the only reason I found it was
because I measured coverage instead of assuming it. Mistakes are the input to
improvement, not a thing to hide.

**42. How do you handle a 3am page that turns out to be nothing?**
Treat it as a real incident until proven otherwise — that is how you avoid
missing the one that matters — but keep it proportionate. Work the
playbook, check the asset and user, record what you checked even if the
outcome is "no action", and make sure the shift note says it was checked.
Then feed the result back: if it was a false positive, that is tuning work
for the rule owner.

**43. How do you keep up with security news?**
Weekly: the vendor advisories for my stack, the SANS Internet Storm Center
daily handler, and one threat-intel newsletter. Monthly: reading the
post-incident reports published by real organisations — they are the best
free training available, because you see exactly what happened and what was
missed. And I read the ATT&CK technique pages for whatever my alerts map to,
so I understand the behaviour behind the alert.

**44. Where do you see yourself in three years?**
Ideally in L2 or detection engineering — writing rules that catch real
techniques, running hunts, and being the person who tunes the noisy alerts
so the team can trust the queue. If I get the VAPT exposure as well, I could
see myself in AppSec or cloud security, which is where a blockchain background
becomes an advantage rather than a detour.

---

## Questions you should ask THEM (memorise these)

1. "What is the shift pattern, and how many nights a month?"
2. "What is the split between alert triage and hunt time in a shift?"
3. "Which SIEM and EDR do you run?"
4. "How do interns get evaluated, and what does a pre-placement offer
   depend on?"
5. "Which alert type would you most like to give someone?"
6. "What is the ratio of interns to full-time analysts on the team?"
7. "What happened in your last P1 incident, and what changed afterwards?"
8. "Is certification training funded?"

---

## Last-minute checklist

- [ ] Revise your three best project stories (rule, triage, VAPT finding)
- [ ] Be able to decode a base64 PowerShell command *live* in your head
- [ ] Memorise: 4624, 4625, 4672, 4720, 4732, 4688, 4104, 5007, 7045, 5140, 1102
- [ ] Know your rule's MITRE technique and the tactic
- [ ] Have one honest "I got this wrong and here is what I changed" story
- [ ] Have one question that only you could ask
- [ ] Bring the demo: `python -m soclab demo` runs in under a second
