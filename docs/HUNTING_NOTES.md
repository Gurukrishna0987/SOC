# Hunting notes & the daily SOC rhythm

Hunting is the difference between a Tier-1 filter and a Tier-2 analyst. Anyone
can work an alert queue; the ones who get promoted write the queries that find
the incident nobody was alerted about.

---

## The first 30 days of a SOC job — what you will actually do

| Time | Activity | What it looks like |
|---|---|---|
| 0:00–0:15 | Handover briefing | The previous shift hands over open tickets, notable events, and watch-list items. **Take notes. This is free intelligence about the estate.** |
| 0:15–4:00 | Alert triage | Read the alert, check the asset, check the user, decide: false positive / true positive / benign true positive. Work the queue. |
| 4:00–4:30 | Break + hunt time | This is when you run your own queries. If you skip it you will never become an analyst, you will stay a filter. |
| 4:30–5:00 | Handover + notes | Write the shift report. This is your evidence when you apply for the L2 role. |

**The most important habit:** keep a personal log of every incident you
triage. What triggered it, what you checked, what you concluded, what you
did, how long it took. After 200 tickets this log is worth more than any
certificate, and it is the raw material for every interview question you will
ever be asked.

---

## Ten hunts to run in your first week

Each of these is a real technique, written as SPL. The same logic applies to
Elastic KQL, Microsoft Sentinel KQL and Google Chronicle YARA-L.

### 1. Baseline where people log on from (run this first, always)
```spl
index=* EventCode=4624
| stats count as logons values(user) as users by src_ip
| sort - logons
```
You cannot spot an impossible-travel alert without knowing the baseline. Build
the baseline before you build the alert.

### 2. Password spray (many accounts, one source)
```spl
index=* EventCode=4625
| stats count as attempts dc(user) as accounts by src_ip
| where accounts > 5 AND attempts > 5
```
`dc(user)` is the key — a spray is *distinct accounts*, not total failures.

### 3. Failures that were followed by a success
```spl
index=* EventCode=4625
| stats count as fails dc(user) as user by src_ip
| where fails > 3
| join src_ip [ search index=* EventCode=4624 | table _time src_ip user Account_Name ]
```

### 4. Encoded or obfuscated command lines
```spl
index=* (CommandLine="*-enc*" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*" OR CommandLine="*-EncodedCommand*")
| table _time host user Image ParentImage CommandLine
```
Then decode it. Base64 `-enc` is trivial to decode; do it out loud in the
interview.

### 5. Office applications spawning shells
```spl
index=* (ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*outlook.exe")
        (Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*mshta.exe")
| table _time host user ParentImage Image CommandLine
```

### 6. Rare destinations
```spl
index=* EventCode=3
| stats count as conns dc(dest) as dest by src_ip dest
| where conns < 5
| sort conns
```
Rare is not always malicious — but rare is where you look.

### 7. Service accounts behaving like humans
```spl
index=* EventCode=4624 (user="svc_*" OR user="*_backup" OR user="*_svc")
| search Logon_Type=2
| table _time host user src_ip
```
A service account with an interactive logon is either a misconfiguration or a
compromised credential.

### 8. DNS with abnormally long labels
```spl
index=* EventCode=22
| rex field=QueryName "^(?<sub>[^.]+)\."
| eval len=len(sub)
| where len > 40
| stats count by QueryName Computer
```

### 9. Audit log cleared / evidence tampering
```spl
index=* (EventCode=1102 OR EventCode=104 OR EventCode=7045 OR EventCode=4698)
| table _time host user EventCode
```

### 10. Who is talking to the internet right now?
```spl
index=proxy
| stats sum(bytes) as total dc(uri) as sites by src
| sort - total
| head 20
```
Run this during business hours. A workstation with 10 GB of traffic to one
host is a story you need to tell.

---

## The "I have 20 minutes and no alert" hunt drill

This is the actual skill. Pick any day, pick any user, and answer these:

1. **Where does this user log on from, and when?**
2. **What do they do right after logging in?** (First 15 minutes.)
3. **What do they access that nobody else accesses?**
4. **What is different about their traffic today versus last week?**
5. **If this account were stolen tomorrow, what would the attacker reach
   first?**

The answer to #5 is the one worth writing down — it is what makes you the
person who finds the thing.

---

## Weekly hunt schedule (paste into your calendar)

| Day | Hunt | Time |
|---|---|---|
| Monday | Baseline refresh — where do people log on from? Update the allow-list. | 30 min |
| Tuesday | Credential anomalies — spray, brute force, failed-then-success | 30 min |
| Wednesday | Endpoint execution — encoded commands, office spawning shells, new services | 30 min |
| Thursday | Network egress — rare destinations, large transfers, DNS anomalies | 30 min |
| Friday | Write-up — one page on the most interesting thing you found this week | 45 min |

**The Friday write-up is the most valuable 45 minutes of your week.** It
becomes your shift report, your interview story, and your evidence of
analytical thinking. Do it from week one.

---

## Triage thinking: the 6 questions

Every alert, every time. Write the answers in the ticket.

1. **What happened?** — the technical summary in one sentence.
2. **Who or what is affected?** — the asset, the user, the data. Get the
   business impact, not just the technical detail.
3. **Is it real?** — what is the evidence? What would a benign explanation
   be, and why is it less likely?
4. **How bad is it?** — criticality of the asset + the technique in the kill
   chain + what is the blast radius?
5. **What do I do now?** — contain, monitor, or escalate. And do it in the
   SLA.
6. **What will we do to stop it happening again?** — the detection gap, the
   control, the rule that should have fired.

Question 6 is what separates L1 from L2. Always answer it.

---

## Useful free tools

| Tool | Use it for | Cost |
|---|---|---|
| **Splunk free trial (30-day)** | SPL practice, saved searches, dashboards | Free |
| **Elastic Security (free)** | KQL detections, ECS field mapping | Free |
| **Microsoft Sentinel (free tier)** | KQL, the same mental model as Splunk | Free (with an Azure account) |
| **Wazuh (open source)** | A full HIDS + XDR/SIEM stack you can run on a laptop | Free |
| **SigmaHQ / Sigma rules repo** | Read production-grade detection rules | Free |
| **MITRE ATT&CK Navigator** | Map your coverage visually | Free |
| **CyberChef** | Decode base64/hex/URL-encoding in the browser | Free |
| **Wireshark** | Read the packet when the log is not enough | Free |
| **PortSwigger Web Security Academy** | Free, better than most paid VAPT courses | Free |
| **TryHackMe SOC Level 1 path** | Structured SOC walkthroughs | Free tier |
| **Hack The Box CDSA path** | SOC + AD + cloud, more advanced | Paid (~₹3–4k) |

---

## Notes template (keep one per hunt)

```markdown
### Hunt: <name> - <date> - <analyst>
**Question:** what was I trying to find out?
**Data:** index/sourcetype/query used
**Finding:** what did I see? (screenshot or SPL output)
**Conclusion:** real / not real / needs more data
**Action:** ticket raised / rule tuned / allow-list updated / no action
**Rule improvement:** what detection would have caught this automatically?
**Time spent:** 35 minutes
```

That last line is for your own weekly review. If your hunts are consistently
taking more than an hour, you need better queries — that is a skill you can
build, and it is exactly what makes you valuable.
