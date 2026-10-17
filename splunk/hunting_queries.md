# Splunk hunting queries

These are the queries a SOC analyst runs when there is no alert - the
proactive side of the job.  Replace `index=*` with your real index.

## 1. Where are users authenticating from? (baseline / impossible travel)
```spl
index=* EventCode=4624
| stats count as logons dc(user) as user by src_ip
| sort - logons
```

## 2. Accounts that never normally log on interactively
```spl
index=* EventCode=4624 Logon_Type=2
| stats earliest(_time) as first_seen latest(_time) as last_seen count as logons by user src_ip
| sort - logons
```

## 3. Which processes are signed, and which are not?
```spl
index=* (EventCode=1 OR EventCode=4688)
| stats count dc(Image) as images by Image ParentImage User
| where images > 0
```

## 4. Encoded or obfuscated command lines
```spl
index=* CommandLine=("*-enc*" OR "*FromBase64String*" OR "*DownloadString*")
| table _time host user Image ParentImage CommandLine
```

## 5. Users accessing admin shares
```spl
index=* EventCode=5140 (ShareName="*C$*" OR ShareName="*ADMIN$*" OR ShareName="*$")
| stats count as accesses by user src_ip dest ShareName
```

## 6. Service accounts that are being used interactively
```spl
index=* EventCode=4624 (user="svc_*" OR user="*_backup")
| search Logon_Type=2
| table _time host user src_ip Logon_Type
```

## 7. Rare destinations talking to your hosts
```spl
index=* EventCode=3
| stats count as conns dc(dest) as dest by src_ip dest
| where conns < 5
```

## 8. Large data transfers out
```spl
index=proxy bytes>10000000
| stats sum(bytes) as total_bytes count as requests by src user dest
| sort - total_bytes
```

## 9. DNS queries with very long labels (tunnelling heuristic)
```spl
index=* EventCode=22
| rex field=QueryName "^(?<sub>[^.]+)\."
| eval len=len(sub)
| where len > 40
| stats count by QueryName Computer
```

## 10. Scheduled tasks created outside business hours
```spl
index=* EventCode=4698
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 20
| table _time host SubjectUserName TaskName
```

## 11. Password spray - one failure, many accounts, one source
```spl
index=* EventCode=4625
| stats count as fails dc(user) as accounts by src_ip
| where accounts > 5 AND fails > 5
```

## 12. Audit log cleared
```spl
index=* EventCode=1102
| table _time host SubjectUserName
```
