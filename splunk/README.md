# Splunk assets exported from the SOC Lab

`python -m soclab splunk` regenerates every file in this folder from the
rules in `../rules/`.  There are 29 rules.

## 1. Load the saved searches (Splunk Enterprise, 30-day trial is enough)

```bash
# copy the conf file into the app directory
sudo cp savedsearches.conf \
  $SPLUNK_HOME/etc/apps/soc_lab/local/savedsearches.conf
$SPLUNK_HOME/bin/splunk reload savedsearch
```

Or, in the browser: **Settings -> Search & Reporting -> Searches, Reports &
Dashboards -> add a new saved search** and paste the `search =` line.

## 2. Load the dashboard

Settings -> Search & Reporting -> Dashboards -> Create -> Import Dashboard,
then upload `dashboard_soc_lab.xml`.

## 3. Use the hunting queries

`hunting_queries.md` contains 12 ready-to-run hunts.  Copy a query into the
Search bar and change `index=*` to the index that holds your events.

## 4. Bring in the lab data

The easiest way to see the rules fire against real-looking data:

```bash
python -m soclab generate          # writes data/events.jsonl
```

Then load it into Splunk as a JSON index (Splunk 9) or convert it with
`splunk-unwrap`/`kv` into key=value events.

## Field mapping

The lab uses ECS-style field names; the SPL uses Splunk CIM names:

| Lab field (ECS)     | Splunk field     |
|---------------------|------------------|
| `event.code`        | `EventCode`      |
| `host.name`         | `host`           |
| `user.name`         | `user`           |
| `source.ip`         | `src_ip`         |
| `destination.ip`    | `dest_ip`        |
| `process.name`      | `Image`          |
| `process.command_line` | `CommandLine` |
| `file.name`         | `file_name`      |
| `url.original`      | `url`            |
| `winlog.logon_type` | `Logon_Type`     |

## A note on licensing

Saved-search *scheduling* and alerting require a Splunk Enterprise
Security licence. The 30-day Splunk Enterprise trial is enough to load the
saved searches and run every hunt, which is all you need to demo this.
