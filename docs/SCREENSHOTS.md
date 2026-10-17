# Screenshot guide

You need six screenshots. They are the difference between a repo that claims
something and a repo that proves it — and they are what goes on your LinkedIn
post the week you start applying.

Take them yourself (this repo cannot generate them for you, because the
dashboard is a live web app and screenshots must come from a real browser).

---

## Setup

```bash
.venv/bin/python -m soclab serve        # dashboard on http://localhost:8080
```

Use Chrome or Edge. Press `F12` → device toolbar → set to **1440 × 900** →
capture as PNG. Consistent width = consistent look in the README.

---

## The six screenshots

| # | Page | URL | What it proves |
|---|---|---|---|
| 1 | Overview | `http://localhost:8080/` | The whole pipeline at a glance: KPIs, alert volume, top rules, ATT&CK distribution, priority queue |
| 2 | Incident detail | `http://localhost:8080/incidents/INC-0001` | The risk breakdown, enriched entities, raw matched events and the response playbook — **this is the single most important screenshot** |
| 3 | Coverage | `http://localhost:8080/coverage` | The attack matrix: every stage of every scenario, detected or missed, plus per-rule precision |
| 4 | Incident queue | `http://localhost:8080/incidents` | The filtered queue with priority, score, asset and ATT&CK columns |
| 5 | Hunt console | `http://localhost:8080/hunt?q=198.51.100.24` | Free-text hunting across every field of every event |
| 6 | Playbook | `http://localhost:8080/playbooks/PB-001` | The response playbook with containment commands and the ticket template |

Save them as:

```
docs/images/dashboard-overview.png
docs/images/dashboard-incident.png
docs/images/dashboard-coverage.png
docs/images/dashboard-incidents.png
docs/images/dashboard-hunt.png
docs/images/dashboard-playbook.png
```

---

## Then wire them into the README

Under the **The dashboard** section, add:

```markdown
![SOC dashboard overview](docs/images/dashboard-overview.png)
```

and under **Detection rules**, add the coverage screenshot, and under
**VAPT**, add a capture of the terminal output of:

```bash
.venv/bin/python -m soclab vapt http://127.0.0.1:5001
```

---

## Also worth capturing

- **The one-second demo.** A screen recording of `python -m soclab demo` —
  under 4 minutes, no narration needed, or with narration. Post it on
  LinkedIn; it gets far more engagement than a static screenshot.
- **Splunk.** After loading the exported saved searches and dashboard into
  the Splunk trial, capture one panel. A screenshot with the real Splunk
  chrome on it is much more convincing than "I exported to Splunk".
- **The evaluation report.** `python -m soclab evaluate` in a terminal —
  the attack matrix with DETECTED/MISSED is a great LinkedIn carousel image.

---

## Checklist before you publish

- [ ] 6 dashboard screenshots captured at 1440px wide
- [ ] Screenshots added to the README in the right sections
- [ ] Terminal captures of `demo`, `evaluate` and `vapt`
- [ ] A < 4 minute demo recording
- [ ] The repo is public and `main` has the latest commit
- [ ] LinkedIn post published with 2–3 of the best images
