# SOC Lab - developer shortcuts.
#
#   make setup     create the virtualenv and install dependencies
#   make demo      run the full pipeline and print the summary
#   make test      run the test suite
#   make serve     start the dashboard on http://127.0.0.1:8080
#   make lab       start the intentionally vulnerable demo app
#   make vapt      scan the demo app and write the report
#   make splunk    regenerate the Splunk assets

PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: setup demo test serve lab vapt splunk evaluate clean

setup:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

demo:
	$(PY) -m soclab demo

evaluate:
	$(PY) -m soclab evaluate

test:
	$(PY) -m pytest tests/ -q

serve:
	$(PY) -m soclab serve --host 0.0.0.0 --port 8080

lab:
	$(PY) lab/insecure_demo/app.py

vapt:
	$(PY) -m soclab vapt http://127.0.0.1:5001 --out data/vapt-report.md

splunk:
	$(PY) -m soclab splunk

clean:
	rm -rf data/*.jsonl data/*.json .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
