#!/usr/bin/env bash
#
# One-command walkthrough of the whole SOC lab.
# Use this when you are demoing the project to someone (interviewer,
# mentor, a friend who asked what you have been building).
#
#   ./scripts/demo.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "No virtualenv found. Run: make setup"
  exit 1
fi

BAR="===================================================================="

echo "$BAR"
echo "SOC LAB - FULL DEMO"
echo "$BAR"

echo
echo "STEP 1/4  Generating labelled telemetry"
echo "$BAR"
$PY -m soclab generate

echo
echo "STEP 2/4  Running detection rules"
echo "$BAR"
$PY -m soclab detect

echo
echo "STEP 3/4  Triaging alerts into prioritised incidents"
echo "$BAR"
$PY -m soclab triage

echo
echo "STEP 4/4  Measuring detection coverage and precision"
echo "$BAR"
$PY -m soclab evaluate

echo
echo "$BAR"
echo "Ad-hoc hunt (one attacker IP, end to end):"
echo "$BAR"
$PY -m soclab hunt "198.51.100.24" --limit 8

echo
echo "$BAR"
echo "Splunk assets:"
echo "$BAR"
$PY -m soclab splunk

echo
echo "$BAR"
echo "Done. Now run:  .venv/bin/python -m soclab serve"
echo "$BAR"
