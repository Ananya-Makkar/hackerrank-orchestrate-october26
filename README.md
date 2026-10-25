# HackerRank Orchestrate - October 2026: Ghost Data Still Exists

## Solution
AI-powered deletion-audit agent that analyzes deletion requests against user identities, audit logs, system activity, and evidence files.

## Setup
```bash
pip install -r requirements.txt  # or no dependencies needed
```
This solution uses only Python standard library.

## Run
```bash
python3 code/main.py
```
This will read from `dataset/` and generate `output.csv` in the repository root with predictions for all 518 deletion requests.

## Output Schema
```csv
case_id,deletion_status,steps_json
```
- `deletion_status`: COMPLETE, INCOMPLETE, or NOT_APPLICABLE
- `steps_json`: Ordered JSON array of findings, remediation actions, and verification checks
