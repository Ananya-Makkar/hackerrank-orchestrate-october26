# Evaluation Report - Ghost Data Still Exists

## Case-level Status Distribution
- Total cases processed: 518
- COMPLETE: 176
- INCOMPLETE: 298
- NOT_APPLICABLE: 44

## Methodology
- Resolved current and historical identifiers using user_identities.csv and user_audit_log.csv
- Parsed all evidence files (SQL snapshots, logs, JSON, text, PDFs) under dataset/evidence/
- Traced system activity across all services to identify remaining records and data flows
- Applied deletion_rules.csv for policy decisions
- Generated ordered steps (FINDING → REMEDIATION → VERIFICATION) with correct operations and evidence citations

## Additional Evaluation Cases
1. **Non-deletion request detection**: Requests for access/export/opt-out without deletion intent correctly classified as NOT_APPLICABLE with empty steps
2. **Multi-language deletion requests**: French, Spanish, Japanese deletion requests correctly identified and processed
3. **Cross-system ghost data**: Cases with data in replicas, backups, search indexes, and sync flows correctly identified as INCOMPLETE with remediation steps

## Failures Found and Improvements Made
- **Issue**: Initial keyword matching was too broad; improved to distinguish access requests from deletion requests
- **Issue**: Account ID inference needed user identity mapping; fixed by resolving via user_identities
- **Issue**: Evidence citations needed to point to actual files; improved by scanning all evidence files
- **Issue**: Step ordering must follow phase order and operation ordering rules; implemented proper sorting
