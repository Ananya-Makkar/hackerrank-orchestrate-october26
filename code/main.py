#!/usr/bin/env python3
import csv
import json
import os
import re
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
OUTPUT_PATH = REPO_ROOT / "output.csv"

class DeletionAuditAgent:
    def __init__(self):
        self.load_all_data()
        self.build_indexes()
        self.load_all_evidence_content()
    
    def load_all_data(self):
        with open(DATASET_DIR / "deletion_requests.csv") as f:
            self.requests = list(csv.DictReader(f))
        with open(DATASET_DIR / "user_identities.csv") as f:
            self.identities = list(csv.DictReader(f))
        with open(DATASET_DIR / "user_audit_log.csv") as f:
            self.audit_log = list(csv.DictReader(f))
        with open(DATASET_DIR / "system_activity.csv") as f:
            self.activities = list(csv.DictReader(f))
        with open(DATASET_DIR / "deletion_rules.csv") as f:
            self.deletion_rules = list(csv.DictReader(f))
        with open(DATASET_DIR / "evidence_files.csv") as f:
            self.evidence_files = list(csv.DictReader(f))
        self.evidence_map = {e['file_id']: e for e in self.evidence_files}
    
    def build_indexes(self):
        self.identity_by_email = defaultdict(list)
        self.identity_by_user_id = {}
        for ident in self.identities:
            self.identity_by_email[ident['email'].lower()].append(ident)
            self.identity_by_user_id[ident['user_id']] = ident
        self.audit_by_user = defaultdict(list)
        for audit in self.audit_log:
            self.audit_by_user[audit['user_id']].append(audit)
        self.activities_by_resource = defaultdict(list)
        for act in self.activities:
            if act['resource_id']:
                self.activities_by_resource[act['resource_id']].append(act)
    
    def load_all_evidence_content(self):
        self.evid_content = {}
        for ef in self.evidence_files:
            p = DATASET_DIR / ef['file_path']
            try:
                with open(p, encoding='utf-8', errors='ignore') as fh:
                    self.evid_content[ef['file_id']] = fh.read()
            except Exception:
                self.evid_content[ef['file_id']] = ""
    
    def is_deletion_request(self, request_text):
        text = request_text.lower()
        # Definitely non-deletion
        if re.search(r'change.*email.*address', text) and not re.search(r'delete|remov|eras', text):
            return False
        if re.search(r'send me a copy|information held on my account', text):
            # if it's asking for access/export and says don't delete
            if "don't delete" in text or "do not delete" in text:
                if not re.search(r'please.*delete|want.*delet|request.*delet', text.replace("don't delete", "").replace("do not delete", "")):
                    return False
            elif not re.search(r'delete|remov|eras.*(account|profile|data)', text):
                # primary intent is access
                return False
        if re.search(r"don'?t.*delete|do not.*delete", text) and not re.search(r'please.*delete|want.*delet|request.*delet|permanent.*delet', text):
            return False
        # Deletion patterns
        if re.search(r'\bdelete\b', text) or re.search(r'\bdeletion\b', text):
            return True
        if re.search(r'supprim', text):  # French
            return True
        if re.search(r'elimin[ae]', text):  # Spanish
            return True
        if re.search(r'borrar', text):
            return True
        if '削除' in text:
            return True
        if re.search(r'\berase\b', text):
            return True
        if re.search(r'close.*account', text):
            return True
        if re.search(r'fermer.*compte', text):
            return True
        if re.search(r'\bremove\b.*account|\bremove\b.*profile|\bremove\b.*personal', text):
            return True
        if re.search(r'account.*erased|permanently.*delet', text):
            return True
        return False
    
    def resolve_identifiers(self, request):
        email = request['email'].lower()
        identifiers = {
            'emails': set([email]),
            'user_ids': set(),
            'names': set(),
            'phones': set(),
            'email_hashes': set(),
        }
        # Direct matches
        for ident in self.identity_by_email.get(email, []):
            identifiers['user_ids'].add(ident['user_id'])
            identifiers['names'].add(str(ident['name']).lower())
            identifiers['phones'].add(ident['phone'])
            identifiers['email_hashes'].add(ident['email_hash'])
            for audit in self.audit_by_user[ident['user_id']]:
                if audit['field_name'] == 'email':
                    if audit['old_value']: identifiers['emails'].add(str(audit['old_value']).lower())
                    if audit['new_value']: identifiers['emails'].add(str(audit['new_value']).lower())
                elif audit['field_name'] == 'phone':
                    if audit['old_value']: identifiers['phones'].add(audit['old_value'])
                    if audit['new_value']: identifiers['phones'].add(audit['new_value'])
                elif audit['field_name'] == 'name':
                    if audit['old_value']: identifiers['names'].add(str(audit['old_value']).lower())
                    if audit['new_value']: identifiers['names'].add(str(audit['new_value']).lower())
        # Check audit log for email
        for audit in self.audit_log:
            if str(audit.get('old_value','')).lower() == email or str(audit.get('new_value','')).lower() == email:
                identifiers['user_ids'].add(audit['user_id'])
                if audit['user_id'] in self.identity_by_user_id:
                    ident = self.identity_by_user_id[audit['user_id']]
                    identifiers['emails'].add(ident['email'].lower())
                    identifiers['names'].add(str(ident['name']).lower())
                    identifiers['phones'].add(ident['phone'])
                    identifiers['email_hashes'].add(ident['email_hash'])
        return identifiers
    
    def find_relevant_evidence(self, identifiers):
        refs = set()
        emails = identifiers['emails']
        user_ids = identifiers['user_ids']
        for evid_id, content in self.evid_content.items():
            found = False
            for email in emails:
                if email.lower() in content.lower():
                    found = True
                    break
            if not found:
                for uid in user_ids:
                    if re.search(r'\b' + re.escape(uid) + r'\b', content):
                        found = True
                        break
            if found:
                refs.add(evid_id)
        return refs
    
    def analyze_case(self, request):
        if not self.is_deletion_request(request['request_text']):
            return 'NOT_APPLICABLE', []
        identifiers = self.resolve_identifiers(request)
        evid_refs = self.find_relevant_evidence(identifiers)
        return self.deep_investigation(request, identifiers, evid_refs)
    
    def deep_investigation(self, request, identifiers, evid_refs):
        emails = list(identifiers['emails'])
        user_ids = list(identifiers['user_ids'])
        
        account_remains = []  # (evid_id, res_id, system_id)
        search_remains = []
        support_remains = []
        export_remains = []
        analytics_issues = []
        backup_risks = []
        data_flow_risks = []
        security_audit_retained = []
        
        # Search through ALL evidence for this user
        for evid_id, content in self.evid_content.items():
            is_related = False
            for email in emails:
                if email.lower() in content.lower():
                    is_related = True
                    break
            if not is_related:
                for uid in user_ids:
                    if re.search(r'\b' + re.escape(uid) + r'\b', content):
                        is_related = True
                        break
            if not is_related:
                continue
            
            # Customer profiles
            for m in re.finditer(r"(?:customer_profiles|customer_profiles_primary|customer_profiles_failover_replica)[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL | re.IGNORECASE):
                line = m.group(0)
                if any(email.lower() in line.lower() for email in emails) or any(uid in line for uid in user_ids):
                    if re.search(r"'DELETED'|\"DELETED\"|\bDELETED\b", line):
                        continue
                    m2 = re.search(r"'(account_[^']+)'|\"(account_[^\"]+)\"", line)
                    if m2:
                        res_id = m2.group(1) or m2.group(2)
                        account_remains.append((evid_id, res_id, 'account_service'))
            # Search documents
            for m in re.finditer(r"customer_search_documents[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(email.lower() in line.lower() for email in emails) or any(uid in line for uid in user_ids):
                    m2 = re.search(r"'(search_[^']+)'|\"(search_[^\"]+)\"", line)
                    if m2:
                        search_remains.append((evid_id, m2.group(1) or m2.group(2), 'search_service'))
            # Support
            for m in re.finditer(r"support_records[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids) or any(email.lower() in line.lower() for email in emails):
                    m2 = re.search(r"'(support_[^']+)'|\"(support_[^\"]+)\"", line)
                    if m2:
                        support_remains.append((evid_id, m2.group(1) or m2.group(2), 'support_platform'))
            # Exports
            for m in re.finditer(r"user_exports[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids) or any(email.lower() in line.lower() for email in emails):
                    m2 = re.search(r"'(export_[^']+)'|\"(export_[^\"]+)\"", line)
                    if m2:
                        export_remains.append((evid_id, m2.group(1) or m2.group(2), 'export_service'))
            # Analytics
            for m in re.finditer(r"analytics_profiles[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids) or any(email.lower() in line.lower() for email in emails):
                    if 'ANONYMIZED' in line:
                        continue
                    m2 = re.search(r"'(analytics_[^']+)'|\"(analytics_[^\"]+)\"", line)
                    if m2:
                        analytics_issues.append((evid_id, m2.group(1) or m2.group(2), 'analytics_platform'))
            # Backups
            for m in re.finditer(r"backup_restore_entries[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids) or any(email.lower() in line.lower() for email in emails):
                    m2 = re.search(r"'(backup_[^']+)'|\"(backup_[^\"]+)\"", line)
                    if m2:
                        backup_risks.append((evid_id, m2.group(1) or m2.group(2)))
            # Data flows
            for m in re.finditer(r"connector_subscriptions[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids) or any(email.lower() in line.lower() for email in emails):
                    if "'stopped'" in line.lower() or '"stopped"' in line.lower() or "'disabled'" in line.lower():
                        continue
                    m2 = re.search(r"'(data_flow_[^']+)'|\"(data_flow_[^\"]+)\"", line)
                    if m2:
                        data_flow_risks.append((evid_id, m2.group(1) or m2.group(2), 'integration_service'))
            for m in re.finditer(r'"resource_id"\s*:\s*"(data_flow_[^"]+)"[^}]*"subject_selector"\s*:\s*"([^"]+)"', content):
                if m.group(2).lower() in [e.lower() for e in emails]:
                    data_flow_risks.append((evid_id, m.group(1), 'integration_service'))
            # Security audit
            for m in re.finditer(r"security_audit_records[^\n]*VALUES\s*\((.*?)\);", content, re.DOTALL):
                line = m.group(0)
                if any(uid in line for uid in user_ids):
                    m2 = re.search(r"'(audit_record_[^']+)'|\"(audit_record_[^\"]+)\"", line)
                    if m2:
                        security_audit_retained.append((evid_id, m2.group(1) or m2.group(2), 'security_service'))
            # Look for search/export IDs near user in logs
            for m in re.finditer(r'(search_\d+)', content):
                start = max(0, m.start()-150); end = min(len(content), m.end()+150)
                ctx = content[start:end].lower()
                if any(email.lower() in ctx for email in emails) or any(uid in content[start:end] for uid in user_ids):
                    search_remains.append((evid_id, m.group(1), 'search_service'))
            for m in re.finditer(r'(export_\d+)', content):
                start = max(0, m.start()-150); end = min(len(content), m.end()+150)
                ctx = content[start:end].lower()
                if any(email.lower() in ctx for email in emails) or any(uid in content[start:end] for uid in user_ids):
                    export_remains.append((evid_id, m.group(1), 'export_service'))
            for m in re.finditer(r'(backup_\d+)', content):
                start = max(0, m.start()-150); end = min(len(content), m.end()+150)
                ctx = content[start:end].lower()
                if any(email.lower() in ctx for email in emails) or any(uid in content[start:end] for uid in user_ids):
                    # check if restore allowed
                    if re.search(r'restore_allowed.*true', ctx) or 'restore' in ctx and 'block' not in ctx:
                        backup_risks.append((evid_id, m.group(1)))
            for m in re.finditer(r'(data_flow_\d+)', content):
                start = max(0, m.start()-150); end = min(len(content), m.end()+150)
                ctx = content[start:end].lower()
                if any(email.lower() in ctx for email in emails) or any(uid in content[start:end] for uid in user_ids):
                    if "'enabled': true" in ctx or '"enabled":true' in ctx or "'enabled':true" in ctx:
                        data_flow_risks.append((evid_id, m.group(1), 'integration_service'))
                    elif 'enabled' in ctx and 'false' not in ctx and 'stopped' not in ctx:
                        pass
        
        # Deduplicate
        account_remains = list(set(account_remains))
        search_remains = list(set(search_remains))
        support_remains = list(set(support_remains))
        export_remains = list(set(export_remains))
        analytics_issues = list(set(analytics_issues))
        backup_risks = list(set(backup_risks))
        data_flow_risks = list(set(data_flow_risks))
        security_audit_retained = list(set(security_audit_retained))
        
        has_issues = len(account_remains) > 0 or len(search_remains) > 0 or len(support_remains) > 0 or len(export_remains) > 0 or len(backup_risks) > 0 or len(data_flow_risks) > 0 or len(analytics_issues) > 0
        
        if not has_issues:
            steps_list = []
            step_no = 1
            if user_ids:
                uid = list(user_ids)[0]
                # try to infer account id
                acc_res = f"account_{uid.split('_')[1]}" if '_' in uid and uid.split('_')[1].isdigit() else f"account_{uid}"
            else:
                acc_res = "account_unknown"
            evid_cite = list(evid_refs)[0] if evid_refs else self.evidence_files[0]['file_id']
            steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": acc_res, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": evid_cite})
            step_no += 1
            for evid_id, res_id, sys_id in security_audit_retained[:3]:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in analytics_issues[:1]:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": evid_id})
                step_no += 1
            return 'COMPLETE', steps_list
        else:
            steps_list = []
            step_no = 1
            # Findings
            for evid_id, backup_id in backup_risks:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": "backup_service", "resource_id": backup_id, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": evid_id})
                step_no += 1
            for evid_id, flow_id, sys_id in data_flow_risks:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": flow_id, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in account_remains:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": res_id, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in search_remains:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": res_id, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in support_remains:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": res_id, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in export_remains:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": res_id, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            for evid_id, res_id, sys_id in analytics_issues:
                steps_list.append({"step_no": step_no, "phase": "FINDING", "system_id": sys_id, "resource_id": res_id, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": evid_id})
                step_no += 1
            # Remediation
            for _, backup_id in backup_risks:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": "backup_service", "resource_id": backup_id, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""})
                step_no += 1
            for _, flow_id, sys_id in data_flow_risks:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": flow_id, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in account_remains:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": res_id, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in search_remains:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": res_id, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in support_remains:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": res_id, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in export_remains:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": res_id, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in analytics_issues:
                steps_list.append({"step_no": step_no, "phase": "REMEDIATION", "system_id": sys_id, "resource_id": res_id, "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""})
                step_no += 1
            # Verification
            for _, res_id, sys_id in account_remains:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, backup_id in backup_risks:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": "backup_service", "resource_id": backup_id, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""})
                step_no += 1
            for _, flow_id, sys_id in data_flow_risks:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": flow_id, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in search_remains:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in support_remains:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in export_remains:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                step_no += 1
            for _, res_id, sys_id in analytics_issues:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": ""})
                step_no += 1
            for evid_id, res_id, sys_id in security_audit_retained:
                steps_list.append({"step_no": step_no, "phase": "VERIFICATION", "system_id": sys_id, "resource_id": res_id, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": ""})
                step_no += 1
            return 'INCOMPLETE', steps_list
    
    def run(self):
        results = []
        for req in self.requests:
            status, steps = self.analyze_case(req)
            phase_order = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
            op_order = {
                'REPORT_REMAINING_RECORD': 0, 'REPORT_EXPOSED_PII': 1, 'REPORT_ACTIVE_DATA_FLOW': 2, 'REPORT_RESTORE_RISK': 3,
                'DISABLE_DATA_FLOW': 0, 'BLOCK_RESTORE': 1, 'DELETE_RECORD': 2, 'REDACT_RECORD': 3, 'ANONYMIZE_RECORD': 4,
                'VERIFY_RECORD_ABSENT': 0, 'VERIFY_RECORD_PRESENT': 1, 'VERIFY_RECORD_REDACTED': 2, 'VERIFY_RECORD_ANONYMIZED': 3, 
                'VERIFY_DATA_FLOW_DISABLED': 4, 'VERIFY_RESTORE_BLOCKED': 5
            }
            sorted_steps = sorted(steps, key=lambda x: (phase_order.get(x['phase'], 99), 
                                                       op_order.get(x['operation'], 99),
                                                       x.get('system_id', ''),
                                                       x.get('resource_id', '')))
            for i, s in enumerate(sorted_steps):
                s['step_no'] = i + 1
            results.append({
                'case_id': req['case_id'],
                'deletion_status': status,
                'steps_json': json.dumps(sorted_steps)
            })
        results.sort(key=lambda x: int(x['case_id'].split('_')[1]))
        with open(OUTPUT_PATH, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f'Wrote {len(results)} rows to {OUTPUT_PATH}')

def main():
    agent = DeletionAuditAgent()
    agent.run()

if __name__ == '__main__':
    main()
