<img width="1325" height="783" alt="image" src="https://github.com/user-attachments/assets/c1f703d9-bc5b-4d22-bdbf-b9165845f8bb" />
Visualized dashboard of Access Review findings prepared by Claude AI.

---

<img width="1498" height="710" alt="Screenshot 2026-08-25 at 11 37 01 AM" src="https://github.com/user-attachments/assets/8cd50c0c-c7f6-419c-8fa5-28b9903ffcf7" />
Copy of data in Excel for professional file sharing.

---

# Cobalt Ridge Financial - User Access Inventory

Fictional company and dataset created for IAM access review training purposes.

**50 accounts** across Finance, HR, and IT - full detail on department, title, manager, systems, group membership, privileged access flag, and the review decision for every account.

| Decision | Meaning |
|---|---|
| 🟢 **Retain** | Access matches current role. No action needed. |
| 🟠 **Revalidate** | Justification missing or outdated. Manager must confirm or it's removed. |
| 🔴 **Remove/Disable** | Access is no longer needed. Disable immediately. |

## Finance (17 accounts)

| ID | Name | Title | Manager | Type | Systems | Groups | Privileged | Last Review | Decision | Reason | Owner |
|---|---|---|---|---|---|---|:---:|---|---|---|---|
| CR-1003 | Noah Singh | Account Executive (transferred from Finance, Q1 2026) | Diane Okafor (VP Finance) | Employee | NetSuite, Concur | Finance-AR-Team, Treasury-Approvers | Yes | 2024-08-14 | 🔴 Remove/Disable | Transferred from Finance to the Sales team in Q1 2026 but retained NetSuite AR and Treasury Approver access, which no longer matches the current role and reports to a different manager. | Diane Okafor, VP Finance |
| CR-1004 | Hannah Bennett | Accounts Receivable Clerk | Robert Vance (Controller) | Employee | NetSuite, ADP Payroll | Finance-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1005 | Liam Foster | Payroll Specialist | Diane Okafor (VP Finance) | Employee | Treasury Portal, NetSuite | Finance-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1006 | Sophia Okafor | Treasury Analyst | Robert Vance (Controller) | Employee | NetSuite, Concur | Finance-AP-Approvers | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1007 | Jordan Reyes | Budget Analyst | Diane Okafor (VP Finance) | Employee | NetSuite, Excel Reporting Suite | Finance-AR-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1008 | Priya Nakamura | FP&A Analyst | Robert Vance (Controller) | Employee | Concur, ADP Payroll | Finance-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1009 | Marcus Bishop | Finance Manager | Diane Okafor (VP Finance) | Employee | NetSuite, ADP Payroll | Finance-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1010 | Elena Torres | Financial Analyst | Robert Vance (Controller) | Employee | Treasury Portal, NetSuite | Finance-AP-Approvers | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1011 | Diego Whitfield | Senior Accountant | Robert Vance (Controller) | Employee | NetSuite, Treasury Portal | Finance-AR-Team, Treasury-Approvers | Yes | 2026-02-10 | 🟠 Revalidate | Treasury Portal access was granted for a single quarter-end project; the grant has no end date and should be revalidated or converted to time-boxed access. | Diane Okafor, VP Finance |
| CR-1012 | Ava Kowalski | Accounts Payable Specialist | Robert Vance (Controller) | Employee | NetSuite, Excel Reporting Suite | Finance-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1013 | Owen Brennan | Accounts Receivable Clerk | Diane Okafor (VP Finance) | Employee | Concur, ADP Payroll | Finance-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1014 | Grace Adeyemi | Payroll Specialist | Robert Vance (Controller) | Employee | NetSuite, ADP Payroll | Finance-AP-Approvers | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1015 | Caleb Hollis | Treasury Analyst | Diane Okafor (VP Finance) | Employee | Treasury Portal, NetSuite | Finance-AR-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1016 | Ines Marchetti | Budget Analyst | Robert Vance (Controller) | Employee | NetSuite, Concur | Finance-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1017 | Tariq Delgado | FP&A Analyst | Diane Okafor (VP Finance) | Employee | NetSuite, Excel Reporting Suite | Finance-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Diane Okafor, VP Finance |
| CR-1031 | Trevor Danforth | Controller | Diane Okafor (VP Finance) | Employee | NetSuite, ADP Payroll, Treasury Portal | Payroll-Admins, Finance-AP-Approvers | Yes | 2026-02-10 | 🟢 Retain | Elevated access is documented, time-appropriate, and required for the Controller role; last reviewed and approved by the VP Finance. | Diane Okafor, VP Finance |
| CR-1034 | Ruth Winslow | Accounts Payable Specialist | Robert Vance (Controller) | Employee | NetSuite, Concur | Finance-AP-Approvers | No | 2026-02-10 | 🔴 Remove/Disable | Employee's last day was recorded four weeks ago in Workday, but NetSuite and Concur access were never deprovisioned. Access should be disabled immediately. | Diane Okafor, VP Finance |

## HR (13 accounts)

| ID | Name | Title | Manager | Type | Systems | Groups | Privileged | Last Review | Decision | Reason | Owner |
|---|---|---|---|---|---|---|:---:|---|---|---|---|
| CR-1018 | Julia Sutherland | Benefits Administrator | Marco Ibarra (HR Manager) | Employee | Workday, Benefits Portal | HR-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1019 | Sam Osei | HR Coordinator | Renee Larsen (VP People) | Employee | Workday, LMS Platform | HR-Records-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1020 | Nadia Larsen | Learning & Development Specialist | Marco Ibarra (HR Manager) | Employee | Greenhouse ATS, LMS Platform | Recruiting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1021 | Leah Petrova | Compensation Analyst | Renee Larsen (VP People) | Employee | Workday, Greenhouse ATS | HR-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1023 | Chloe Vance | HR Business Partner | Renee Larsen (VP People) | Employee | Workday, LMS Platform | Recruiting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1024 | Aiden Novak | Recruiter | Marco Ibarra (HR Manager) | Employee | Greenhouse ATS, LMS Platform | HR-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1025 | Renee Beaumont | Benefits Administrator | Renee Larsen (VP People) | Employee | Workday, Greenhouse ATS | HR-Records-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1026 | Kevin Farrow | HR Coordinator | Marco Ibarra (HR Manager) | Employee | Workday, Greenhouse ATS | HR-Records-ReadOnly | No | 2026-02-10 | 🔴 Remove/Disable | Duplicate Workday account created during a recent systems migration; the original account is still active. The duplicate should be disabled. | Renee Larsen, VP People |
| CR-1027 | Fatima Ibarra | Learning & Development Specialist | Renee Larsen (VP People) | Employee | Workday, LMS Platform | HR-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1028 | Bruno Sara | Compensation Analyst | Marco Ibarra (HR Manager) | Employee | Greenhouse ATS, LMS Platform | HR-Records-ReadOnly | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1029 | Malik Solberg | HR Generalist | Renee Larsen (VP People) | Employee | Workday, Greenhouse ATS | Recruiting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Renee Larsen, VP People |
| CR-1033 | Felix Machado | HR Business Partner | Renee Larsen (VP People) | Employee | Workday, Benefits Portal | HR-Records-Admin, Recruiting-Team | Yes | 2026-02-10 | 🟠 Revalidate | HR-Records-Admin grant predates the current HR system rollout and has no documented owner or expiration date; requires manager revalidation. | Renee Larsen, VP People |
| CR-1049 | Sara Hollis | Benefits Administrator | Renee Larsen (VP People) | Employee | Benefits Portal, Workday | Benefits-Admins, Recruiting-Team | No | 2026-02-10 | 🔴 Remove/Disable | Benefits Administrator access was retained after an internal move to Recruiting; the role no longer needs Benefits Portal write access. | Renee Larsen, VP People |

## IT (20 accounts)

| ID | Name | Title | Manager | Type | Systems | Groups | Privileged | Last Review | Decision | Reason | Owner |
|---|---|---|---|---|---|---|:---:|---|---|---|---|
| CR-1001 | Mia Chen | Service Desk Analyst | Victor Petrova (IT Director) | Employee | Okta Identity, ServiceNow | IT-Global-Admins, IT-Helpdesk-L1 | Yes | 2024-11-02 | 🟠 Revalidate | Global Administrator access in Okta has no documented business justification on file. The role (Service Desk Analyst) only requires L1 helpdesk permissions, not tenant-wide admin rights. | Victor Petrova, IT Director |
| CR-1002 | Ethan Cole | IT Support Specialist (Contract) | Sara Novak (IT Manager) | Contractor | ServiceNow, VPN Gateway | IT-Helpdesk-L1 | No | 2025-03-18 | 🔴 Remove/Disable | Contract end date (June 30, 2026) has passed. VPN and ServiceNow access remain active with no renewal record on file. | Victor Petrova, IT Director |
| CR-1022 | Victor Kildare | Systems Administrator | Victor Petrova (IT Director) | Employee | Okta Identity, Azure AD, AWS Console | IT-Global-Admins, Domain-Admins | Yes | 2026-02-10 | 🟢 Retain | Elevated access is documented, time-appropriate, and required for the Systems Administrator role; last reviewed and approved by the IT Director. | Victor Petrova, IT Director |
| CR-1030 | Zoe Hargrove | IT Support Specialist | Sara Novak (IT Manager) | Employee | ServiceNow, VPN Gateway | IT-Helpdesk-L1 | No | 2026-02-10 | 🔴 Remove/Disable | No login activity recorded in over 180 days. Access should be disabled pending confirmation with the employee's manager. | Victor Petrova, IT Director |
| CR-1032 | Amara Ellery | Database Administrator | Sara Novak (IT Manager) | Employee | ServiceNow, VPN Gateway | IT-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1035 | Gavin Castellano | Network Engineer | Victor Petrova (IT Director) | Employee | AWS Console, GitHub | DevOps-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1036 | Layla Broderick | Security Analyst | Sara Novak (IT Manager) | Employee | Datadog, ServiceNow | IT-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1037 | Oscar Alvarado | Cloud Engineer | Victor Petrova (IT Director) | Employee | Okta Identity, ServiceNow | IT-Helpdesk-L1 | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1038 | Nina Pemberton | IT Support Specialist | Sara Novak (IT Manager) | Employee | ServiceNow, VPN Gateway | Network-Admins | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1039 | Dominic Achebe | DevOps Engineer | Victor Petrova (IT Director) | Employee | Okta Identity, GitHub | DevOps-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1040 | Paige Quintero | Database Administrator | Sara Novak (IT Manager) | Employee | Azure AD, ServiceNow | IT-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1041 | Ravi Voss | Service Desk Analyst | Victor Petrova (IT Director) | Employee | AWS Console, GitHub | IT-Helpdesk-L1 | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1042 | Cara Fenwick | Systems Administrator | Sara Novak (IT Manager) | Employee | Datadog, ServiceNow | Network-Admins | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1043 | Simon Ardley | Network Engineer | Victor Petrova (IT Director) | Employee | Okta Identity, ServiceNow | DevOps-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1044 | Yara Cole | Security Analyst | Sara Novak (IT Manager) | Employee | ServiceNow, VPN Gateway | IT-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1045 | Marco Delacroix | Cloud Engineer | Victor Petrova (IT Director) | Employee | Okta Identity, GitHub | IT-Helpdesk-L1 | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1046 | Rosa Singh | IT Support Specialist | Sara Novak (IT Manager) | Employee | Azure AD, ServiceNow | Network-Admins | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1047 | Ethan Farrow | DevOps Engineer | Victor Petrova (IT Director) | Employee | AWS Console, GitHub | DevOps-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1048 | Ivy Danforth | Database Administrator | Sara Novak (IT Manager) | Employee | Datadog, ServiceNow | IT-Reporting-Team | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |
| CR-1050 | Cole Nakamura | Systems Administrator | Sara Novak (IT Manager) | Employee | ServiceNow, VPN Gateway | Network-Admins | No | 2026-02-10 | 🟢 Retain | Access aligns with current role, department, and manager; no changes identified during this review cycle. | Victor Petrova, IT Director |

---

## Summary

| Metric | Count |
|---|:---:|
| Accounts reviewed | 50 |
| Actions required (Remove/Disable + Revalidate) | 9 |
| Privileged accounts | 6 |
| Access retained as-is | 41 |

### By department

| Department | Total | Remove/Disable | Revalidate | Retain |
|---|:---:|:---:|:---:|:---:|
| Finance | 17 | 2 | 1 | 14 |
| HR | 13 | 2 | 1 | 10 |
| IT | 20 | 2 | 1 | 17 |
