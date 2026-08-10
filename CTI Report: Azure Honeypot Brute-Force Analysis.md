# CTI Report: Azure Honeypot Brute-Force Analysis

**Host:** SENT-CORP-WEST | **Window:** 2026-08-02 14:25 UTC → 2026-08-09 14:25 UTC | **TLP:GREEN**

## Summary

483,648 failed logon events (EventID 4625, LogonType 3) from 497 source IPs targeting 5,553 usernames over 7 days. Volume and pattern indicate automated, continuous credential brute-forcing against an exposed RDP/SMB-class service.

- **"Administrator"** (exact case) = 314,718 attempts (**65.1%**) — the dominant target. Case-normalized variants = 71.2%.
- **Top 20 IPs = 85.7%** of all traffic — a small number of hosts, not a broad botnet.
- **65.3% of volume traces to 3 rented VPS clusters** (Poland, Germany, France) — see below.

## Most-Targeted Usernames & Correlating IP

| TargetUserName | Attempts (%) | Top Correlating IP | From that IP | Region |
|---|---|---|---|---|
| Administrator | 314,718 (65.1%) | 88.214.25.121 | 30,566 | Germany (Frankfurt) |
| WEST | 47,409 (9.8%) | 103.103.133.93 | 32,292 | Unattributed |
| SENT | 23,966 (5.0%) | 121.182.226.243 | 12,561 | Unattributed |
| ADMINISTRATOR | 14,014 (2.9%) | 14.136.73.18 | 6,019 | Unattributed |
| administrator | 11,221 (2.3%) | 194.180.48.139 | 3,835 | Unattributed |

*Note: "WEST" and "SENT" mirror the honeypot's own hostname (`SENT-CORP-WEST')) — likely hostname-derived credential guessing.*

## Top Attacking IPs

| IP | Events | Top Target | Region / Host |
|---|---|---|---|
| 103.103.133.93 | 33,813 | WEST (96%) | Unattributed |
| 88.214.25.121 | 30,568 | Administrator (100%) | Germany — Frankfurt (VDS&VPN/one-host.net) |
| 194.165.16.167 | 28,873 | Administrator (100%) | Poland — Warsaw (Flyservers S.A., AS48721) |
| 88.214.25.124 | 27,861 | Administrator (100%) | Germany — Frankfurt |
| 194.165.16.165 | 27,491 | Administrator (100%) | Poland — Warsaw |
| 91.238.181.92 | 26,685 | Administrator (100%) | France — Paris (VDS&VPN/one-host.net) |
| 194.165.16.162 | 25,783 | Administrator (100%) | Poland — Warsaw |
| 121.182.226.243 | 24,715 | SENT (51%) | Unattributed |
| 64.76.8.21 | 13,982 | admin (31%) | Unattributed |

## Regional Trends

| Region | Provider | Subnet | IPs | Events | Share |
|---|---|---|---|---|---|
| 🇵🇱 Poland (Warsaw) | Flyservers S.A. (AS48721) | 194.165.16.0/24 | 10 | 201,074 | 41.6% |
| 🇩🇪 Germany (Frankfurt) | VDS&VPN services / one-host.net | 88.214.25.0/24 | 4 | 86,498 | 17.9% |
| 🇫🇷 France (Paris) | VDS&VPN services / one-host.net | 91.238.181.0/24 | 2 | 28,200 | 5.8% |
| Other | Unattributed | — | 481 | 167,876 | 34.7% |

The Poland cluster is near-purely single-credential brute-force (1 username/host). The Germany/France clusters share the same hosting brand across two European POPs — likely the same reseller or operator. One German host (88.214.25.123) ran a 165-username spray, distinct from its siblings.

## Recommendations

- Block/rate-limit `194.165.16.0/24`, `88.214.25.0/24`, `91.238.181.0/24` at the network edge; report to Flyservers S.A. and one-host.net abuse contacts.
- Disable/rename built-in Administrator accounts where feasible; enforce lockout + MFA on any exposed auth surface.
- Confirm RDP/SMB isn't directly internet-exposed elsewhere — use Bastion/VPN + Conditional Access.
- Enrich remaining unattributed top IPs (103.103.133.93, 121.182.226.243, 64.76.8.21, etc.) via Defender TI / MaxMind / paid AbuseIPDB API for full regional coverage.
- Alert on any 4624 (success) immediately following a 4625 burst from these IPs — likely indicates compromise.

---
*IP attribution from open WHOIS/geolocation lookups (AbuseIPDB/IPinfo); reflects data-center location, not attacker's physical location. Stats computed directly from query_data.csv (483,648 rows, no sampling).*


---

## Images
Microsoft Sentinel Logs as of August 10, 2026, approximately 13:01 UTC.
<img width="1251" height="692" alt="Screenshot 2026-08-10 at 8 59 59 AM" src="https://github.com/user-attachments/assets/d7fd1749-41f9-4d50-93f1-ce2d3ac4cf18" />

---

Microsoft Azure Log Analytics Workspace custom workbook as of August 10, 2026, approximately 13:01 UTC.


<img width="1176" height="575" alt="Screenshot 2026-08-10 at 8 58 31 AM" src="https://github.com/user-attachments/assets/362a1c82-13f0-4736-8917-223a7c1845f7" />

