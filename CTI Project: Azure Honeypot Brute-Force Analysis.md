# CTI Report: Azure Honeypot Brute-Force Analysis

**Host:** SENT-CORP-WEST | **Window:** 2026-08-03 22:21 UTC → 2026-08-20 21:00 UTC (~17 days) | **TLP:Green**

*Updated with latest query export (500,000 events, superseding the prior 7-day snapshot.)*

## Summary

500,000 failed logon events (EventID 4625, LogonType 3) from 432 source IPs targeting 7,009 usernames. Pattern remains automated, continuous credential brute-forcing against an exposed RDP/SMB-class service.

- **"Administrator"** (exact case) = 336,538 attempts (**67.3%**) - still the dominant target. Case-normalized admin-style variants = **89.3%** of all traffic (up from 71.2% previously).
- **Top 20 IPs = 77.1%** of all traffic.
- **65.1% of volume still traces to the same 3 rented VPS clusters** (Poland, Germany, France) - consistent infrastructure across both collection windows.

## Most-Targeted Usernames & Correlating IP

| TargetUserName | Attempts (%) | Top Correlating IP | From that IP | Region |
|---|---|---|---|---|
| Administrator | 336,538 (67.3%) | 88.214.25.121 | 31,259 | Germany (Frankfurt) |
| administrator | 38,175 (7.6%) | 213.55.79.194 | 6,237 | Unattributed |
| ADMINISTRATOR | 26,079 (5.2%) | 66.181.39.165 | 5,003 | Unattributed |
| admin | 21,262 (4.3%) | 64.76.8.21 | 8,743 | Unattributed |
| ADMIN | 9,785 (2.0%) | 94.26.68.54 | 2,334 | Unattributed |

*Note: "WEST"/"SENT" (hostname-derived guesses, prominent in the prior window) have dropped out of the top ranks - the two IPs driving them previously (103.103.133.93, 121.182.226.243) are no longer in the top 20, suggesting that specific actor/campaign has gone quiet.*

## Top Attacking IPs

| IP | Events | Top Target | Region / Host |
|---|---|---|---|
| 88.214.25.121 | 31,259 | Administrator (100%) | Germany - Frankfurt (VDS&VPN/one-host.net) |
| 194.165.16.167 | 29,428 | Administrator (99%) | Poland - Warsaw (Flyservers S.A., AS48721) |
| 88.214.25.124 | 28,488 | Administrator (100%) | Germany - Frankfurt |
| 194.165.16.165 | 27,935 | Administrator (100%) | Poland - Warsaw |
| 91.238.181.92 | 27,165 | Administrator (100%) | France - Paris (VDS&VPN/one-host.net) |
| 194.165.16.162 | 26,257 | Administrator (100%) | Poland - Warsaw |
| 88.214.25.123 | 26,211 | Administrator (98%) | Germany - Frankfurt |
| 194.165.16.123 | 24,852 | Administrator (100%) | Poland - Warsaw |
| 194.165.16.163 | 24,113 | Administrator (100%) | Poland - Warsaw |
| **64.76.8.21** | **22,907** | admin (38%) | Unattributed - *new top-10 entrant, was 13,982 last window* |
| 194.165.16.166 | 20,817 | Administrator (98%) | Poland - Warsaw |
| 194.165.16.161 | 19,318 | Administrator (97%) | Poland - Warsaw |
| 194.165.16.121 | 15,805 | Administrator (98%) | Poland - Warsaw |
| **213.55.79.194** | **14,828** | administrator (42%) | Unattributed - *new, not seen in prior window* |
| 194.165.16.164 | 12,103 | Administrator (91%) | Poland - Warsaw |

## Regional Trends

| Region | Provider | Subnet | IPs | Events | Share |
|---|---|---|---|---|---|
| 🇵🇱 Poland (Warsaw) | Flyservers S.A. (AS48721) | 194.165.16.0/24 | 10 | 205,717 | 41.1% |
| 🇩🇪 Germany (Frankfurt) | VDS&VPN services / one-host.net | 88.214.25.0/24 | 4 | 90,098 | 18.0% |
| 🇫🇷 France (Paris) | VDS&VPN services / one-host.net | 91.238.181.0/24 | 3 (+1 new IP) | 29,570 | 5.9% |
| Other | Unattributed | - | 415 | 174,615 | 34.9% |

All three previously-identified clusters are **still active and stable in volume/share** - this is persistent, long-running infrastructure, not a one-off burst. The France cluster added one new IP since the last window.

## What Changed Since Last Report

- Volume basis grew (7 days → 500K events over ~17 days), so totals aren't directly comparable, but **percentage concentration on "Administrator"-style accounts increased** (71.2% → 89.3%).
- **64.76.8.21** and **213.55.79.194** are new/rising unattributed sources worth investigating - no open-source WHOIS/AbuseIPDB match found for 64.76.8.21 in this pass.
- The hostname-guessing actors behind "WEST"/"SENT" (103.103.133.93, 121.182.226.243) are no longer active in top rankings.
- The 3 confirmed European VPS clusters (Poland/Germany/France) remain the core, stable backbone of the campaign.

## Recommendations

- Block/rate-limit `194.165.16.0/24`, `88.214.25.0/24`, `91.238.181.0/24` at the network edge; report to Flyservers S.A. and one-host.net abuse contacts.
- Investigate and attribute 64.76.8.21 and 213.55.79.194 via internal threat-intel tooling (Defender TI/MaxMind) - both are now top-15 sources with no open-source attribution found.
- Disable/rename built-in Administrator accounts where feasible; enforce lockout + MFA on any exposed auth surface.
- Alert on any 4624 (success) immediately following a 4625 burst from these IPs - likely indicates compromise.

---
*IP attribution from open WHOIS/geolocation lookups (AbuseIPDB/IPinfo); reflects data-center location, not attacker's physical location.*

---

## Images
<img width="1280" height="626" alt="image" src="https://github.com/user-attachments/assets/efa2fdde-8197-4112-8b8d-7b94e54f6949" />
<img width="1918" height="918" alt="image" src="https://github.com/user-attachments/assets/2420e5f7-e006-4de6-bd18-fb0ae301cf5f" />
<img width="1915" height="915" alt="image" src="https://github.com/user-attachments/assets/5fdc983c-5dfa-4840-96e6-06c91715d40b" />
<img width="1915" height="915" alt="image" src="https://github.com/user-attachments/assets/835bd3f3-e8eb-42f1-ac31-998edb004d4f" />




