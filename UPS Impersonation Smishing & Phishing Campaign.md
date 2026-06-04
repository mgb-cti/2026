# CTI Report: UPS Impersonation Smishing & Phishing Campaign
**TLP: WHITE** | **Report Date:** 2026-06-04 | **Analyst:** mgb-cti | **Confidence:** Moderate–High (Infrastructure); Low–Moderate (Actor Attribution)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Victim Targeting](#2-victim-targeting)
3. [Campaign Overview](#3-campaign-overview)
4. [Delivery Mechanism](#4-delivery-mechanism)
5. [Infrastructure Analysis](#5-infrastructure-analysis)
6. [Indicators of Compromise (IOCs)](#6-indicators-of-compromise-iocs)
7. [Actor Attribution Assessment](#7-actor-attribution-assessment)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Recommended Actions](#9-recommended-actions)
10. [References & Reporting Contacts](#10-references--reporting-contacts)
11. [Images & Examples](#11-images--examples)

---

## 1. Executive Summary

An active smishing campaign impersonating United Parcel Service (UPS) was identified on 2026-06-03, leveraging PDF-lure text messages to drive victims to a multi-stage phishing infrastructure designed to harvest cardholder data (CHD), personally identifiable information (PII), and residential address information. The campaign operates across twenty bulk-registered domains sharing a common algorithmic naming convention, with sixteen unique tracking subdomains deployed under the confirmed active domain `1usa18aioiiku69[.]us` to enable per-victim click telemetry. Terminal data collection occurs at `kvntiebwm[.]life`, a domain registered one day before campaign identification, with harvested data exfiltrated in real time via a webhook. Infrastructure characteristics, including APAC-hosted IP addresses, NameSilo bulk registration patterns, multi-hop redirect chains, and package-delivery lure themes overlap significantly with TTPs attributed to the **Smishing Triad** and the **Darcula** Phishing-as-a-Service platform, both Chinese-nexus threat clusters. Immediate action is recommended to block identified infrastructure, report to relevant abuse and law enforcement channels, and monitor the broader `1usa*[.]us` domain cluster for continued activity.

---

## 2. Victim Targeting

### 2.1 Target Profile

This campaign is broadly targeted at general consumers in North America, with no evidence of vertical-specific or demographic-specific filtering at this time. The UPS brand impersonation is deliberately generic, package delivery is a near-universal consumer experience which maximizes the potential victim pool across age groups, technical literacy levels, and geographic regions. The Canadian-area-code sender number (`+1 416-274-1357`) suggests at least partial targeting of Canadian recipients, though spoofed VOIP numbers make definitive geographic scoping unreliable.

### 2.2 Data Harvested

A successful phishing interaction is designed to collect the following categories of sensitive information via the terminal form at `kvntiebwm[.]life/uqjmw/form`:

| Data Category | Examples | Classification |
|---|---|---|
| **Cardholder Data (CHD)** | Payment card number, expiry date, CVV | PCI-DSS Sensitive |
| **Personally Identifiable Information (PII)** | Full name, date of birth, email address, phone number | Regulated — varies by jurisdiction |
| **Residential / Home Information** | Street address, city, state/province, ZIP/postal code | PII — moderate sensitivity |

### 2.3 Downstream Impact

Victims who complete the phishing form face multiple categories of downstream harm:

**Financial fraud** is the most immediate risk. Harvested CHD enables card-not-present (CNP) fraud, unauthorized purchases, and potential cash advances. Depending on card type and issuer response time, victims may face significant financial loss before cards are cancelled.

**Identity theft** is a compounding risk when CHD is combined with full name, address, and date of birth -  a data combination sufficient to open new lines of credit, file fraudulent tax returns, or conduct account takeover (ATO) attacks against banking and e-commerce platforms.

**Credential stuffing enablement** is a secondary risk if victims reuse passwords across services and the actor cross-references harvested email addresses against breach databases.

**Physical security risk** is a lower-probability but notable concern given the collection of home address data, which could facilitate targeted physical fraud, parcel interception, or be resold to other criminal actors operating physical scam networks.

Data is exfiltrated in real time via a webhook (`d2c19b29-3ae0-44a5-a780-bd42c8084b09`), meaning harvested records are available to the threat actor immediately upon victim form submission, reducing the detection and intervention window to near zero.

---

## 3. Campaign Overview

### 3.1 Lure Theme

The campaign impersonates **United Parcel Service (UPS)**, a globally recognized package delivery brand. Victims receive an unsolicited SMS text message containing a PDF attachment. The lure message instructs recipients to check the attachment immediately to avoid their package being returned to sender, creating a false sense of urgency to drive interaction.

This social engineering tactic exploits routine consumer expectations around package delivery, making it highly effective across a broad demographic.

### 3.2 Subdomain Tracking Architecture

Analysis identified sixteen unique three-character subdomains under the parent domain `1usa18aioiiku69[.]us`. Each hyperlink embedded within the PDF resolved through a distinct subdomain before redirecting to the same phishing destination. The use of unique subdomains for individual PDF elements likely serves click-tracking and campaign telemetry purposes, allowing the threat actor to determine which specific document elements are interacted with by victims. This technique also increases the effective clickable area of the lure and may provide anti-analysis benefits by distinguishing human interaction from automated scanning activity.

### 3.3 Redirect Chain

> **⚠️ Infrastructure Update — 2026-06-04:** The original terminal harvest domain `kvntiebwm[.]life` has been taken down. The threat actor has pivoted to a new harvest domain (`eakdlcm[.]life`), demonstrating active infrastructure resilience and rapid domain rotation. All distribution URLs now resolve to the updated chain below.

**Original chain (kvntiebwm[.]life — TAKEN DOWN):**

```
https://<3-char-subdomain>.1usa18aioiiku69[.]us/
        ↓
https://jqxeonxtn[.]life/uqjmw
        ↓
https://kvntiebwm[.]life/uqjmw/form  ← TAKEN DOWN
```

**Current active chain (as of 2026-06-04):**

```
https://<3-char-subdomain>.1usa18aioiiku69[.]us/
        ↓
https://eakdlcm[.]life/uqjmw  ← NEW active harvest destination
```

The actor's ability to swap the terminal harvest domain while leaving the entire distribution infrastructure (`1usa18aioiiku69[.]us` subdomains) intact confirms that the intermediate relay layer (`jqxeonxtn[.]life`) functions as an anti-takedown buffer — insulating the distribution layer from disruption of individual harvest domains. This rotation pattern is consistent with documented Smishing Triad / Darcula operational behavior and should be expected to continue. All `*.life` domains resolving to the identified APAC IPs should be treated as active or pre-positioned harvest infrastructure.

### 3.4 Bulk Domain Infrastructure

Reverse WHOIS analysis identified twenty domains sharing the same registration details, registrar, creation date, and naming convention. The domains appear to have been registered in bulk as part of a coordinated infrastructure deployment. While the common registration information links the domains operationally, the WHOIS registrant details alone are insufficient for actor attribution due to the possibility of falsified or stolen registration information.

The naming convention follows a consistent algorithmic pattern: `1usa[NN][random-alphanumeric].[TLD]`, strongly suggesting automated bulk registration tooling rather than manual domain creation.

---

## 4. Delivery Mechanism

| Attribute | Detail |
|---|---|
| **Delivery vector** | SMS (smishing) |
| **Sender number** | `+1 416-274-1357` *(Canadian area code - likely spoofed or VOIP)*  |
| **Attachment type** | PDF file |
| **Lure theme** | Fake UPS package delivery issue |
| **Urgency tactic** | "Check attachment immediately to avoid package being returned" |
| **Embedded payload** | Hyperlinks within PDF using unique tracking subdomains |

> **MDM Note:** The sender number `+1 416-274-1357` should be added to MDM blocklists immediately.

---

## 5. Infrastructure Analysis

### 5.1 Primary Phishing Domain

| Field | Value |
|---|---|
| **Domain** | `1usa18aioiiku69[.]us` |
| **Registrar** | NameSilo, LLC |
| **Registered** | 2026-05-29 |
| **Updated** | 2026-06-03 |
| **Expiry** | 2027-05-29 |

### 5.2 Harvest Domain — Original (TAKEN DOWN)

| Field | Value |
|---|---|
| **Domain** | `kvntiebwm[.]life` |
| **Registrar** | NameSilo, LLC |
| **Registered** | 2026-06-03 *(one day prior to identification)* |
| **Status** | ⛔ TAKEN DOWN as of 2026-06-04 |
| **Notes** | Extremely fresh registration consistent with actor spinning up harvest infrastructure immediately before campaign launch. Takedown confirmed — actor pivoted to a replacement domain within the same operational cycle. |

### 5.3 Harvest Domain — Replacement (ACTIVE)

| Field | Value |
|---|---|
| **Domain** | `eakdlcm[.]life` |
| **Status** | ✅ ACTIVE as of 2026-06-04 |
| **Active URL** | `hxxps://eakdlcm[.]life/uqjmw` |
| **Notes** | Replacement harvest domain activated following takedown of `kvntiebwm[.]life`. Identical path structure (`/uqjmw`) is retained, indicating templated or automated infrastructure deployment. Rapid pivot confirms the actor maintains a pre-staged domain inventory. All `*.life` domains resolving to the identified APAC IPs should be treated as active or pre-positioned harvest infrastructure. |

### 5.4 Active Subdomain URLs (Distribution Layer)

All sixteen subdomains resolve to the same redirect chain. Defanged for safe sharing:

```
hxxps://ueg.1usa18aioiiku69[.]us/
hxxps://tcj.1usa18aioiiku69[.]us/
hxxps://pvw.1usa18aioiiku69[.]us/
hxxps://swt.1usa18aioiiku69[.]us/
hxxps://odi.1usa18aioiiku69[.]us/
hxxps://emz.1usa18aioiiku69[.]us/
hxxps://ocs.1usa18aioiiku69[.]us/
hxxps://jje.1usa18aioiiku69[.]us/
hxxps://pmm.1usa18aioiiku69[.]us/
hxxps://ine.1usa18aioiiku69[.]us/
hxxps://why.1usa18aioiiku69[.]us/
hxxps://xma.1usa18aioiiku69[.]us/
hxxps://ign.1usa18aioiiku69[.]us/
hxxps://mtk.1usa18aioiiku69[.]us/
hxxps://coa.1usa18aioiiku69[.]us/
hxxps://dfh.1usa18aioiiku69[.]us/
```

### 5.4 Related Domains (Same Registration Cluster)

The following twenty domains share registration details and naming convention, indicating bulk coordinated deployment:

```
1usa01xboxlti28[.]us       1usa02ubgtmur26[.]us
1usa03gsbbtra99[.]us       1usa04lutyrak82[.]us
1usa05jyccpil83[.]us       1usa06ratpzjo48[.]us
1usa07cshezsd31[.]us       1usa08gfsvljf84[.]us
1usa09wngrdai56[.]us       1usa10vzaytvq17[.]us
1usa11axxhhgo97[.]us       1usa12fnnxgzx64[.]us
1usa13zbaoxlz35[.]us       1usa14tkdqzgk45[.]us
1usa15mzspbsh64[.]us       1usa16xhgclne46[.]us
1usa17pqguxgk67[.]us       1usa18aioiiku69[.]us  ← Active (confirmed)
1usa19gzbzcvq52[.]us       1usa20aondqsg83[.]us
```

> **Analyst Note:** All twenty domains should be treated as active or pre-positioned phishing infrastructure. Blocking the pattern `1usa*[.]us` may be appropriate for high-security environments.

### 5.5 IP Infrastructure

| IP Address | Notes |
|---|---|
| `49.51.70.217` | Associated with campaign infrastructure — verify current hosting provider via WHOIS/BGP |
| `43.173.104.156` | Associated with campaign infrastructure — verify current hosting provider via WHOIS/BGP |

Both IPs fall within APAC address space consistent with Chinese cloud/CDN provider allocation, a pattern frequently observed in smishing campaigns attributed to Chinese-nexus threat actors (see Section 7).

### 5.6 Exfiltration Webhook

A webhook UUID was identified, likely used for real-time data exfiltration notification (e.g., via a Telegram bot or webhook service):

```
d2c19b29-3ae0-44a5-a780-bd42c8084b09
```

This UUID should be monitored or reported to the associated platform to disrupt the actor's ability to receive harvested data in real time.

---

## 6. Indicators of Compromise (IOCs)

### 6.1 Domains

| Indicator | Type | Confidence | Notes |
|---|---|---|---|
| `1usa18aioiiku69[.]us` | Domain | High | Confirmed active distribution domain |
| `kvntiebwm[.]life` | Domain | High | Original terminal harvest domain — ⛔ TAKEN DOWN 2026-06-04; retain for blocking/historical tracking |
| `eakdlcm[.]life` | Domain | High | ✅ ACTIVE replacement harvest domain as of 2026-06-04 |
| `jqxeonxtn[.]life` | Domain | High | Redirect relay domain |
| `1usa01xboxlti28[.]us` – `1usa20aondqsg83[.]us` | Domain cluster | High | Bulk-registered infrastructure (see Section 5.4) |

### 6.2 IP Addresses

| Indicator | Type | Confidence | Notes |
|---|---|---|---|
| `49.51.70.217` | IPv4 | High | Campaign infrastructure |
| `43.173.104.156` | IPv4 | High | Campaign infrastructure |

### 6.3 Phone Number

| Indicator | Type | Confidence | Notes |
|---|---|---|---|
| `+14162741357` | Phone (E.164) | High | Smishing sender; Canadian VOIP/spoofed number |

### 6.4 Webhook

| Indicator | Type | Confidence | Notes |
|---|---|---|---|
| `d2c19b29-3ae0-44a5-a780-bd42c8084b09` | Webhook UUID | Moderate | Real-time exfiltration channel |
| `75e7a535-9492-4dd1-b5c8-d7011cb54265` | Webhook UUID | Moderate | Real-time exfiltration channel |


### 6.5 URL Patterns

| Indicator | Type | Notes |
|---|---|---|
| `hxxps://[3-char].1usa18aioiiku69[.]us/` | URL pattern | 16 subdomains confirmed |
| `hxxps://jqxeonxtn[.]life/uqjmw` | URL | Redirect hop |
| `hxxps://kvntiebwm[.]life/uqjmw/form` | URL | Live harvest form |

---

## 7. Actor Attribution Assessment

**Attribution Confidence: LOW–MODERATE**
**Suspected Cluster: Smishing Triad / Darcula PhaaS (Chinese-Nexus)**

### 7.1 Overlapping Indicators

Several characteristics of this campaign align closely with the **Smishing Triad**, a well-documented Chinese-nexus cybercriminal group, and the **Darcula** Phishing-as-a-Service (PhaaS) platform:

| Characteristic | This Campaign | Smishing Triad / Darcula |
|---|---|---|
| Delivery vector | SMS smishing with PDF attachment | SMS / iMessage / RCS smishing |
| Lure theme | Package delivery (UPS) | Package delivery, toll services, postal brands |
| Infrastructure | Bulk domain registration via NameSilo | Bulk domain registration; 194,000+ domains documented |
| Hosting | APAC IP space (Chinese CDN/cloud providers) | Tencent, Alibaba Cloud ASNs documented |
| Naming convention | Algorithmic: `1usa[NN][random].[TLD]` | Automated bulk registration tooling |
| Redirect chains | Multi-hop redirect before harvest form | Multi-hop redirect chains documented |
| Subdomain tracking | Unique per-link subdomains for telemetry | Per-victim unique link generation documented |
| Registrar | NameSilo, LLC | NameSilo among documented registrars |
| Domain freshness | Harvest domain registered 1 day before campaign | Rapid registration-to-deployment lifecycle |

### 7.2 Caveats

Attribution to Smishing Triad or Darcula should be treated as a **working hypothesis** rather than a confirmed finding. The following caveats apply:

- WHOIS registrant details may be falsified or represent stolen identity information and cannot be used as sole attribution evidence.
- Darcula is a PhaaS platform — multiple independent threat actors may operate campaigns using the same kit with similar TTPs, making individual actor differentiation difficult.
- No kit-level fingerprint (backend script, hardcoded email, Telegram token) has been confirmed at the time of this report. Recovery of the phishing kit would significantly increase attribution confidence.
- Shared infrastructure (CDN/cloud) does not imply shared actor; Chinese cloud providers are widely abused by unrelated threat actors globally.

### 7.3 Recommended Attribution Actions

- Submit IOCs to **Palo Alto Unit 42** and **Silent Push** for cross-referencing against known Smishing Triad/Darcula infrastructure databases.
- Attempt phishing kit retrieval by probing for exposed `.zip` or `/admin` paths on active domains.
- Monitor the webhook UUID for associated service (Telegram, Discord, etc.) to identify exfiltration infrastructure linkages.

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | SMS smishing delivery |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | PDF attachment as lure |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | Bulk domain registration (20 domains) |
| Resource Development | Acquire Infrastructure: Web Services | T1583.006 | Webhook for exfiltration |
| Resource Development | Stage Capabilities: Upload Tool | T1608.002 | Redirect relay domain deployment |
| Collection | Input Capture: Web Portal Capture | T1056.003 | Credential/CHD harvest form |
| Command & Control | Web Service | T1102 | Webhook-based data exfiltration |
| Exfiltration | Exfiltration Over Web Service | T1567 | Real-time webhook exfiltration |
| Defense Evasion | Traffic Signaling / Redirect | T1205 | Multi-hop redirect chain; subdomain-per-link anti-analysis |

---

## 9. Recommended Actions

### 9.1 Immediate (0–24 hrs)

- [ ] Block all 20 `1usa*[.]us` domains and both IPs at the perimeter firewall and DNS sinkholes.
- [ ] Add sender number `+1 416-274-1357` to MDM/UEM blocklist.
- [ ] Block `kvntiebwm[.]life` and `jqxeonxtn[.]life` across web proxies and endpoint DNS.
- [ ] Report webhook UUID to the associated platform (Telegram/Discord abuse teams) for account suspension.
- [ ] Submit all IOCs to **PhishTank**, **Google Safe Browsing** (`safebrowsing.google.com/safebrowsing/report_phish/`), and **OpenPhish**.

### 9.2 Short-Term (24–72 hrs)

- [ ] Submit abuse report to **NameSilo** at `abuse@namesilo.com` for all 20 domains — include this report as supporting evidence.
- [ ] Report to **UPS Security** at `fraud@ups.com` for brand impersonation coordination.
- [ ] Report smishing number to the carrier and to **FTC** at `reportfraud.ftc.gov`.
- [ ] Forward smishing text to **7726 (SPAM)** — carrier-level reporting.
- [ ] File a complaint with **IC3** (`ic3.gov`) given the CHD/PII harvesting scope.
- [ ] Submit IOCs to **CISA** (`cisa.gov/report`) if any critical infrastructure personnel are among potential victims.

### 9.3 Ongoing

- [ ] Monitor the full `1usa*[.]us` domain pattern for new registrations.
- [ ] Monitor `*.life` domains resolving to the identified IP addresses for new harvest infrastructure.
- [ ] Cross-reference IOCs against **AlienVault OTX**, **ThreatFox**, and **AbuseIPDB**.
- [ ] Submit to **Palo Alto Unit 42** Smishing Triad tracking team for cluster analysis.

---

## 10. References & Reporting Contacts

| Resource | URL / Contact |
|---|---|
| NameSilo Abuse | `abuse@namesilo.com` — `namesilo.com/report_abuse.php` |
| UPS Fraud | `fraud@ups.com` |
| PhishTank | `phishtank.org` |
| Google Safe Browsing | `safebrowsing.google.com/safebrowsing/report_phish/` |
| CISA Report | `cisa.gov/report` |
| IC3 | `ic3.gov` |
| FTC Fraud | `reportfraud.ftc.gov` |
| Smishing to Carrier | Forward to `7726` (SPAM) |
| AlienVault OTX | `otx.alienvault.com` |
| ThreatFox | `threatfox.abuse.ch` |
| AbuseIPDB | `abuseipdb.com` |
| Palo Alto Unit 42 | `unit42.paloaltonetworks.com` |
| Smishing Triad Research (Palo Alto) | `securityweek.com/massive-china-linked-smishing-campaign-leveraged-194000-domains/` |
| Darcula PhaaS (Wikipedia) | `en.wikipedia.org/wiki/Darcula` |

---

## 11. Images & Examples

*PDF Lure*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-PDF-lure.png)

----

*SMS Example*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-SMS.png)

---

*Phishing Landing Page*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-landingpage.png)

---

*First page prompting victim PII*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-firstpage.png)

---

*Second page prompting payment (CHD)*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-secondpage.png)

---

*Third page prompting for an OTP*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-OTP.png)

---

*Example of webhook via browser network tab - webhooking logging info per key stroke.*

![image alt](https://github.com/mgb-cti/2026/blob/main/2026-Images/UPS-Smishing-networkwebhook-proof.png)


------


*Report generated by mgb-cti on 2026-06-04*

*TLP: WHITE | May be shared freely with appropriate attribution.*
