# Traffic Violation Phishing Campaign
---
## Executive Summary
This report analyzes a recently observed phishing campaign leveraging a spoofed traffic violation notice to harvest banking credentials via a malicious URL.

**What is the threat?:** Phishing campaign impersonating government traffic enforcement.
**Who is targeted?:** Residents in the state of Georgia - Fulton County, GA specifically.
**What is the objective?:** Credential harvesting & financial fraud.
**What makes it relevant?:** <50 days old

## Key Findings
This campaign is targeted at residents in the state of Georgia by a threat actor sending an image of a spoofed traffic violation that urges the victim to scan the visible QR code to make a payment on a 'traffic violation ticket'. The intent is for the user to be flustered in urgency to quickly make a payment on a low cost traffic violation for $6.99 USD due to 'Failure to Pay Toll'.
The campaign was launched on March 4th, 2026 with users receiving the phishing image on the same date which urges them to pay the 'fine' or have a 'bench warrant placed for the victims arrest'. The listed 'court date' or 'due date' was for March 5th, 2026 - which shows the intent for urgency. Obviously this is an attempt to make the victim panic into following the phishing QR code and submitting a form of payment.

[!image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/traffficticketphishing.jpg)

## Indicators of Compromise (IOCs)
Domain -
    Registered on: March 3rd, 2026
    Registrar: NameSilo, LLC
IP Address -
    IP: 172.67.133.25
    Hosted by: CloudFlare
Redirect Chain - 
    Inital URL from QR code: `https://hin.obediencegb.xyz/r/he`
    Final phishing page: `https://dds-georgia.uabph.icu/pay/`
Page Assets - 
    JS files - Most are null 'javascript:void(null)'
Phone Number - 
    +1 945-393-1471 (Origin of phishing image)

## Infrastructure Analysis

## Attack Flow
Initally you would be sent an image from an unknown number which states that you will have a warrant out for your arrest if you do not pay a fine. Once you scan the QR code (MITRE ID: T1566.002), you are sent to `https://hin.obediencegb.xyz/r/he` which then redirects you to `https://dds-georgia.uabph.icu/pay/`. Most of the final redirect page is a great replica of what looks to be a real government website (MITRE ID: T1656), however most of the page is simply fluff with no real endpoint or redirects.
[!image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/trafficticketlandingpage.png)
First you are to enter your personal information so it can 'pull up your record' (MITRE ID: T1598.002), then it will prompt you with the same false state law that the victim broke, and what follows is the request for insertion of the victim's payment method (MITRE ID: T1657). From there it will make it look like the payment failed in an attempt to get the victim to enter other credit card info.
[!image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/traffficticketpayment.png)

## MITRE ATT&CK Mapping

|   Tactic   | MITRE ID  | MITRE Info  |
| ------------- |:-------------:| -----:|
| Phishing QR Code   | T1566.002 | Spearphishing link |
| Posing as government website  | T1656     |  Impersonation |
| PII request | T1598.002    | Phishing for Information |
| CHD request | T1657   |   Financial Theft |


## Social Engineering Analysis
Psychological tactics -
    - Urgency
    - Authority impersonation
    - Fear

## Risk Assessment
This will be mostly targeted at any phone number registered in the state of Georgia.  Expect end points mobile devices to be tagreted via SMS.
The likelihood of this is large and severity is minimal unless an end user falls for the phishing link.

## Mitigation Recommendations
Block -
  Phone number = +1 945-393-1471
  url = `https://hin.obediencegb.xyz/r/he`
        `https://dds-georgia.uabph.icu/pay/`

## References
VirusTotal for url analysis | Triage for url analysis | MITRE ATT&CK for MITRE IDs 
---
