# Traffic Violation Phishing Campaign
### TLP:CLEAR
---
## Executive Summary
This report analyzes a recently observed phishing campaign leveraging a spoofed traffic violation notice to harvest banking credentials via a malicious URL.

**What is the threat?:** Phishing campaign impersonating government traffic enforcement.

**Who is targeted?:** Residents in the state of Georgia - Fulton County, GA specifically.

**What is the objective?:** Credential harvesting & financial fraud.

**What makes it relevant?:** <50 days old and actively targeting users via SMS.

## Key Findings
This campaign is targeted at residents in the state of Georgia by a threat actor sending an image of a spoofed traffic violation that urges the victim to scan the visible QR code to make a payment on a 'traffic violation ticket'. The intent is for the user to be flustered in urgency to quickly make a payment on a low cost traffic violation for $6.99 USD due to 'Failure to Pay Toll'.
The campaign was launched on March 4th, 2026 with users receiving the phishing image on the same date which urges them to pay the 'fine' or have a 'bench warrant placed for the victims arrest'. The listed 'court date' or 'due date' was for March 5th, 2026 - which shows the intent for urgency. Obviously this is an attempt to make the victim panic into following the phishing QR code and submitting a form of payment.

*Original Phishing Image Sent by Threat Actor*

![image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/traffficticketphishing.jpg)

## Indicators of Compromise (IOCs)

Domain -
Registered on: March 3rd, 2026
   
Registrar: NameSilo, LLC

IP Address -
IP: 172.67.133.25

Hosted by: CloudFlare

Redirect Chain - 
Initial URL from QR code: `https://hin.obediencegb[.]xyz/r/he`

Final phishing page: `https://dds-georgia.uabph[.]icu/pay/` - As of April 23, 2026 the url has been taken down.

Page Assets - 
JS files - Most are null 'javascript:void(null)'

Phone Number - 
+1 945-393-1471 (Origin of phishing image)

## Infrastructure Analysis
- Domain age correlation (March 3 vs March 4 attack)
- Hosting insight (Cloudflare -> possible obfuscation)
- Domain naming patterns (.xyz, .icu)
- Redirect infrastructure purpose (tracking / evasion)

## Attack Flow
1. Victim receives SMS containing phishing image
2. Victim scans QR code
3. Redirect to intermediate URL
4. Redirect to phishing site
5. User submits PII
6. User submits payment info
7. Payment “fails” -> prompts re-entry

Initially you would be sent an image from an unknown number which states that you will have a warrant out for your arrest if you do not pay a fine. Once you scan the QR code (MITRE ID: T1566.002), you are sent to `https://hin.obediencegb[.]xyz/r/he` which then redirects you to `https://dds-georgia.uabph[.]icu/pay/`. Most of the final redirect page is emulating a legitimate government portal (MITRE ID: T1656), however most of the page is simply fluff with no real endpoint or redirects.

*Landing Page After Redirect*

![image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/trafficticketlandingpage.png)

First you are to enter your personal information so it can 'pull up your record' (MITRE ID: T1598.002), then it will prompt you with the same false state law that the victim broke, and what follows is the request for insertion of the victim's payment method. From there it will make it look like the payment failed in an attempt to get the victim to enter other credit card info.

*Payment Page Screencap*

![image alt](https://github.com/mgb-cti/2026/blob/d6eff80204d0b30f0fc5c759c44050b9237491e4/traffficticketpayment.png)

## MITRE ATT&CK Mapping

|   Tactic   | MITRE ID  | MITRE Info  |
| ------------- |:-------------:| -----:|
| Phishing QR Code   | T1566.002 | Spearphishing link |
| Posing as government website  | T1656     |  Impersonation |
| PII request | T1598.002    | Phishing for Information |

## Social Engineering Analysis
Urgency: 24-hour deadline + legal consequences

Authority: Government branding + legal terminology

Fear: Threat of arrest / bench warrant

Low friction: Small fine reduces skepticism


Psychological tactics -
- Urgency
        
- Fear
        
- Authority impersonation


## Risk Assessment
Likelihood: High (broad SMS targeting + urgency tactic)

Impact: High (financial theft + PII compromise)

Expanded:
- Credit card fraud

- Identity theft

- Potential reuse of stolen credentials

## Mitigation Recommendations
- User awareness training (QR phishing)

- SMS filtering where possible

- Domain monitoring for lookalikes

- Blocking at DNS/web proxy level

Block -

Phone number = +1 945-393-1471
  
url = `https://hin.obediencegb[.]xyz/r/he` & `https://dds-georgia.uabph[.]icu/pay/`
  
## Detection Opportunities
Splunk -
`index=* sourcetype=*
(https://dds-georgia.uabph[.]icu/pay/)
| stats count by src_ip, user, dest, uri, user_agent`

DNS -
`index=* sourcetype=dns
query="hin.obediencegb.xyz"
| stats count by src_ip, query`

## References

VirusTotal for url analysis | Triage for url analysis | MITRE ATT&CK for MITRE IDs 
---
