# Phising-Email-Identifier
**Phishing:** A cyber attack where an attacker sends a fake email that looks like it came from a trusted company, to trick the victim into clicking a malicious link or giving away passwords and card details.
**Technologies Used:** Python 3 (`re`, `pathlib`, `sys`), Markdown

This task explains how to spot a phishing email, using 4 sample emails written for this exercise (3 phishing, 1 legitimate), a checklist and a Python script that marks suspicious signs automatically.

## Common Red Flags (see checklist.md)
1. Urgent or threatening language (account suspended, act within 24 hours)
2. Mismatched links: the text shows one website but the real URL goes elsewhere
3. Unknown or look-alike sender (paypa1, amaz0n, odd endings like .xyz/.top)
4. Requests for passwords, card numbers or OTPs
5. Generic greeting such as "Dear customer"
6. Unexpected attachments or invoices
7. Too-good-to-be-true offers such as free prizes

## Setup Instructions
1. Install Python 3.8 or above
2. Open Command Prompt in the Task-3 folder
3. Run `python phishing_identifier.py` to scan all emails in `sample_emails/`, or `python phishing_identifier.py yourfile.txt`

## Results
```
email1_bank_phish.txt
Verdict: PHISHING (high risk) (8 red flag(s))
  [!] Urgent / threatening language: urgent, immediately, within 24 hours, suspended, verify your account, locked
  [!] Asks for sensitive information: password
  [!] Generic greeting (no real name): dear customer
  [!] Sender name doesn't match sender domain: 'paypal support' sent from paypa1-verify.xyz
  [!] Unknown / suspicious sender domain: paypa1-verify.xyz
  [!] Mismatched link (shown text vs real URL): shows 'www.paypal.com/verify' but goes to 185.23.44.9
  [!] Link uses a raw IP address: http://185.23.44.9/login
  [!] Link is not HTTPS: http://185.23.44.9/login

email4_legitimate.txt
Verdict: Looks safe (0 red flag(s))
```

## Summary of Findings
| Email | Verdict | Main red flags |
|---|---|---|
| email1_bank_phish | Phishing | urgent language, fake PayPal sender, link shows paypal.com but goes to an IP address, asks for password |
| email2_prize_scam | Phishing | fake prize, asks for card details, suspicious .top/.click domains |
| email3_fake_invoice | Phishing | fake Amazon sender, attachment, urgent tone, mismatched link |
| email4_legitimate | Safe | personal greeting, normal domain, no links or requests |

## Conclusion
No single sign proves an email is phishing, but three or more together mean high risk. Never click links in suspicious emails: open the official website yourself and report the email.
