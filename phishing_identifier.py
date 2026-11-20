"""Phishing Email Identifier - scans an email file and lists suspicious signs.

Email file format: header lines (From:, Subject:), a blank line, then the body.
Links are written as [display text](url).
"""
import re
import sys
from pathlib import Path

URGENT = ["urgent", "immediately", "within 24 hours", "act now", "suspended",
          "verify your account", "final notice", "locked", "expires", "limited time"]
SENSITIVE = ["password", "ssn", "social security", "credit card", "bank account", "otp", "pin"]
BAD_TLDS = (".xyz", ".top", ".click", ".tk", ".ru", ".zip")
GENERIC = ["dear customer", "dear user", "dear valued", "dear sir/madam", "dear account holder"]
LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def domain(url):
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1).lower() if m else ""


def analyze(text):
    head, _, body = text.partition("\n\n")
    headers = dict(l.split(":", 1) for l in head.splitlines() if ":" in l)
    sender = headers.get("From", "").strip()
    flags = []
    low = body.lower() + " " + headers.get("Subject", "").lower()

    hits = [w for w in URGENT if w in low]
    if hits:
        flags.append(("Urgent / threatening language", ", ".join(hits)))
    hits = [w for w in SENSITIVE if re.search(r"\b" + re.escape(w) + r"\b", low)]
    if hits:
        flags.append(("Asks for sensitive information", ", ".join(hits)))
    hits = [g for g in GENERIC if g in low]
    if hits:
        flags.append(("Generic greeting (no real name)", hits[0]))

    m = re.search(r"<[^@>]+@([^>]+)>", sender)
    sender_dom = (m.group(1) if m else sender.split("@")[-1]).strip().lower()
    display = sender.split("<")[0].strip().lower()
    for brand in ("paypal", "amazon", "microsoft", "google", "bank", "apple"):
        if brand in display and brand not in sender_dom:
            flags.append(("Sender name doesn't match sender domain", f"'{display}' sent from {sender_dom}"))
            break
    if sender_dom.endswith(BAD_TLDS) or re.search(r"\d{4,}", sender_dom):
        flags.append(("Unknown / suspicious sender domain", sender_dom))

    for text_shown, url in LINK_RE.findall(body):
        d = domain(url)
        if "." in text_shown and domain("http://" + text_shown.replace("https://", "")) != d:
            flags.append(("Mismatched link (shown text vs real URL)", f"shows '{text_shown}' but goes to {d}"))
        if re.fullmatch(r"[\d.]+", d):
            flags.append(("Link uses a raw IP address", url))
        if d.endswith(BAD_TLDS):
            flags.append(("Link uses a suspicious domain ending", d))
        if url.startswith("http://"):
            flags.append(("Link is not HTTPS", url))

    if re.search(r"attach|\.exe|\.zip|\.scr|invoice", low):
        flags.append(("Unexpected attachment / invoice mention", "check before opening"))

    verdict = "PHISHING (high risk)" if len(flags) >= 3 else "SUSPICIOUS" if flags else "Looks safe"
    return verdict, flags


def main():
    files = sys.argv[1:] or sorted(str(p) for p in Path("sample_emails").glob("*.txt"))
    for f in files:
        verdict, flags = analyze(Path(f).read_text())
        print(f"\n=== {f} ===\nVerdict: {verdict}  ({len(flags)} red flag(s))")
        for name, detail in flags:
            print(f"  [!] {name}: {detail}")


if __name__ == "__main__":
    main()
