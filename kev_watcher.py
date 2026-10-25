#!/usr/bin/env python3
"""
KEV Watcher - monitor the CISA Known Exploited Vulnerabilities (KEV) catalog
and report entries that matter to *your* stack.

Pure Python standard library. No API keys. Read-only.

Examples:
    python kev_watcher.py --watch apache,microsoft,fortinet
    python kev_watcher.py --watchlist stack.txt --new-only --format markdown
    python kev_watcher.py --since 7 --ransomware --format json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import date, datetime, timedelta
from typing import Iterable

__version__ = "1.0.0"

FEED_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Official CISA-maintained mirror on GitHub, used as a fallback.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
)
USER_AGENT = f"kev-watcher/{__version__} (+https://github.com/Zasnit1/kev-watcher)"
DEFAULT_STATE = os.path.join(os.path.expanduser("~"), ".kev_watcher_state.json")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: str
    description: str
    required_action: str
    cwes: tuple[str, ...] = ()

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"

    @property
    def is_ransomware(self) -> bool:
        return self.ransomware.strip().lower() == "known"

    @classmethod
    def from_raw(cls, raw: dict) -> "KevEntry":
        return cls(
            cve=str(raw.get("cveID", "")).strip(),
            vendor=str(raw.get("vendorProject", "")).strip(),
            product=str(raw.get("product", "")).strip(),
            name=str(raw.get("vulnerabilityName", "")).strip(),
            date_added=str(raw.get("dateAdded", "")).strip(),
            due_date=str(raw.get("dueDate", "")).strip(),
            ransomware=str(raw.get("knownRansomwareCampaignUse", "Unknown")).strip(),
            description=str(raw.get("shortDescription", "")).strip(),
            required_action=str(raw.get("requiredAction", "")).strip(),
            cwes=tuple(str(c) for c in (raw.get("cwes") or [])),
        )


# --------------------------------------------------------------------------- feed

def load_feed(source: str | None = None, timeout: float = 30.0) -> dict:
    """Load the KEV feed from a local file, a URL, or the default CISA URLs."""
    if source and os.path.exists(source):
        with open(source, encoding="utf-8") as fh:
            return json.load(fh)
    urls = (source,) if source else FEED_URLS
    errors = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("Could not load the KEV feed:\n  " + "\n  ".join(errors))


def parse_entries(feed: dict) -> list[KevEntry]:
    entries = []
    for raw in feed.get("vulnerabilities", []):
        entry = KevEntry.from_raw(raw)
        if CVE_RE.match(entry.cve):
            entries.append(entry)
    return entries


# --------------------------------------------------------------------------- filters

def read_watchlist(path: str) -> list[str]:
    terms = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                terms.append(line)
    return terms


def matches(entry: KevEntry, terms: Iterable[str]) -> bool:
    """Case-insensitive whole-word match against vendor, product and name."""
    haystack = f"{entry.vendor} {entry.product} {entry.name}".lower()
    for term in terms:
        term = term.strip().lower()
        if term and re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", haystack):
            return True
    return False


def apply_filters(entries: list[KevEntry], terms: list[str] | None = None, since_days: int | None = None,
                  ransomware_only: bool = False, today: date | None = None) -> list[KevEntry]:
    today = today or date.today()
    out = []
    for e in entries:
        if terms and not matches(e, terms):
            continue
        if ransomware_only and not e.is_ransomware:
            continue
        if since_days is not None:
            try:
                added = datetime.strptime(e.date_added, "%Y-%m-%d").date()
            except ValueError:
                continue
            if added < today - timedelta(days=since_days):
                continue
        out.append(e)
    return sorted(out, key=lambda x: (x.date_added, x.cve), reverse=True)


# --------------------------------------------------------------------------- state

def load_state(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return set(json.load(fh).get("seen", []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_state(path: str, seen: set[str]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"updated": datetime.now().isoformat(timespec="seconds"), "seen": sorted(seen)}, fh)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- output

def due_status(entry: KevEntry, today: date | None = None) -> str:
    today = today or date.today()
    try:
        due = datetime.strptime(entry.due_date, "%Y-%m-%d").date()
    except ValueError:
        return "-"
    days = (due - today).days
    if days < 0:
        return f"overdue {-days}d"
    return f"in {days}d"


def render_table(entries: list[KevEntry], today: date | None = None) -> str:
    if not entries:
        return "No matching KEV entries."
    rows = [("CVE", "ADDED", "DUE", "RANSOMWARE", "VENDOR / PRODUCT")]
    for e in entries:
        rows.append((e.cve, e.date_added, due_status(e, today), "yes" if e.is_ransomware else "-",
                     f"{e.vendor} / {e.product}"))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = []
    for i, r in enumerate(rows):
        lines.append("  ".join(r[c].ljust(widths[c]) for c in range(4)) + "  " + r[4])
        if i == 0:
            lines.append("  ".join("-" * w for w in widths) + "  " + "-" * 16)
    lines.append(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}.")
    return "\n".join(lines)


def render_markdown(entries: list[KevEntry], today: date | None = None) -> str:
    if not entries:
        return "_No matching KEV entries._"
    out = ["| CVE | Added | Due | Ransomware | Vendor / Product | Name |", "|---|---|---|---|---|---|"]
    for e in entries:
        name = e.name.replace("|", "\\|")
        out.append(f"| [{e.cve}]({e.nvd_url}) | {e.date_added} | {due_status(e, today)} | "
                   f"{'yes' if e.is_ransomware else '-'} | {e.vendor} / {e.product} | {name} |")
    return "\n".join(out)


def render_json(entries: list[KevEntry]) -> str:
    return json.dumps([{**asdict(e), "cwes": list(e.cwes), "nvd_url": e.nvd_url} for e in entries], indent=2)


def post_webhook(url: str, entries: list[KevEntry], timeout: float = 15.0) -> None:
    """Send a short summary to a Slack / Discord / Mattermost compatible incoming webhook."""
    if not entries:
        return
    lines = [f"{len(entries)} new KEV entr{'y' if len(entries) == 1 else 'ies'} matching your watchlist:"]
    for e in entries[:20]:
        flag = " [ransomware]" if e.is_ransomware else ""
        lines.append(f"- {e.cve} {e.vendor} {e.product}: {e.name}{flag} (due {e.due_date}) {e.nvd_url}")
    if len(entries) > 20:
        lines.append(f"...and {len(entries) - 20} more.")
    text = "\n".join(lines)
    body = json.dumps({"text": text, "content": text[:1990]}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout):
        pass


# --------------------------------------------------------------------------- cli

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kev_watcher", description="Monitor the CISA KEV catalog for vendors and products you care about.")
    p.add_argument("--watch", help="Comma-separated vendor/product keywords, e.g. 'apache,fortinet,ivanti'.")
    p.add_argument("--watchlist", help="File with one keyword per line (# comments allowed).")
    p.add_argument("--since", type=int, metavar="DAYS", help="Only entries added in the last DAYS days.")
    p.add_argument("--ransomware", action="store_true", help="Only entries with known ransomware campaign use.")
    p.add_argument("--new-only", action="store_true", help="Only entries not seen in a previous run (uses --state).")
    p.add_argument("--state", default=DEFAULT_STATE, help=f"State file for --new-only (default: {DEFAULT_STATE}).")
    p.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    p.add_argument("--webhook", default=os.environ.get("KEV_WEBHOOK_URL"), help="Incoming webhook URL (or env KEV_WEBHOOK_URL).")
    p.add_argument("--feed", help="Local KEV JSON file or alternative URL (default: CISA, with GitHub mirror fallback).")
    p.add_argument("--fail-on-match", action="store_true", help="Exit with code 3 when anything matches (useful in CI).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    terms: list[str] = []
    if args.watch:
        terms += [t for t in args.watch.split(",") if t.strip()]
    if args.watchlist:
        terms += read_watchlist(args.watchlist)

    try:
        feed = load_feed(args.feed)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2

    entries = apply_filters(parse_entries(feed), terms or None, args.since, args.ransomware)

    if args.new_only:
        seen = load_state(args.state)
        fresh = [e for e in entries if e.cve not in seen]
        save_state(args.state, seen | {e.cve for e in entries})
        entries = fresh

    if args.format == "json":
        print(render_json(entries))
    elif args.format == "markdown":
        print(render_markdown(entries))
    else:
        version = feed.get("catalogVersion", "?")
        print(f"CISA KEV catalog {version} - {feed.get('count', '?')} total entries\n")
        print(render_table(entries))

    if args.webhook and entries:
        try:
            post_webhook(args.webhook, entries)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"Webhook failed: {exc}", file=sys.stderr)

    return 3 if (args.fail_on_match and entries) else 0


if __name__ == "__main__":
    sys.exit(main())
