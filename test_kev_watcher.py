import json
from datetime import date

import kev_watcher as kw

FEED = {
    "catalogVersion": "2026.10.24",
    "count": 4,
    "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Apache", "product": "Traffic Server", "vulnerabilityName": "Apache Traffic Server Request Smuggling",
         "dateAdded": "2026-10-20", "dueDate": "2026-10-23", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "x", "requiredAction": "patch", "cwes": ["CWE-444"]},
        {"cveID": "CVE-2026-0002", "vendorProject": "Plex", "product": "Media Server", "vulnerabilityName": "Plex SSRF",
         "dateAdded": "2026-10-22", "dueDate": "2026-11-12", "knownRansomwareCampaignUse": "Known", "shortDescription": "y", "requiredAction": "patch"},
        {"cveID": "CVE-2025-9999", "vendorProject": "Microsoft", "product": "Windows", "vulnerabilityName": "Windows Shell Bypass",
         "dateAdded": "2025-01-01", "dueDate": "2025-01-22", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "z", "requiredAction": "patch"},
        {"cveID": "not-a-cve", "vendorProject": "Bad", "product": "Row"},
    ],
}
TODAY = date(2026, 10, 25)


def entries():
    return kw.parse_entries(FEED)


def test_parse_skips_invalid_rows():
    assert [e.cve for e in entries()] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-9999"]


def test_whole_word_matching():
    e = entries()
    assert kw.matches(e[0], ["apache"])
    assert kw.matches(e[0], ["traffic server"])
    assert not kw.matches(e[0], ["apach"])  # no partial-word false positives
    assert not kw.matches(e[2], ["win"])


def test_since_and_ransomware_filters():
    recent = kw.apply_filters(entries(), since_days=7, today=TODAY)
    assert [e.cve for e in recent] == ["CVE-2026-0002", "CVE-2026-0001"]
    rw = kw.apply_filters(entries(), ransomware_only=True, today=TODAY)
    assert [e.cve for e in rw] == ["CVE-2026-0002"]


def test_due_status():
    e = entries()
    assert kw.due_status(e[0], TODAY) == "overdue 2d"
    assert kw.due_status(e[1], TODAY) == "in 18d"


def test_renderers():
    e = entries()
    assert "CVE-2026-0001" in kw.render_table(e, TODAY)
    md = kw.render_markdown(e, TODAY)
    assert "[CVE-2026-0002](https://nvd.nist.gov/vuln/detail/CVE-2026-0002)" in md
    data = json.loads(kw.render_json(e))
    assert data[0]["cwes"] == ["CWE-444"]
    assert kw.render_table([], TODAY) == "No matching KEV entries."


def test_new_only_state(tmp_path):
    feed_file = tmp_path / "feed.json"
    feed_file.write_text(json.dumps(FEED))
    state = tmp_path / "state.json"
    args = ["--feed", str(feed_file), "--state", str(state), "--new-only", "--format", "json", "--fail-on-match"]
    assert kw.main(args) == 3          # first run: everything is new
    assert kw.main(args) == 0          # second run: nothing new
    assert len(json.loads(state.read_text())["seen"]) == 3


def test_watchlist_file(tmp_path):
    wl = tmp_path / "stack.txt"
    wl.write_text("# my stack\nplex\n\nmicrosoft  # desktops\n")
    assert kw.read_watchlist(str(wl)) == ["plex", "microsoft"]
