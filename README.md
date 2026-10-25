# KEV Watcher

Know when a vulnerability in **your** stack is being exploited in the wild.

KEV Watcher checks the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and reports only the entries that match the vendors and products you care about. It can remember what it has already shown you, flag ransomware-linked entries, show remediation due dates, and push alerts to Slack, Discord or Mattermost.

- Single file, **Python standard library only** (3.9+). No API keys, no installs.
- Read-only: it downloads a public JSON feed and nothing else.
- Falls back to CISA's official GitHub mirror if cisa.gov is unreachable.

## Why

Most CVEs are never exploited. The KEV catalog lists the ones that are. If something you run shows up there, it should jump to the top of your patch queue. CISA's own Binding Operational Directives use KEV as a core input for federal remediation deadlines.

## Quick start

```bash
git clone https://github.com/Zasnit1/kev-watcher.git
cd kev-watcher
python3 kev_watcher.py --watch plex,microsoft,"traffic server" --since 30
```

```
CISA KEV catalog 2026.10.23 - 1756 total entries

CVE             ADDED       DUE          RANSOMWARE  VENDOR / PRODUCT
--------------  ----------  -----------  ----------  ----------------
CVE-2026-96656  2026-10-20  overdue 2d   -           Plex / Media Server
CVE-2026-96655  2026-10-20  in 9d        -           Plex / Media Server
CVE-2026-96654  2026-10-20  overdue 2d   -           Plex / Media Server
CVE-2026-96652  2026-10-20  in 9d        -           Plex / Media Server
CVE-2026-96951  2026-10-13  overdue 9d   -           Microsoft / Windows
CVE-2026-65660  2026-09-25  overdue 27d  -           Microsoft / SharePoint
```

*(Real output from 25 October 2026. "Due" is CISA's federal remediation deadline, a useful urgency signal for everyone.)*

## Usage

| Option | What it does |
|---|---|
| `--watch a,b,c` | Comma-separated vendor/product keywords (case-insensitive, whole-word) |
| `--watchlist FILE` | One keyword per line, `#` comments allowed (see `watchlist.example.txt`) |
| `--since DAYS` | Only entries added in the last N days |
| `--ransomware` | Only entries with known ransomware campaign use |
| `--new-only` | Only entries you have not seen before (state kept in `~/.kev_watcher_state.json`) |
| `--format table\|markdown\|json` | Output format |
| `--webhook URL` | Post new matches to a Slack/Discord/Mattermost incoming webhook (or set `KEV_WEBHOOK_URL`) |
| `--fail-on-match` | Exit code `3` when anything matches, handy in CI |
| `--feed PATH_OR_URL` | Use a local copy or alternative URL of the KEV JSON |

### Daily alert with cron

```bash
# every morning at 08:00, alert only on new matches
0 8 * * * KEV_WEBHOOK_URL=https://hooks.slack.com/services/XXX python3 /opt/kev-watcher/kev_watcher.py --watchlist /opt/kev-watcher/stack.txt --new-only
```

### GitHub Actions

```yaml
name: kev-watch
on:
  schedule: [{ cron: "0 6 * * *" }]
  workflow_dispatch:
jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python3 kev_watcher.py --watchlist watchlist.example.txt --since 2 --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## Matching rules

Keywords are matched as whole words against the vendor, product and vulnerability name, so `apache` matches *Apache HTTP Server* but `apach` does not, and `win` does not match *Windows*. Use the exact product wording CISA uses (for example `traffic server`, `exchange server`) for tighter results.

## Tests

```bash
python3 -m pytest -q
```

## Data source and credit

All vulnerability data comes from the **CISA Known Exploited Vulnerabilities Catalog**, published by the U.S. Cybersecurity and Infrastructure Security Agency. This project is independent and not affiliated with or endorsed by CISA.

## License

MIT, see [LICENSE](LICENSE).

Built by Ibrahim Maqtoush with AI assistance. Issues and pull requests are welcome.
