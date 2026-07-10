# crawldex-report-py

[![CI](https://github.com/crawldex/crawldex-report-py/actions/workflows/ci.yml/badge.svg)](https://github.com/crawldex/crawldex-report-py/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

21% of measured CrawlDex site-task rows need a person nearby before completion (n=8,401, source: https://crawldex.com/board.json). Add fail-open CrawlDex preflight and redacted outcome reports to Python agents.

```bash
python -m pip install crawldex-report
```

## Privacy

crawldex-report sends a random anonymous instance ID with API calls so CrawlDex can count distinct agents. It contains no personal data, is stored server-side only as a salted hash, and is never linked to your identity or IP. Disable with `CRAWLDEX_NO_INSTANCE_ID=1` -- functionality is identical without it.

Set `CRAWLDEX_CHANNEL` to a registered distribution channel when you want CrawlDex to attribute adoption to a package, registry, or integration path.

```ts
// Before: the agent discovers blockers after it has already started.
await page.goto("https://example-airline.com/manage-trip");
await page.getByLabel("Confirmation number").fill(code);
await page.getByText("Continue").click();
// After: preflight catches the user-present boundary first.
const check = await crawldex.preflight("example-airline.com", "travel.manage_flight_reservation");
if (check.recommendation?.includes("handoff")) {
  return { status: "needs_user", reason: check.known_blockers };
}
await runWithUserPresent();
```

Links: [CrawlDex](https://crawldex.com), [contribution quickstart](https://crawldex.com/contribute), [bench leaderboard](https://crawldex.com/bench), [methodology](https://crawldex.com/methodology), [developer hub](https://crawldex.com/developers).

This mirror is generated from the canonical CrawlDex monorepo. Open issues and pull requests here; maintainers port accepted changes upstream.
