# Build and preview

```sh
hugo server --bind 127.0.0.1
sh scripts/build-site.sh                # Check links and build public/
sh scripts/build-site.sh --publish-root # Also refresh branch-root Pages output
```

The build clears stale files from the generated `public/` directory before
validating and copying output. It does not commit, push, or change GitHub Pages
settings.

## External articles and local backups

Posts with `originalUrl` retain their full article and local images on this site.
Listings normally open the original. Local copies remain available at their own
URLs and are used automatically when the saved routing decision selects a backup.
The checker follows HTTP redirects and verifies the article title or H1, so a
200 response from an unrelated landing page is not treated as healthy.

Posts with `reportUrl` are checked in the same workflow. PDF reports require a
`reportSha256` containing the SHA-256 of the reviewed document. The checker follows
redirects, downloads at most 16 MiB, checks the PDF header/end marker, and verifies
the digest. HTML landing pages, truncated files, oversized responses and changed
PDFs are inconclusive rather than healthy; review a changed report before updating
its digest. Each report is a leaf bundle with a `reportFile` naming the complete,
unchanged PDF stored alongside `index.md`. Confirmed outages route listings and
the overview's main report link to that archived PDF. Build validation requires
the archived file to match the reviewed digest. The illustrated overview retains
its own canonical URL and sitemap entry, and its local images are validated along
with the HTML article backups. The overview also provides an always-available
archive link.

```sh
python3 scripts/check_external_posts.py                   # Read-only live check
python3 scripts/check_external_posts.py --write           # Save routing decisions
python3 scripts/check_external_posts.py --site-dir public # Check built backups
python3 -m unittest discover -s tests -v                  # Offline regression tests
```

Three consecutive missing-page (404/410), server (5xx), network, or timeout
failures in a check select the local copy. A verified successful response restores
the original link. Bot blocks, rate limits, certificate-verification errors and
unrecognised pages are inconclusive and retain the previous routing decision.
The checker reports these as `unknown`; they need manual review. This includes
soft 404s without a recognisable missing-page heading. It does not prove that
all original article text or images remain intact.

Decisions and timestamps are stored in `data/original_links.json` and applied by
Hugo at build time. A read-only live check exits nonzero for unavailable or
inconclusive results. `--write` saves those results without failing the build,
allowing the fallback to be published. Missing/incomplete local articles,
redirecting backups, and missing or remote backup images fail backup validation.

Both the local build script and the Actions build run the check. The current
GitHub Pages configuration publishes committed branch-root files from `master`;
use `--publish-root`, then review, commit and push to publish new decisions.
The Actions deployment requires Pages to be configured for GitHub Actions.
The Pages workflow runs an **Original articles must be reachable** job alongside
the build, on pushes to `master` and manual workflow runs. It uses the read-only
checker and fails for unavailable or inconclusive results, with URL details in
the run summary. Deployment depends only on the build job, so a link-check
failure does not prevent the build's local fallback from being published.
There is no scheduled monitor or per-click check.

Enable GitHub Actions email/web notifications, optionally **Send notifications
for failed workflows only**, in your GitHub notification settings. Delivery is
controlled by GitHub and your account preferences; the workflow itself does not
send email.

### Article metadata

Give each post one main area with `areas: ["DFIR"]` (or Threat Intel, Threat Hunting, Detection Engineering, Malware Analysis, AI & Automation). Hugo generates `/areas/` archives; the main-area label links to its archive. Use `tags` for overlapping topics and tools, and a short `summary` for listings. Keep historical limitations in summaries where examples have been superseded.

### Sharing previews and agent discovery

`layouts/partials/social-meta.html` emits Open Graph and X card metadata using each page's title and SEO description, the existing canonical routing logic, and `static/social-preview.png`. The homepage uses the full site title. The 1200 × 630 PNG reuses the existing smile icon and can be regenerated on macOS with `swift scripts/render-social-card.swift`; Hugo builds use the committed PNG without needing Swift.

`static/llms.txt` is a curated site guide, linked from the page head. Keep its links and descriptions current when featured resources change. It does not change crawler access or guarantee indexing. After deploying, verify the domain in Search Console if needed and submit `https://dfir.au/sitemap.xml`; no account verification token is included here.
