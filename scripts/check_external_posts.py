#!/usr/bin/env python3
"""Check original articles and validate their rendered local backups (stdlib only)."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPException
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / 'data/original_links.json'


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.heading = None
        self.headings = []
        self.images = []
        self.text = []
        self.redirect = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('title', 'h1'):
            self.heading = []
        if tag == 'img':
            self.images.append(attrs.get('src', ''))
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'refresh':
            self.redirect = True

    def handle_endtag(self, tag):
        if tag in ('title', 'h1') and self.heading is not None:
            self.headings.append(' '.join(self.heading))
            self.heading = None

    def handle_data(self, text):
        self.text.append(text)
        if self.heading is not None:
            self.heading.append(text)


def articles(root=ROOT):
    result = []
    for path in sorted((root / 'content/posts').rglob('*.md')):
        text = path.read_text()
        if not text.startswith('---\n'):
            continue
        front = text.split('---', 2)[1]
        fields = dict(re.findall(r'^(title|originalUrl):\s*(.*?)\s*$', front, re.M))
        if 'originalUrl' not in fields:
            continue
        fields = {key: value.strip('\"\'') for key, value in fields.items()}
        if not fields.get('title') or urlsplit(fields['originalUrl']).scheme != 'https':
            raise ValueError(f'Invalid originalUrl/title in {path}')
        result.append(dict(title=fields['title'], url=fields['originalUrl'],
                           path=path.relative_to(root / 'content').with_suffix('').as_posix()))
    if not result:
        raise ValueError('No originalUrl posts found')
    return result


def same_article(expected, headings):
    words = set(re.findall(r'\w+', expected.casefold()))
    return any(len(words & set(re.findall(r'\w+', heading.casefold()))) >= max(1, len(words) * .65)
               for heading in headings)


def probe(article):
    request = Request(article['url'], headers={'User-Agent': 'Mozilla/5.0 (compatible; dfir.au article-link-check)'})
    try:
        with urlopen(request, timeout=10) as response:
            html = response.read(2 * 1024 * 1024).decode('utf-8', errors='replace')
            page = Page(html)
            detail = f'HTTP {response.status}: {response.url}'
            if response.status == 200 and same_article(article['title'], page.headings):
                return 'available', detail
            if any(re.search(r'\b(404|410|page not found|page removed)\b', h, re.I) for h in page.headings):
                return 'unavailable', detail + ' (missing-page heading)'
            return 'unknown', detail + ' (article identity not verified)'
    except HTTPError as exc:
        status = 'unavailable' if exc.code in (404, 410) or 500 <= exc.code < 600 else 'unknown'
        exc.close()
        return status, f'HTTP {exc.code}'
    except (URLError, OSError, HTTPException) as exc:
        # Certificate failures can reflect this checker rather than the website.
        status = 'unknown' if 'CERTIFICATE_VERIFY_FAILED' in str(exc) else 'unavailable'
        return status, str(exc)


def check(article, previous, attempts=3, delay=1, fetch=probe):
    observations = []
    for attempt in range(attempts):
        status, detail = fetch(article)
        observations.append(status)
        if status in ('available', 'unknown'):
            break
        if attempt + 1 < attempts:
            time.sleep(delay)
    confirmed = len(observations) == attempts and all(s == 'unavailable' for s in observations)
    status = 'unavailable' if confirmed else status if status != 'unavailable' else 'unknown'
    use_backup = status == 'unavailable' or (status == 'unknown' and previous.get('use_backup', False))
    return dict(status=status, use_backup=use_backup, detail=detail, attempts=len(observations))


def validate_backups(items, site):
    for article in items:
        path = site / article['path'] / 'index.html'
        html = path.read_text()
        page = Page(html)
        if page.redirect or re.search(r'window\.location\s*=', html):
            raise ValueError(f'Backup still redirects: {path}')
        if not same_article(article['title'], page.headings) or len(' '.join(page.text).split()) < 300:
            raise ValueError(f'Backup article missing or incomplete: {path}')
        for image in page.images:
            url = urlsplit(image)
            if url.scheme or url.netloc:
                raise ValueError(f'Backup depends on remote image: {path}: {image}')
            local = site / unquote(url.path).lstrip('/') if url.path.startswith('/') else path.parent / unquote(url.path)
            if not local.is_file():
                raise ValueError(f'Missing backup image: {local}')
        print(f'BACKUP OK {article["path"]}: {len(page.images)} local images')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Save routing decisions for the next Hugo build')
    parser.add_argument('--site-dir', type=Path, help='Validate built backups only; no network or state changes')
    args = parser.parse_args()
    items = articles()
    if args.site_dir:
        validate_backups(items, args.site_dir)
        return 0
    previous = json.loads(STATE.read_text()) if STATE.exists() else {}
    def run(article):
        return article['url'], check(article, previous.get(article['url'], {}))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(run, items))
    for article in items:
        result = results[article['url']]
        result['checked_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        route = 'local backup' if result['use_backup'] else 'original'
        print(f'{result["status"].upper():11} {article["title"]}: {result["detail"]}; route={route}')
    if args.write:
        STATE.parent.mkdir(exist_ok=True)
        temporary = STATE.with_suffix('.tmp')
        temporary.write_text(json.dumps(results, indent=2) + '\n')
        temporary.replace(STATE)
        return 0
    return 0 if all(r['status'] == 'available' for r in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
