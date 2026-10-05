import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from io import BytesIO

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('links', ROOT / 'scripts/check_external_posts.py')
links = importlib.util.module_from_spec(spec)
spec.loader.exec_module(links)
ARTICLE = dict(title='AI Ate My Velociraptor', url='https://example.test/article/', path='posts/test')
PDF_BYTES = b'%PDF-1.4\nreviewed report\n%%EOF\n'
REPORT = dict(title='Kimsuky report', url='https://example.test/report.pdf',
              path='posts/report', kind='pdf', sha256=hashlib.sha256(PDF_BYTES).hexdigest())


class SEOHead(links.HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.description = None
        self.canonical = None
        self.schema_text = ''
        self.in_schema = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'meta' and attrs.get('name') == 'description':
            self.description = attrs.get('content')
        if tag == 'link' and attrs.get('rel') == 'canonical':
            self.canonical = attrs['href']
        if tag == 'script' and attrs.get('type') == 'application/ld+json':
            self.in_schema = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_schema = False

    def handle_data(self, text):
        if self.in_schema:
            self.schema_text += text


class Response(BytesIO):
    status = 200
    url = 'https://example.test/new-article/'


class LinkChecks(unittest.TestCase):
    def test_pdf_identity_and_invalid_responses(self):
        for body, expected in [(PDF_BYTES, 'available'),
                               (b'<html>Download report</html>', 'unknown'),
                               (PDF_BYTES.replace(b'reviewed', b'different'), 'unknown'),
                               (PDF_BYTES[:-7], 'unknown')]:
            with self.subTest(body=body), patch.object(links, 'urlopen', return_value=Response(body)):
                status, detail = links.probe(REPORT)
                self.assertEqual(status, expected)
                self.assertIn('new-article', detail)

    def test_pdf_download_size_is_bounded(self):
        response = Response(PDF_BYTES + b' ' * 50)
        with patch.object(links, 'MAX_PDF_BYTES', 32), patch.object(links, 'urlopen', return_value=response):
            self.assertEqual(links.probe(REPORT)[0], 'unknown')

    def test_pdf_outage_recovery_and_changed_document_preserve_routing(self):
        with patch.object(links, 'urlopen', side_effect=HTTPError(REPORT['url'], 404, '', {}, None)) as fetch:
            failed = links.check(REPORT, {}, delay=0)
            self.assertTrue(failed['use_backup'])
            self.assertEqual(fetch.call_count, 3)
        with patch.object(links, 'urlopen', return_value=Response(PDF_BYTES.replace(b'reviewed', b'new'))):
            self.assertTrue(links.check(REPORT, failed)['use_backup'])
        with patch.object(links, 'urlopen', return_value=Response(PDF_BYTES)):
            self.assertFalse(links.check(REPORT, failed)['use_backup'])

    def test_report_discovery_handles_leaf_bundle_and_requires_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / 'content/posts/report/index.md'
            page.parent.mkdir(parents=True)
            front = f'---\ntitle: Kimsuky report\nreportUrl: {REPORT["url"]}\n'
            page.write_text(front + '---\nOverview')
            with self.assertRaises(ValueError):
                links.articles(root)
            page.write_text(front + f'reportSha256: {REPORT["sha256"]}\n---\nOverview')
            self.assertEqual(links.articles(root), [REPORT])

    def test_verified_article_and_redirect_destination(self):
        with patch.object(links, 'urlopen', return_value=Response(b'<title>AI Ate My Velociraptor - Labs</title>')):
            status, detail = links.probe(ARTICLE)
        self.assertEqual(status, 'available')
        self.assertIn('new-article', detail)

    def test_h1_accepts_article_when_title_differs(self):
        self.assertTrue(links.same_article(ARTICLE['title'], ['Labs', ARTICLE['title']]))

    def test_http_failure_classification(self):
        for code, expected in [(404, 'unavailable'), (410, 'unavailable'), (503, 'unavailable'),
                               (403, 'unknown'), (429, 'unknown')]:
            with self.subTest(code=code), patch.object(links, 'urlopen', side_effect=HTTPError(ARTICLE['url'], code, '', {}, None)):
                self.assertEqual(links.probe(ARTICLE)[0], expected)

    def test_homepage_and_soft_404_are_not_healthy(self):
        for title, expected in [('Welcome to Labs', 'unknown'), ('404 Page not found', 'unavailable')]:
            with self.subTest(title=title), patch.object(links, 'urlopen', return_value=Response(f'<title>{title}</title>'.encode())):
                self.assertEqual(links.probe(ARTICLE)[0], expected)

    def test_network_failure_and_certificate_ambiguity(self):
        for error, expected in [(TimeoutError('timeout'), 'unavailable'), (URLError('DNS failure'), 'unavailable'),
                                (links.HTTPException('truncated response'), 'unavailable'),
                                (URLError('CERTIFICATE_VERIFY_FAILED'), 'unknown')]:
            with self.subTest(error=error), patch.object(links, 'urlopen', side_effect=error):
                self.assertEqual(links.probe(ARTICLE)[0], expected)

    def test_read_only_cli_fails_for_unavailable_or_unknown_without_writing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            state.write_text('{}\n')
            for status, expected in [('available', 0), ('unavailable', 1), ('unknown', 1)]:
                result = dict(status=status, use_backup=status == 'unavailable', detail='test', attempts=3)
                with self.subTest(status=status), patch.object(links, 'STATE', state), \
                     patch.object(links, 'articles', return_value=[ARTICLE]), \
                     patch.object(links, 'check', return_value=result), \
                     patch('sys.argv', ['check_external_posts.py']), patch('builtins.print'):
                    self.assertEqual(links.main(), expected)
                    self.assertEqual(state.read_text(), '{}\n')

    def test_three_failures_select_backup(self):
        result = links.check(ARTICLE, {}, delay=0, fetch=lambda _: ('unavailable', 'HTTP 404'))
        self.assertTrue(result['use_backup'])
        self.assertEqual(result['attempts'], 3)

    def test_transient_failure_does_not_select_backup(self):
        responses = iter([('unavailable', '503'), ('available', '200')])
        result = links.check(ARTICLE, {}, delay=0, fetch=lambda _: next(responses))
        self.assertFalse(result['use_backup'])

    def test_unknown_preserves_last_routing_decision(self):
        for previous in [True, False]:
            responses = iter([('unavailable', '503'), ('unknown', '403')])
            result = links.check(ARTICLE, {'use_backup': previous}, delay=0, fetch=lambda _: next(responses))
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['use_backup'], previous)

    def test_recovered_original_restores_external_link(self):
        result = links.check(ARTICLE, {'use_backup': True}, fetch=lambda _: ('available', '200'))
        self.assertFalse(result['use_backup'])

    def test_backup_rejects_missing_remote_images_and_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            page = site / ARTICLE['path'] / 'index.html'
            page.parent.mkdir(parents=True)
            body = '<h1>AI Ate My Velociraptor</h1>' + 'article ' * 350
            for extra in ['<img src="/missing.png">', '<img src="https://example.test/image.png">',
                          '<meta http-equiv="refresh" content="0;url=https://example.test">',
                          '<script>window.location = "https://example.test"</script>']:
                with self.subTest(extra=extra):
                    page.write_text(body + extra)
                    with self.assertRaises(ValueError):
                        links.validate_backups([ARTICLE], site)
            page.write_text('<h1>AI Ate My Velociraptor</h1>Redirecting')
            with self.assertRaises(ValueError):
                links.validate_backups([ARTICLE], site)


@unittest.skipUnless(shutil.which('hugo'), 'Hugo required for routing integration')
class HugoRouting(unittest.TestCase):
    def test_healthy_and_failed_originals_render_correct_routes_and_backups(self):
        items = links.articles()
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            data = temp / 'data'
            data.mkdir()
            config = temp / 'config.json'
            config.write_text(json.dumps({'dataDir': str(data)}))
            for use_backup in [False, True]:
                (data / 'original_links.json').write_text(json.dumps({item['url']: {'use_backup': use_backup} for item in items}))
                output = temp / str(use_backup)
                subprocess.run(['hugo', '--minify', '--config', f'hugo.toml,{config}', '--destination', str(output)],
                               cwd=ROOT, check=True, capture_output=True, text=True)
                for listing in ['index.html', 'posts/index.html', 'tags/dfir/index.html']:
                    html = (output / listing).read_text()
                    title_links = '\n'.join(links.re.findall(r'<p class=["\']?line-title["\']?>.*?</p>', html, links.re.S))
                    for item in items:
                        if listing != 'posts/index.html' and not any(
                                candidate in title_links for candidate in [item['url'], '/' + item['path'] + '/']):
                            continue
                        # Minified Hugo output can omit quotes around href values.
                        expected = '/' + item['path'] + '/' if use_backup else item['url']
                        self.assertRegex(title_links, 'href=["\']?' + links.re.escape(expected))
                        if not use_backup:
                            self.assertNotIn('/' + item['path'] + '/', title_links)
                        if use_backup:
                            self.assertNotIn(item['url'], title_links)
                sitemap = {node.text for node in ET.parse(output / 'sitemap.xml').iter()
                           if node.tag.endswith('}loc')}
                self.assertFalse(any('g-g41g20slqn' in url for url in sitemap))
                self.assertFalse((output / 'g-g41g20slqn/index.html').exists())
                self.assertIn('Sitemap: https://dfir.au/sitemap.xml', (output / 'robots.txt').read_text())
                for item in items:
                    local = 'https://dfir.au/' + item['path'] + '/'
                    page = SEOHead((output / item['path'] / 'index.html').read_text())
                    self.assertTrue(page.description)
                    local_canonical = use_backup or item.get('kind') == 'pdf'
                    self.assertEqual(page.canonical, local if local_canonical else item['url'])
                    self.assertEqual(local in sitemap, local_canonical)
                    schema = json.loads(page.schema_text)
                    self.assertEqual(schema['@type'], 'BlogPosting')
                    self.assertEqual(schema['mainEntityOfPage'], page.canonical)
                    self.assertEqual(schema['author']['name'], 'Matthew Green')
                    self.assertIn('datePublished', schema)
                for path in ['index.html', 'about/index.html', 'posts/index.html',
                             'projects/index.html', 'projects/velociraptor-skills/index.html']:
                    self.assertTrue(SEOHead((output / path).read_text()).description, path)
                links.validate_backups(items, output)


if __name__ == '__main__':
    unittest.main()
