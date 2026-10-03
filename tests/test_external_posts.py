import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from io import BytesIO

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('links', ROOT / 'scripts/check_external_posts.py')
links = importlib.util.module_from_spec(spec)
spec.loader.exec_module(links)
ARTICLE = dict(title='AI Ate My Velociraptor', url='https://example.test/article/', path='posts/test')


class Response(BytesIO):
    status = 200
    url = 'https://example.test/new-article/'


class LinkChecks(unittest.TestCase):
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
                    for item in items:
                        # Minified Hugo output can omit quotes around href values.
                        expected = '/' + item['path'] + '/' if use_backup else item['url']
                        self.assertRegex(html, 'href=["\']?' + links.re.escape(expected))
                        self.assertIn('/' + item['path'] + '/', html)
                        if use_backup:
                            self.assertNotIn(item['url'], html)
                if use_backup:
                    self.assertIn('Original currently unavailable', (output / 'index.html').read_text())
                links.validate_backups(items, output)


if __name__ == '__main__':
    unittest.main()
