"""Verify workshop preservation and generated navigation without executing lab code."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import unquote, urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'content/projects/deathcon2023'
BASE = '/projects/deathcon2023-practical-death-by-velociraptor/'
MANIFEST = json.loads((ROOT / 'docs/deathcon2023-import.json').read_text())


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links, self.images, self.ids, self.paging = [], [], set(), {}
        self.h1 = self.blocks = self.callouts = self.project_rows = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if tag == 'a' and 'href' in attrs:
            self.links.append(attrs['href'])
            if attrs.get('rel') in ('prev', 'next'):
                self.paging[attrs['rel']] = attrs['href']
        if tag == 'img':
            self.images.append(attrs)
        self.h1 += tag == 'h1'
        self.blocks += tag == 'pre'
        self.callouts += tag == 'blockquote'
        self.project_rows += tag == 'div' and attrs.get('class') == 'post-line'


@unittest.skipUnless(shutil.which('hugo'), 'Hugo is required')
class WorkshopMigration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        subprocess.run(['hugo', '--destination', str(cls.output), '--environment',
                        'development', '--cleanDestinationDir'], cwd=ROOT,
                       check=True, capture_output=True, text=True)

    def document(self, path):
        file = self.output / path.lstrip('/')
        if file.is_dir():
            file /= 'index.html'
        return Document(file.read_text())

    def test_source_code_and_images_match_export(self):
        for lesson in MANIFEST['lessons']:
            with self.subTest(lesson=lesson['slug']):
                folder = BUNDLE / lesson['slug']
                text = (folder / 'index.md').read_text()
                blocks = re.findall(r'(?m)^[ \t]*```[^\n]*\n(.*?)^[ \t]*```[ \t]*$', text, re.S)
                self.assertEqual([hashlib.sha256(b.encode()).hexdigest() for b in blocks],
                                 lesson['code_sha256'])
                self.assertNotIn('<aside>', text)
                for image in lesson['images']:
                    self.assertEqual(hashlib.sha256((folder / image['file']).read_bytes()).hexdigest(),
                                     image['sha256'])

    def test_rendered_content_navigation_assets_and_anchors(self):
        lessons = MANIFEST['lessons']
        routes = [BASE] + [BASE + x['slug'] + '/' for x in lessons]
        for route in routes:
            with self.subTest(route=route):
                doc = self.document(route)
                self.assertEqual(doc.h1, 1)
                for image in doc.images:
                    self.assertTrue(image.get('alt') or image['src'].endswith('brand-smiley.png'))
                    target = urlparse(urljoin('https://dfir.au' + route, image['src']))
                    self.assertEqual(target.netloc, 'dfir.au')
                    self.assertTrue((self.output / unquote(target.path).lstrip('/')).is_file())
                for href in doc.links:
                    target = urlparse(urljoin('https://dfir.au' + route, href))
                    if target.scheme not in ('http', 'https') or target.netloc != 'dfir.au':
                        continue
                    path = self.output / unquote(target.path).lstrip('/')
                    self.assertTrue(path.is_file() or (path / 'index.html').is_file(), href)
                    if target.fragment:
                        self.assertIn(unquote(target.fragment), self.document(target.path).ids, href)
        for i, lesson in enumerate(lessons):
            doc = self.document(BASE + lesson['slug'] + '/')
            self.assertEqual(doc.blocks, len(lesson['code_sha256']))
            self.assertEqual(doc.callouts, lesson['callouts'])
            self.assertEqual(len([im for im in doc.images if 'screenshot-' in im['src']]), len(lesson['images']))
            expected = {}
            if i:
                expected['prev'] = BASE + lessons[i-1]['slug'] + '/'
            if i + 1 < len(lessons):
                expected['next'] = BASE + lessons[i+1]['slug'] + '/'
            self.assertEqual(doc.paging, expected)

    def test_project_listing_videos_and_discovery(self):
        projects = self.document('/projects/')
        self.assertEqual(projects.project_rows, 9)
        self.assertIn(BASE, projects.links)
        for lesson in MANIFEST['lessons']:
            self.assertNotIn(BASE + lesson['slug'] + '/', projects.links)
        landing = self.document(BASE)
        self.assertEqual(len([u for u in landing.links if u.startswith('https://youtu.be/')]), 5)
        sitemap = (self.output / 'sitemap.xml').read_text()
        for lesson in MANIFEST['lessons']:
            self.assertIn('https://dfir.au' + BASE + lesson['slug'] + '/', sitemap)
        self.assertIn(BASE, (self.output / 'tags/dfir/index.html').read_text())


if __name__ == '__main__':
    unittest.main()
