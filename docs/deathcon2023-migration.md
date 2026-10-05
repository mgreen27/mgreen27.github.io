# DEATHcon 2023 workshop migration

The workshop is a Hugo branch bundle at `content/projects/deathcon2023/`.
Its landing page retains `/projects/deathcon2023-practical-death-by-velociraptor/`.
Six leaf bundles hold the individual lessons and their local screenshots.
The Projects listing retains one workshop entry and now links to the local material.

## Source and preservation

Imported from the user-supplied Notion Markdown export on 5 October 2026.
`deathcon2023-import.json` records the export checksum, original lesson names,
source Markdown checksums, all 124 screenshot checksums and the 34 fenced-code
block checksums. The original ZIP remains in the user's Downloads folder.

- All six lab bodies were retained; commands and code blocks were not modernised or executed.
- Trailing whitespace was normalised outside fenced code; Markdown hard breaks were retained.
- The exported title was moved into front matter. Other top-level headings were
  changed to level two so each rendered page has one main heading.
- Relative Notion links were rewritten to local lesson routes.
- Screenshot filenames were normalised per lesson; placeholder "Untitled" alt
  text was replaced with the lesson and nearest section name.
- Seventeen Notion HTML callouts were converted to Markdown blockquotes so Hugo
  renders their content without enabling unsafe HTML.
- The spurious `http://Windows.System.Services` link was replaced by the literal
  artifact identifier. No executable example was changed.
- Five video URLs, reference links and links embedded in code were retained.
  External scripts, samples and videos remain on their original hosts; their
  availability and current behaviour have not been validated by this migration.
- The existing skull artwork and November 2023 project date were retained.

## Layout

`layouts/projects/workshop.html` renders the landing page; `workshop-lesson.html`
renders each lab with an archive notice, expandable contents and previous/next
navigation. The landing-page cards come from `workshop-lessons.html`, ordered by
lesson weight. `assets/css/workshop.css` provides scoped responsive styling.

Task groups now render as native, initially collapsed disclosures, using the
archived level-three headings. References stay outside the disclosures. This
reconstructs the expandable grouping from the Markdown export and the author's
description; the original Notion UI could not be checked because browser access
was blocked by its administrator-policy verification.

The `workshop-task` shortcode retains heading IDs; `workshop-toc.html` builds
the contents menu from the rendered headings, including the nested LNK solution.
Nested shortcode output is kept separate from Markdown rendering so its HTML
is preserved without enabling unsafe raw HTML. The optional
`assets/js/workshop.js` adds expand/collapse-all controls and opens a task when
following a contents link or loading a fragment URL. Individual disclosures work
without JavaScript. Step numbers now continue across screenshot/code interruptions
within a task group and restart in the next group; fenced code remains unchanged.

Presentation refinements add explicit task numbers, five nested Process topics,
a compact expandable archive notice, and full-size screenshot links that open a
new tab. Notion-specific swipe/back instructions were removed. Some Process
blocks use the shortcode's `dedent` option to normalise their inherited list
indentation only during rendering; the original code bytes remain preserved.

## Validation

Run `python3 -m unittest discover -s tests -v` and a clean Hugo build.
The workshop tests check code and image preservation, local links and fragment
IDs, rendered callout/code/image counts, the lesson sequence, the project listing,
video links and sitemap discovery. They do not run lab code or validate malware
behaviour. Browser visual review remains required: browser access was blocked
by the tool's security-policy verification during this migration.

Future corrections should be labelled separately from the 2023 archive. If
intentionally changing an archived code block or screenshot, review the change
against the export before updating the preservation manifest.
