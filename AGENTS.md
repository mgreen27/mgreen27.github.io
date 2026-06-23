# Repository Guide

This repository is the source for `https://dfir.au/`. It is a Hugo site
deployed to GitHub Pages by GitHub Actions.

## Layout

- `hugo.toml` is the main Hugo configuration.
- `content/` contains posts, project pages, and the about page.
- `layouts/` contains local Hugo layout overrides and shortcodes.
- `themes/typo/` contains the current Hugo theme.
- `static/` contains source-controlled files that should remain browseable in
  GitHub, including downloadable artifacts such as `static/DownloadCradle`.
- `static/CNAME` preserves the custom domain in the generated Pages artifact.
- `.github/workflows/pages.yml` builds Hugo and deploys the generated `public/`
  directory to GitHub Pages.

The old standalone source repo at `~/git/mgreen27dev` is now a backup. New
edits should happen in this repository.

## Local Workflow

Preview locally:

```sh
hugo server --bind 127.0.0.1
```

Build locally:

```sh
hugo --gc --minify
mkdir -p public/static
rsync -a static/ public/static/
```

The `rsync` step preserves legacy published paths under `/static/...` while
keeping the source files in `static/...` for GitHub browsing links.

## Publishing Workflow

Commit source changes to `master` and push. GitHub Actions builds and deploys
the site from `public/`.

The repository should have GitHub Pages configured to use **GitHub Actions** as
the build and deployment source.

## Important Rules

- Edit Markdown in `content/`, not generated HTML.
- Edit templates in `layouts/` or `themes/typo/`.
- Keep `public/`, `resources/`, and `.hugo_build.lock` untracked.
- Do not commit generated HTML, generated feeds, generated tag pages, or
  generated assets from `public/`.
- Keep `static/CNAME` as `dfir.au`.
- Be careful with old links that point to GitHub folders such as
  `static/DownloadCradle`; those rely on the source files remaining under
  `static/`.
