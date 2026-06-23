# Repository Guide

This repository is the source for `https://dfir.au/`. It is a Hugo site. The
source lives in Hugo directories, and generated files are currently committed at
the repository root so GitHub Pages can publish the existing `master` branch
source while the Pages settings are still using branch publishing.

## Layout

- `hugo.toml` is the main Hugo configuration.
- `content/` contains posts, project pages, and the about page.
- `layouts/` contains local Hugo layout overrides and shortcodes.
- `themes/typo/` contains the current Hugo theme.
- `static/` contains source-controlled files that should remain browseable in
  GitHub, including downloadable artifacts such as `static/DownloadCradle`.
- `static/CNAME` preserves the custom domain in the generated Pages artifact.
- Top-level generated files such as `index.html`, `posts/`, `projects/`,
  `tags/`, `assets/`, feeds, and sitemaps are the published branch-root output.
- `.github/workflows/pages.yml` can build Hugo and deploy the generated
  `public/` directory once GitHub Pages is configured to use GitHub Actions.

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
rsync -a public/ ./
```

The `rsync` step preserves legacy published paths under `/static/...` while
keeping the source files in `static/...` for GitHub browsing links.

## Publishing Workflow

Commit source changes and regenerated branch-root output to `master`, then push.
This keeps the site live with branch-root GitHub Pages publishing.

The repository should have GitHub Pages configured to use **GitHub Actions** as
the build and deployment source when you are ready to stop committing generated
root output. After that switch, generated root output can be removed and only
source changes need to be committed.

## Important Rules

- Edit Markdown in `content/`, not generated HTML.
- Edit templates in `layouts/` or `themes/typo/`.
- Keep `public/`, `resources/`, and `.hugo_build.lock` untracked.
- Generated root output is committed for the current branch-root publishing
  setup. Do not edit generated HTML directly; edit Hugo source and rebuild.
- Keep `static/CNAME` as `dfir.au`.
- Be careful with old links that point to GitHub folders such as
  `static/DownloadCradle`; those rely on the source files remaining under
  `static/`.
