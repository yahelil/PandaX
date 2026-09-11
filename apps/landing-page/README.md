# PandaX marketing site

Static files, served by Cloudflare Workers static assets (`wrangler.jsonc`).
No framework, no bundler, no dependencies.

## Editing copy

All copy lives in [`content/en.mjs`](content/en.mjs). Edit there, then:

```bash
node build.mjs
```

**Do not edit the generated `.html` files by hand** — `build.mjs` overwrites
them. Generated pages are committed so the site deploys without a build step.

A German translation would be `content/de.mjs` with the same shape.

## Pages

| Path | Source |
|---|---|
| `/` | `index.html` |
| `/partners/` | `partners/index.html` |
| `/impressum/` | `impressum/index.html` — § 5 TMG, has TODOs |
| `/datenschutz/` | `datenschutz/index.html` — has TODOs |
| `/privacy/` | `privacy/index.html` — English, has TODOs |

## Forms

No third-party embed. Set `PANDAX_FORM_ENDPOINT` before building to post
somewhere; with no endpoint the form falls back to `mailto:`. There is a
honeypot field and no reCAPTCHA.

## Assets

Fonts are self-hosted in `assets/fonts/` — the site makes no external
requests, which is what keeps it outside cookie-consent territory. There is no
analytics.
