# TLB documentation

Astro Starlight serves the public documentation at <https://niklasrosenstein.github.io/tlb/>.

Use Node 24.21.0 (also pinned in `.node-version`):

```bash
npm ci
npm run dev
npm run check
npm run build
npm run preview
```

Run these commands from `docs/`. Development and preview URLs include `/tlb/`.

- `src/content/docs/`: introduction, task guides, reference, and operations pages.
- `astro.config.mjs`: site URL, GitHub Pages base path, sidebar, and theme configuration.
- `src/styles/custom.css`: small visual adjustments to the Starlight theme.
- `scripts/check-links.mjs`: validates built local links and anchors, including `/tlb/` paths.
- `reviews/`: repository review records, outside the public content collection.

The docs workflow validates pull requests and publishes `main` using GitHub Actions deployments. GitHub Pages must use
**GitHub Actions** as its build source. The site includes Pagefind search, light/dark themes, mobile navigation, and
syntax-highlighted code examples.

Describe current behavior and verify field names/defaults against the Rust types, validation, and Helm templates. Task
guides should link to reference pages instead of duplicating complete field tables. Keep release and migration history
in pull requests and review records.
