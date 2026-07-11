# Screenshots

Drop the images listed below into this folder using the **exact filenames**. The
README's `## Screenshots` section already references them — once the files exist,
uncomment the gallery block in the root `README.md` and it renders automatically.

## Shot list

| Filename | What to capture | Suggested size |
|---|---|---|
| `side-panel.png` | The assessment side panel on a real page, **Headers** or **Storage** subtab visible with a few findings | ~640×1000 (panel is tall/narrow) |
| `assessment-llm.png` | The **LLM/AI** subtab showing LLM findings (e.g. a direct provider call + a redacted prompt finding) | ~640×1000 |
| `html-report.png` | The exported self-contained HTML report open in a browser tab | ~1280×800 |
| `demo.gif` _(optional)_ | A short loop: open panel → scan → switch subtabs → export report | ≤ 5 MB, ~1200px wide |

## Capture tips

- Use a **demo/test page**, never a real user's authenticated session — the panel
  shows cookie/token/storage values (redacted, but still avoid real data).
- To exercise the **LLM/AI** tab, use a page that calls a provider API directly, or
  the DevTools-console snippet in the README's "What the LLM/AI review can — and
  cannot — see" section.
- Prefer the extension's **dark** theme for the panel shots (matches the UI); the
  HTML report renders in both light and dark — pick whichever reads best.
- Crop tightly (no OS chrome / bookmarks bar) and export as PNG. Keep each still
  under ~500 KB where possible.

## Ready-to-paste gallery (already in the root README, commented out)

```html
<p align="center">
  <img src="docs/screenshots/side-panel.png" alt="Assessment side panel" width="320">
  &nbsp;
  <img src="docs/screenshots/assessment-llm.png" alt="LLM/AI subtab" width="320">
</p>
<p align="center">
  <img src="docs/screenshots/html-report.png" alt="Exported self-contained HTML report" width="640">
</p>
```
