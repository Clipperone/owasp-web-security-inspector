// Registers the DevTools panel.
// This script runs inside devtools.html — the devtools_page context.
chrome.devtools.panels.create(
  'Headers',
  '',
  'src/devtools/panel.html',
);
