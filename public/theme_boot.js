/* Agent Capsule Jail — theme + embed bootstrap (runs before first paint).
 * Order: ?theme=light|dark (persisted to localStorage "acj-theme") > stored choice > prefers-color-scheme.
 * ?embed=1 marks the document for iframe embedding (Zoth Studio). */
(function () {
  var root = document.documentElement;
  var KEY = 'acj-theme';
  var params;
  try { params = new URLSearchParams(window.location.search); } catch (e) { params = { get: function () { return null; } }; }
  var fromParam = params.get('theme');
  var stored = null;
  try { stored = window.localStorage.getItem(KEY); } catch (e) { stored = null; }
  var theme;
  if (fromParam === 'light' || fromParam === 'dark') {
    theme = fromParam;
    try { window.localStorage.setItem(KEY, fromParam); } catch (e) { /* storage blocked */ }
  } else if (stored === 'light' || stored === 'dark') {
    theme = stored;
  } else {
    theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  root.setAttribute('data-theme', theme);
  if (params.get('embed') === '1') root.setAttribute('data-embed', '1');
  window.__ACJ_THEME__ = { key: KEY, explicit: theme === fromParam || theme === stored };
})();
