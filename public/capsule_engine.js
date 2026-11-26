/**
 * Agent Capsule Jail v2.6.0 — web cockpit controller.
 * Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
 *
 * Live mode: talks to the local daemon (/api/health, /api/stats, /api/capsules, POST /api/exec).
 * Errors (400/401/403/413/500/network) are shown as errors — never as a successful run.
 * Offline demo mode is used ONLY when /api/health is unreachable or not JSON (static hosting);
 * every simulated result is labelled "DEMO (not executed)".
 */
(function () {
  'use strict';

  var TOKEN_KEY = 'acj-token';
  var THEME_KEY = 'acj-theme';
  var SOLANA = 'GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK';

  var PRESETS = {
    file_writer: {
      label: 'File write + diff',
      mode: 'cmd',
      text: 'python3 -c "import os, json; os.makedirs(\'output\', exist_ok=True); open(\'output/report.txt\', \'w\').write(\'written inside the capsule\\n\'); json.dump({\'ok\': True}, open(\'output/meta.json\', \'w\')); print(\'wrote 2 files\')"',
      timeout: 10, memory: 256, procs: 32,
      desc: 'Writes two files in the scratch directory. The diff table lists them with size and SHA-256.',
      demo: { status: 'success', exit_code: 0, stdout: 'wrote 2 files\n', stderr: '' }
    },
    env_leak: {
      label: 'Secret env strip',
      mode: 'cmd',
      text: 'python3 -c "import os; [print(k.ljust(22), os.environ.get(k)) for k in (\'OPENAI_API_KEY\', \'ANTHROPIC_API_KEY\', \'AWS_SECRET_ACCESS_KEY\', \'GITHUB_TOKEN\', \'STRIPE_SECRET_KEY\')]; print(\'visible env:\', sorted(os.environ))"',
      timeout: 5, memory: 128, procs: 16,
      desc: 'Prints well-known credential variables from inside the capsule. Expect None for every one.',
      demo: { status: 'success', exit_code: 0, stdout: 'OPENAI_API_KEY         None\nANTHROPIC_API_KEY      None\nAWS_SECRET_ACCESS_KEY  None\nGITHUB_TOKEN           None\nSTRIPE_SECRET_KEY      None\n', stderr: '' }
    },
    network: {
      label: 'Network block',
      mode: 'script',
      text: 'import socket\nfor host, port in [("1.1.1.1", 53), ("127.0.0.1", 8105)]:\n    s = socket.socket()\n    s.settimeout(2)\n    try:\n        s.connect((host, port))\n        print(host, port, "CONNECTED")\n    except OSError as e:\n        print(host, port, "blocked:", e.strerror or e)\n    finally:\n        s.close()\n',
      timeout: 10, memory: 128, procs: 16,
      desc: 'Tries the internet and the daemon port. With --unshare-all only a private loopback exists.',
      demo: { status: 'success', exit_code: 0, stdout: '1.1.1.1 53 blocked: Network is unreachable\n127.0.0.1 8105 blocked: Connection refused\n', stderr: '' }
    },
    cpu_timeout: {
      label: 'Timeout kill',
      mode: 'script',
      text: 'print("spinning until the timeout kills this capsule", flush=True)\nwhile True:\n    pass\n',
      timeout: 2, memory: 128, procs: 16,
      desc: 'Infinite loop with a 2 s timeout. Expect status TIMEOUT and a negative exit code (SIGKILL).',
      demo: { status: 'timeout', exit_code: -9, stdout: 'spinning until the timeout kills this capsule\n', stderr: '' }
    },
    fork_ceiling: {
      label: 'Process ceiling',
      mode: 'script',
      text: 'import os, time\nn = 0\ntry:\n    while n < 300:\n        pid = os.fork()\n        if pid == 0:\n            time.sleep(3)\n            os._exit(0)\n        n += 1\n    print("spawned", n, "children with no refusal")\nexcept OSError as e:\n    print("fork refused after", n, "children:", e.strerror)\n',
      timeout: 8, memory: 256, procs: 16,
      desc: 'Forks until the kernel refuses. The refusal point tracks the Max processes slider.',
      demo: { status: 'success', exit_code: 0, stdout: 'fork refused after 14 children: Resource temporarily unavailable\n', stderr: '' }
    },
    memory_cap: {
      label: 'Memory cap',
      mode: 'script',
      text: 'print("allocating 512 MB against the memory limit", flush=True)\nblock = bytearray(512 * 1024 * 1024)\nprint("allocated", len(block) // (1024 * 1024), "MB")\n',
      timeout: 10, memory: 256, procs: 16,
      desc: 'Allocates 512 MB under a 256 MB address-space cap. Expect the allocation to fail.',
      demo: { status: 'oom_killed', exit_code: 1, stdout: 'allocating 512 MB against the memory limit\n', stderr: 'MemoryError\n' }
    }
  };

  var state = {
    mode: 'detecting',      // 'live' | 'demo' | 'blocked'
    health: null,
    running: false,
    tab: 'cmd',
    preset: 'file_writer',
    last: null,             // { kind, payload, receiptCheck }
    demoRuns: [],
    pollTimer: null,
    tutorial: null
  };

  var els = {};
  function $(id) { return document.getElementById(id); }

  // ---------- DOM helpers (no innerHTML with data) ----------
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') el.className = attrs[k];
        else if (k === 'text') el.textContent = attrs[k];
        else el.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  }
  function setText(el, value) { if (el) el.textContent = (value === undefined || value === null || value === '') ? '—' : String(value); }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); }
  function show(el, on) { if (el) el.classList.toggle('hidden', !on); }

  function fmtMs(v) { return (typeof v === 'number' && isFinite(v)) ? v.toFixed(v < 100 ? 1 : 0) + ' ms' : '—'; }
  function fmtCpu(res) {
    var u = res.cpu_time_user_s;
    var s = res.cpu_time_system_s != null ? res.cpu_time_system_s : res.cpu_time_sys_s;
    if (typeof u !== 'number' && typeof s !== 'number') return '—';
    return (((u || 0) + (s || 0)) * 1000).toFixed(1) + ' ms';
  }
  function fmtRss(kb) { return (typeof kb === 'number' && isFinite(kb)) ? (kb / 1024).toFixed(1) + ' MB' : '—'; }
  function fmtDuration(sec) {
    if (typeof sec !== 'number' || !isFinite(sec)) return '—';
    var s = Math.floor(sec);
    if (s < 60) return s + 's';
    var m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60) + 's';
    var hr = Math.floor(m / 60);
    if (hr < 48) return hr + 'h ' + (m % 60) + 'm';
    return Math.floor(hr / 24) + 'd ' + (hr % 24) + 'h';
  }
  function timeAgo(ts) {
    if (typeof ts !== 'number') return '';
    var sec = Math.floor(Date.now() / 1000 - ts);
    if (sec < 5) return 'just now';
    if (sec < 60) return sec + 's ago';
    var min = Math.floor(sec / 60);
    if (min < 60) return min + 'm ago';
    var hr = Math.floor(min / 60);
    return hr < 48 ? hr + 'h ago' : Math.floor(hr / 24) + 'd ago';
  }
  function statusClass(st) {
    return ['success', 'error', 'timeout', 'oom_killed'].indexOf(st) >= 0 ? 'st-' + st : 'st-error';
  }
  function statusLabel(st) { return String(st || 'unknown').replace(/_/g, ' ').toUpperCase(); }
  function cmdText(c) { return Array.isArray(c) ? c.join(' ') : String(c == null ? '' : c); }

  // ---------- Token ----------
  function metaToken() {
    var m = document.querySelector('meta[name="capsule-token"]');
    return m ? (m.getAttribute('content') || '') : '';
  }
  function sessionToken() {
    try { return window.sessionStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
  }
  function currentToken() {
    var s = sessionToken();
    if (s) return { value: s, source: 'session' };
    var m = metaToken();
    if (m) return { value: m, source: 'meta' };
    return { value: '', source: 'none' };
  }
  function renderTokenSource() {
    var t = currentToken();
    var msg;
    if (t.source === 'session') msg = 'Using the token you pasted for this tab (sessionStorage).';
    else if (t.source === 'meta') msg = 'Using the token the daemon injected into this page.';
    else msg = 'No token found. Requests will return 401. Get one with: agent-capsule-jail token';
    setText(els.tokenSource, msg);
    setText(els.tokenSummary, 'Exec token · ' + (t.source === 'none' ? 'missing' : t.source === 'meta' ? 'from daemon page' : 'session'));
  }

  // ---------- Canonical JSON + SHA-256 receipt check ----------
  function canonical(v) {
    if (v === undefined) v = null;
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    if (v !== null && typeof v === 'object') {
      return '{' + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ':' + canonical(v[k]); }).join(',') + '}';
    }
    return JSON.stringify(v);
  }
  function sha256Hex(text) {
    if (!(window.crypto && window.crypto.subtle && window.TextEncoder)) return Promise.resolve(null);
    return window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    });
  }
  function verifyReceipt(res) {
    var claimed = res && res.receipt_sha256;
    if (typeof claimed !== 'string' || !/^[0-9a-f]{64}$/.test(claimed)) {
      return Promise.resolve({ state: 'absent', text: claimed ? 'malformed receipt (not 64-hex)' : 'no receipt returned' });
    }
    var body = canonical({
      capsule_id: res.capsule_id, command: res.command, exit_code: res.exit_code,
      stdout: res.stdout, stderr: res.stderr, fs_diff: res.fs_diff
    });
    return sha256Hex(body).then(function (hex) {
      if (!hex) return { state: 'unavailable', text: 'not re-checked (WebCrypto unavailable in this context)' };
      if (hex === claimed) return { state: 'ok', text: 'receipt verified in browser (SHA-256 match)' };
      return { state: 'mismatch', text: 'MISMATCH — browser computed ' + hex };
    }).catch(function () { return { state: 'unavailable', text: 'not re-checked (WebCrypto error)' }; });
  }

  // ---------- Init ----------
  function init() {
    [
      'btnTheme', 'btnGuide', 'demoBanner', 'daemonNotice', 'daemonNoticeTitle', 'daemonNoticeText',
      'engineDot', 'engineMode', 'engSandbox', 'engPids', 'engNet', 'engVersion',
      'cntTotal', 'cntTotalSub', 'cntSuccess', 'cntErrorsSub', 'cntKills', 'cntUptime', 'cntCpuSub',
      'presetDesc', 'tabCmd', 'tabScript', 'paneCmd', 'paneScript', 'inputCmd', 'inputScript',
      'sliderTimeout', 'valTimeout', 'sliderMemory', 'valMemory', 'sliderProcs', 'valProcs', 'inputEnv',
      'tokenBox', 'tokenSummary', 'tokenSource', 'inputToken', 'btnSaveToken', 'btnClearToken', 'btnRun',
      'runKind', 'statusBadge', 'gDuration', 'gCpu', 'gRss', 'gExit', 'errorPanel', 'errorPayload',
      'btnCopyStdout', 'terminalStdout', 'terminalStderr', 'diffSummary', 'diffTableBody', 'diffEmpty',
      'rReceipt', 'rReceiptCheck', 'rFlight', 'rSandbox', 'rPids', 'rLimits', 'rEnvDenied', 'rCapsuleId',
      'recentRuns', 'forensicPayload', 'btnExport'
    ].forEach(function (id) { els[id] = $(id); });

    bindTheme();
    bindEvents();
    loadPreset('file_writer');
    renderTokenSource();
    setupEmbedHeight();
    detectDaemon();
  }

  // ---------- Theme ----------
  function applyThemeButton() {
    var theme = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    var next = theme === 'light' ? 'dark' : 'light';
    els.btnTheme.textContent = next === 'light' ? '☀ Light' : '☾ Dark';
    els.btnTheme.setAttribute('aria-label', 'Switch to ' + next + ' theme');
    els.btnTheme.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  }
  function bindTheme() {
    if (!els.btnTheme) return;
    applyThemeButton();
    els.btnTheme.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      var next = cur === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      try { window.localStorage.setItem(THEME_KEY, next); } catch (e) { /* storage blocked */ }
      if (window.__ACJ_THEME__) window.__ACJ_THEME__.explicit = true;
      applyThemeButton();
    });
    if (window.matchMedia) {
      var mq = window.matchMedia('(prefers-color-scheme: light)');
      var onChange = function (e) {
        if (window.__ACJ_THEME__ && window.__ACJ_THEME__.explicit) return;
        document.documentElement.setAttribute('data-theme', e.matches ? 'light' : 'dark');
        applyThemeButton();
      };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
    }
  }

  function setupEmbedHeight() {
    if (document.documentElement.getAttribute('data-embed') !== '1' || window.parent === window) return;
    var lastH = 0;
    var post = function () {
      var hgt = Math.ceil(document.documentElement.scrollHeight);
      if (hgt === lastH) return;
      lastH = hgt;
      try { window.parent.postMessage({ type: 'acj:height', height: hgt }, '*'); } catch (e) { /* ignore */ }
    };
    if (window.ResizeObserver) new ResizeObserver(post).observe(document.body);
    window.addEventListener('load', post);
    post();
  }

  // ---------- Events ----------
  function bindEvents() {
    document.querySelectorAll('.preset-pill').forEach(function (btn) {
      btn.addEventListener('click', function () { loadPreset(btn.getAttribute('data-preset')); });
    });
    els.tabCmd.addEventListener('click', function () { switchTab('cmd'); });
    els.tabScript.addEventListener('click', function () { switchTab('script'); });
    els.sliderTimeout.addEventListener('input', syncSliders);
    els.sliderMemory.addEventListener('input', syncSliders);
    els.sliderProcs.addEventListener('input', syncSliders);
    els.btnRun.addEventListener('click', runCapsule);

    els.btnSaveToken.addEventListener('click', function () {
      var v = (els.inputToken.value || '').trim();
      if (!v) return;
      try { window.sessionStorage.setItem(TOKEN_KEY, v); } catch (e) { /* storage blocked */ }
      els.inputToken.value = '';
      renderTokenSource();
    });
    els.btnClearToken.addEventListener('click', function () {
      try { window.sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* storage blocked */ }
      els.inputToken.value = '';
      renderTokenSource();
    });

    els.btnCopyStdout.addEventListener('click', function () {
      copyText(els.terminalStdout.textContent || '', els.btnCopyStdout, 'Copy');
    });
    els.btnExport.addEventListener('click', exportJson);

    document.querySelectorAll('.js-copy-sol').forEach(function (btn) {
      var original = btn.textContent;
      btn.addEventListener('click', function () { copyText(btn.getAttribute('data-copy') || SOLANA, btn, original); });
    });

    if (els.btnGuide) {
      els.btnGuide.addEventListener('click', openGuide);
    }

    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && state.mode === 'live') refreshTelemetry();
    });
  }

  function copyText(text, btn, original) {
    var done = function (ok) {
      btn.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(function () { btn.textContent = original; }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      done(false);
    }
  }

  function syncSliders() {
    els.valTimeout.textContent = els.sliderTimeout.value + ' s';
    els.valMemory.textContent = els.sliderMemory.value + ' MB';
    els.valProcs.textContent = els.sliderProcs.value;
  }

  function switchTab(mode) {
    state.tab = mode;
    els.tabCmd.setAttribute('aria-selected', mode === 'cmd' ? 'true' : 'false');
    els.tabScript.setAttribute('aria-selected', mode === 'script' ? 'true' : 'false');
    show(els.paneCmd, mode === 'cmd');
    show(els.paneScript, mode === 'script');
  }

  function loadPreset(key) {
    var p = PRESETS[key];
    if (!p) return;
    state.preset = key;
    document.querySelectorAll('.preset-pill').forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-preset') === key ? 'true' : 'false');
    });
    switchTab(p.mode);
    if (p.mode === 'cmd') els.inputCmd.value = p.text; else els.inputScript.value = p.text;
    els.sliderTimeout.value = p.timeout;
    els.sliderMemory.value = p.memory;
    els.sliderProcs.value = p.procs;
    syncSliders();
    els.presetDesc.textContent = p.desc;
  }

  // ---------- Daemon detection ----------
  function fetchJson(url, opts, timeoutMs) {
    var ctrl = window.AbortController ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, timeoutMs || 4000) : null;
    var o = Object.assign({ cache: 'no-store', credentials: 'same-origin' }, opts || {});
    if (ctrl) o.signal = ctrl.signal;
    return fetch(url, o).then(function (resp) {
      return resp.text().then(function (txt) {
        var data = null;
        var ct = resp.headers.get('content-type') || '';
        try { data = JSON.parse(txt); } catch (e) { data = null; }
        return { status: resp.status, ok: resp.ok, data: data, text: txt, json: data !== null, contentType: ct };
      });
    }).finally(function () { if (timer) clearTimeout(timer); });
  }

  function detectDaemon() {
    fetchJson('/api/health', null, 3000).then(function (r) {
      if (r.ok && r.data && typeof r.data === 'object' && r.data.service === 'agent-capsule-jail') {
        enterLive(r.data);
      } else if (r.json && r.data && r.data.error) {
        enterBlocked(r.status, r.data);
      } else {
        enterDemo();
      }
    }).catch(function () { enterDemo(); });
  }

  function enterLive(health) {
    state.mode = 'live';
    state.health = health;
    show(els.demoBanner, false);
    els.engineDot.className = 'dot live';
    els.engineMode.textContent = 'LIVE daemon :' + (health.port || window.location.port || '');
    setText(els.engSandbox, health.sandbox);
    setText(els.engPids, health.pids_enforcement);
    setText(els.engNet, health.network_opt_in_enabled === true ? 'enabled by operator' : health.network_opt_in_enabled === false ? 'off' : null);
    setText(els.engVersion, health.version ? 'v' + health.version : null);
    show(els.tokenBox, true);
    if (health.sandbox === 'unavailable') {
      daemonNotice('SANDBOX UNAVAILABLE', 'bubblewrap was not found, so the daemon refuses to execute (fail-closed). Install bwrap and restart the daemon.');
    } else if (health.sandbox === 'unsandboxed') {
      daemonNotice('UNSANDBOXED', 'The operator enabled CAPSULE_ALLOW_UNSANDBOXED. Commands run with rlimits only, without namespace isolation.');
    } else {
      show(els.daemonNotice, false);
    }
    els.btnRun.textContent = 'Run in capsule';
    refreshTelemetry();
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(function () { if (!document.hidden) fetchStats(); }, 6000);
  }

  function enterBlocked(status, body) {
    state.mode = 'blocked';
    show(els.demoBanner, false);
    els.engineDot.className = 'dot err';
    els.engineMode.textContent = 'Daemon refused (HTTP ' + status + ')';
    daemonNotice('HTTP ' + status, (body.error || 'request refused') + (body.hint ? ' — ' + body.hint : ''));
    els.btnRun.textContent = 'Run in capsule';
  }

  function enterDemo() {
    state.mode = 'demo';
    show(els.demoBanner, true);
    show(els.daemonNotice, false);
    show(els.tokenBox, false);
    els.engineDot.className = 'dot demo';
    els.engineMode.textContent = 'OFFLINE DEMO — no daemon at /api/health';
    ['engSandbox', 'engPids', 'engNet', 'engVersion'].forEach(function (k) { setText(els[k], 'n/a'); });
    ['cntTotal', 'cntSuccess', 'cntKills', 'cntUptime'].forEach(function (k) { setText(els[k], '—'); });
    setText(els.cntTotalSub, 'daemon offline');
    setText(els.cntErrorsSub, 'daemon offline');
    setText(els.cntCpuSub, 'daemon offline');
    els.btnRun.textContent = 'Run demo (not executed)';
    renderRuns();
  }

  function daemonNotice(title, text) {
    els.daemonNoticeTitle.textContent = title;
    els.daemonNoticeText.textContent = ' ' + text;
    show(els.daemonNotice, true);
  }

  // ---------- Telemetry ----------
  function refreshTelemetry() { fetchStats(); fetchHistory(); }

  function fetchStats() {
    if (state.mode !== 'live') return;
    fetchJson('/api/stats').then(function (r) {
      if (!r.ok || !r.data) return;
      var d = r.data;
      setText(els.cntTotal, d.total_capsules);
      setText(els.cntSuccess, d.total_successes);
      var kills = (typeof d.total_timeouts === 'number' ? d.total_timeouts : 0) + (typeof d.total_memory_kills === 'number' ? d.total_memory_kills : 0);
      setText(els.cntKills, kills);
      setText(els.cntUptime, fmtDuration(d.uptime_seconds));
      setText(els.cntTotalSub, 'since daemon start');
      setText(els.cntErrorsSub, 'errors ' + (d.total_errors != null ? d.total_errors : '—'));
      setText(els.cntCpuSub, 'cpu ' + (typeof d.cumulative_cpu_ms === 'number' ? (d.cumulative_cpu_ms / 1000).toFixed(2) + ' s' : '—'));
    }).catch(function () { /* keep last values */ });
  }

  function fetchHistory() {
    if (state.mode !== 'live') return;
    fetchJson('/api/capsules?limit=8').then(function (r) {
      if (!r.ok || !r.data) return;
      renderRuns(r.data.capsules || []);
    }).catch(function () { /* keep last list */ });
  }

  function renderRuns(list) {
    var runs = state.mode === 'demo' ? state.demoRuns : (list || []);
    clear(els.recentRuns);
    if (!runs.length) {
      els.recentRuns.appendChild(h('p', { class: 'runs-empty', text: state.mode === 'demo' ? 'No demo runs yet. Demo runs are not executed and are not stored.' : 'No runs recorded yet.' }));
      return;
    }
    runs.slice(0, 8).forEach(function (r) {
      var isDemo = state.mode === 'demo';
      var badge = h('span', { class: 'pill ' + (isDemo ? 'st-demo' : statusClass(r.status)), text: isDemo ? 'DEMO' : statusLabel(r.status) });
      var meta = h('span', { class: 'run-meta', text: isDemo ? 'not executed' : (fmtMs(r.duration_ms) + ' · ' + timeAgo(r.timestamp)) });
      var btn = h('button', { type: 'button', class: 'run-item', 'aria-label': 'Show run ' + (r.capsule_id || '') }, [
        badge, h('span', { class: 'run-cmd', text: cmdText(r.command) || r.capsule_id || '' }), meta
      ]);
      btn.addEventListener('click', function () { renderResult(r, isDemo ? 'demo' : 'history'); });
      els.recentRuns.appendChild(btn);
    });
  }

  // ---------- Run ----------
  function buildPayload() {
    var payload = {
      timeout_sec: Math.min(60, Math.max(1, Number(els.sliderTimeout.value) || 10)),
      memory_mb: Math.min(4096, Math.max(64, parseInt(els.sliderMemory.value, 10) || 512)),
      max_procs: Math.min(512, Math.max(1, parseInt(els.sliderProcs.value, 10) || 64))
    };
    if (state.tab === 'script') payload.script = els.inputScript.value;
    else payload.command = els.inputCmd.value.trim();
    var env = (els.inputEnv.value || '').split(/[\s,]+/).filter(function (n) { return /^[A-Za-z_][A-Za-z0-9_]*$/.test(n); });
    if (env.length) payload.allowed_env = env;
    return payload;
  }

  function setRunning(on) {
    state.running = on;
    els.btnRun.disabled = on;
    if (on) {
      els.btnRun.textContent = state.mode === 'demo' ? 'Simulating…' : 'Running in capsule…';
    } else {
      els.btnRun.textContent = state.mode === 'demo' ? 'Run demo (not executed)' : 'Run in capsule';
    }
  }

  function resetResultView(kindText) {
    els.statusBadge.className = 'pill st-running';
    els.statusBadge.textContent = 'RUNNING';
    els.runKind.className = 'kind';
    els.runKind.textContent = kindText;
    show(els.errorPanel, false);
    els.terminalStdout.textContent = '';
    els.terminalStderr.textContent = '';
  }

  function runCapsule() {
    if (state.running) return;
    var payload = buildPayload();
    if (!payload.command && !(payload.script && payload.script.trim())) {
      renderError(0, { error: 'Nothing to run', hint: 'Enter a shell command or a Python script.' }, 'input');
      return;
    }
    if (state.mode === 'demo') { runDemo(payload); return; }

    setRunning(true);
    resetResultView('POST /api/exec');
    var tok = currentToken();
    fetchJson('/api/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Capsule-Token': tok.value },
      body: JSON.stringify(payload)
    }, 75000).then(function (r) {
      if (!r.ok) {
        var body = (r.data && typeof r.data === 'object') ? r.data : { error: (r.text || '').slice(0, 400) || ('HTTP ' + r.status) };
        if (r.status === 401 && tok.source === 'session' && !body.hint) body.hint = 'Your pasted token was rejected. Clear it to fall back to the page token.';
        renderError(r.status, body, 'http');
        return;
      }
      if (!r.data || typeof r.data !== 'object') {
        renderError(r.status, { error: 'Daemon returned a non-JSON response', hint: (r.text || '').slice(0, 200) }, 'http');
        return;
      }
      renderResult(r.data, 'live');
    }).catch(function (err) {
      var aborted = err && err.name === 'AbortError';
      renderError(0, {
        error: aborted ? 'request timed out waiting for the daemon' : 'network error: daemon unreachable',
        hint: 'Check that the daemon is running: agent-capsule-jail serve'
      }, 'network');
    }).finally(function () {
      setRunning(false);
      refreshTelemetry();
    });
  }

  function renderError(httpStatus, body, origin) {
    var payload = { http_status: httpStatus || null, error: body.error || 'unknown error' };
    if (body.hint) payload.hint = body.hint;
    if (body.policy_violation) payload.policy_violation = body.policy_violation;

    state.last = { kind: 'error', payload: payload, receiptCheck: null };
    els.statusBadge.className = 'pill st-error';
    els.statusBadge.textContent = 'ERROR';
    els.runKind.className = 'kind k-err';
    els.runKind.textContent = httpStatus ? 'HTTP ' + httpStatus + ' — not executed' : (origin === 'input' ? 'not sent' : 'no response — not executed');
    show(els.errorPanel, true);
    els.errorPayload.textContent = JSON.stringify(payload, null, 2);
    els.terminalStdout.textContent = '(nothing ran — the request was rejected before execution)';
    els.terminalStderr.textContent = '—';
    ['gDuration', 'gCpu', 'gRss', 'gExit'].forEach(function (k) { setText(els[k], null); });
    renderFsDiff(null);
    ['rReceipt', 'rFlight', 'rSandbox', 'rPids', 'rLimits', 'rEnvDenied', 'rCapsuleId'].forEach(function (k) { setText(els[k], null); });
    els.rReceiptCheck.className = 'muted';
    els.rReceiptCheck.textContent = 'no receipt (request rejected)';
    els.forensicPayload.textContent = JSON.stringify(payload, null, 2);
  }

  function runDemo(payload) {
    setRunning(true);
    resetResultView('DEMO (not executed)');
    var preset = PRESETS[state.preset];
    var text = payload.command || payload.script || '';
    var matches = preset && text === preset.text;
    var sim = matches ? preset.demo : {
      status: 'error', exit_code: null,
      stdout: '',
      stderr: 'Custom commands cannot run in the offline demo. Start the local daemon: agent-capsule-jail serve\n'
    };
    var result = {
      capsule_id: 'demo-' + Math.random().toString(16).slice(2, 10),
      command: payload.command || '<python script>',
      status: sim.status,
      exit_code: sim.exit_code,
      stdout: sim.stdout,
      stderr: sim.stderr,
      fs_diff: matches && state.preset === 'file_writer'
        ? { created: [{ path: 'output/meta.json', size_bytes: 12, sha256: null, is_dir: false }, { path: 'output/report.txt', size_bytes: 27, sha256: null, is_dir: false }], modified: [], deleted: [], total_changes: 2 }
        : { created: [], modified: [], deleted: [], total_changes: 0 },
      limits: { timeout_sec: payload.timeout_sec, memory_mb: payload.memory_mb, max_procs: payload.max_procs },
      timestamp: Date.now() / 1000,
      demo: true
    };
    setTimeout(function () {
      state.demoRuns.unshift(result);
      state.demoRuns = state.demoRuns.slice(0, 8);
      renderResult(result, 'demo');
      renderRuns();
      setRunning(false);
    }, 250);
  }

  function renderResult(res, kind) {
    var isDemo = kind === 'demo';
    state.last = { kind: kind, payload: res, receiptCheck: null };
    show(els.errorPanel, false);

    if (isDemo) {
      els.statusBadge.className = 'pill st-demo';
      els.statusBadge.textContent = 'DEMO · ' + statusLabel(res.status);
      els.runKind.className = 'kind k-demo';
      els.runKind.textContent = 'DEMO (not executed)';
    } else {
      els.statusBadge.className = 'pill ' + statusClass(res.status);
      els.statusBadge.textContent = statusLabel(res.status);
      els.runKind.className = 'kind k-live';
      els.runKind.textContent = (kind === 'history' ? 'past run · ' : 'executed · ') + (res.sandbox_mode || 'unknown sandbox');
    }

    setText(els.gDuration, isDemo ? null : fmtMs(res.duration_ms));
    setText(els.gCpu, isDemo ? null : fmtCpu(res));
    setText(els.gRss, isDemo ? null : fmtRss(res.max_rss_kb));
    setText(els.gExit, res.exit_code);

    var prefix = isDemo ? '[DEMO — not executed. Expected output from the real daemon:]\n' : '';
    els.terminalStdout.textContent = prefix + (res.stdout ? res.stdout : (isDemo ? '' : '(no stdout)'));
    els.terminalStderr.textContent = res.stderr ? res.stderr : '(empty)';

    renderFsDiff(res.fs_diff, isDemo);

    setText(els.rCapsuleId, res.capsule_id);
    setText(els.rSandbox, isDemo ? 'none (demo)' : res.sandbox_mode);
    setText(els.rPids, isDemo ? 'n/a (demo)' : res.pids_enforcement);
    var lim = res.limits || {};
    setText(els.rLimits, (lim.timeout_sec != null || lim.memory_mb != null)
      ? [lim.timeout_sec != null ? lim.timeout_sec + ' s' : null, lim.memory_mb != null ? lim.memory_mb + ' MB' : null,
         lim.max_procs != null ? lim.max_procs + ' procs' : null, lim.max_file_size_mb != null ? lim.max_file_size_mb + ' MB files' : null]
          .filter(Boolean).join(' · ')
      : null);
    setText(els.rEnvDenied, Array.isArray(res.env_denied) ? (res.env_denied.length ? res.env_denied.join(', ') : 'none') : (isDemo ? 'n/a (demo)' : null));

    if (isDemo) {
      setText(els.rReceipt, 'not issued (demo)');
      setText(els.rFlight, 'not sent (demo)');
      els.rReceiptCheck.className = 'muted';
      els.rReceiptCheck.textContent = 'n/a (demo)';
      els.forensicPayload.textContent = JSON.stringify(res, null, 2);
      return;
    }

    setText(els.rReceipt, res.receipt_sha256);
    if (typeof res.flight_recorder_dispatched === 'boolean') {
      els.rFlight.textContent = res.flight_recorder_dispatched ? 'dispatched (2xx from :8104)' : 'not dispatched';
      els.rFlight.className = res.flight_recorder_dispatched ? 'ok-text' : 'muted';
    } else {
      setText(els.rFlight, null);
      els.rFlight.className = '';
    }
    els.forensicPayload.textContent = JSON.stringify(res, null, 2);
    els.rReceiptCheck.className = 'muted';
    els.rReceiptCheck.textContent = 'checking…';
    var target = state.last;
    verifyReceipt(res).then(function (check) {
      if (state.last !== target) return;
      target.receiptCheck = check;
      els.rReceiptCheck.textContent = check.text;
      els.rReceiptCheck.className = check.state === 'ok' ? 'ok-text' : check.state === 'mismatch' ? 'err-text' : 'muted';
    });
  }

  function renderFsDiff(fs, isDemo) {
    clear(els.diffTableBody);
    var created = (fs && fs.created) || [];
    var modified = (fs && fs.modified) || [];
    var deleted = (fs && fs.deleted) || [];
    var total = created.length + modified.length + deleted.length;
    els.diffSummary.textContent = fs ? (total + ' change' + (total === 1 ? '' : 's') + ' · +' + created.length + ' ~' + modified.length + ' -' + deleted.length) : '—';
    show(els.diffEmpty, total === 0);
    var row = function (tagCls, tagText, path, size, sha) {
      els.diffTableBody.appendChild(h('tr', null, [
        h('td', null, [h('span', { class: 'tag ' + tagCls, text: tagText })]),
        h('td', { text: String(path == null ? '' : path) }),
        h('td', { text: size == null ? '—' : String(size) }),
        h('td', { title: sha || '', text: sha ? String(sha).slice(0, 16) + '…' : (isDemo ? 'demo' : '—') })
      ]));
    };
    created.forEach(function (c) { row('tag-new', c.is_dir ? 'NEW DIR' : 'NEW', c.path, c.size_bytes, c.sha256); });
    modified.forEach(function (m) { row('tag-mod', 'MOD', m.path, m.size_bytes, m.sha256); });
    deleted.forEach(function (d) { row('tag-del', 'DEL', typeof d === 'string' ? d : d.path, null, null); });
  }

  function exportJson() {
    if (!state.last) return;
    var out = { kind: state.last.kind, response: state.last.payload };
    if (state.last.receiptCheck) out.client_receipt_check = state.last.receiptCheck;
    var blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    var id = (state.last.payload && state.last.payload.capsule_id) || state.last.kind;
    a.href = url;
    a.download = 'capsule_' + String(id).replace(/[^A-Za-z0-9_.-]/g, '_') + '.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ---------- Guide ----------
  function openGuide() {
    if (!state.tutorial && window.createSovereignTutorial) {
      state.tutorial = window.createSovereignTutorial({
        toolId: 'agent-capsule-jail',
        toolName: 'Agent Capsule Jail',
        tagline: 'Quick guide to the controls on this page',
        steps: [
          { icon: '1', title: 'Pick a preset or write your own', desc: 'Presets fill the editor and the limits. Use the Shell command tab for a command line or the Python script tab for a script.' },
          { icon: '2', title: 'Set the limits', desc: 'Timeout (1–60 s), Memory (address-space cap in MB) and Max processes. The optional env allowlist passes named host variables; names that look like secrets are refused and listed under env_denied.' },
          { icon: '3', title: 'Run and read the real result', desc: 'You get stdout, stderr, exit code, CPU and peak RSS for that run, the scratch filesystem diff with per-file SHA-256, and receipt_sha256, which this page recomputes with WebCrypto.' },
          { icon: '4', title: 'Needs the local daemon', desc: 'Isolation happens in the daemon (agent-capsule-jail serve, 127.0.0.1:8105). Without it the page shows an OFFLINE DEMO banner and every result is labelled DEMO (not executed).' }
        ]
      });
    }
    if (state.tutorial) state.tutorial.open();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
