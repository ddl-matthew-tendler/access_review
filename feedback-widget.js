/*
 * QUANTA feedback widget. Framework-agnostic, no dependencies.
 * Works in React, Vue, plain HTML, Dash or Shiny apps served as Domino Apps or extensions.
 *
 * Usage:
 *   <script src="api/feedback/html-to-image.js"></script>   // served by feedback_api_jira's router
 *   <script src="api/feedback/widget.js"></script>
 *   QCFeedback.init({ app: "qc-hub", endpoint: "api/feedback",   // relative: resolves under /apps/<id>/
 *                     screenshot: (el) => htmlToImage.toPng(el) });
 *   QCFeedback.setContext({ view: "Findings", bundleId: "L-16.2.7" });   // identifiers only
 *
 * Form: problem or improvement (optional), optional details, optional priority P0-P3 with a one-line guide,
 * auto screenshot with markup (pen, arrow, box, text, blur).
 * Captured automatically: page, parent Domino URL, browser, screen, Domino user (/v4/users/self),
 * last 25 API calls (method, path, status, ms), last 10 JS errors, last 15 clicks.
 * Never captured: input values, request or response bodies, query-string values.
 */
(function () {
  if (window.QCFeedback) return;

  const MAX_CALLS = 25, MAX_ERRORS = 10, MAX_CLICKS = 15;
  const state = { opts: {}, context: {}, calls: [], errors: [], clicks: [], shot: null, viewer: null, capturing: false };
  const push = (arr, item, max) => { arr.push(item); if (arr.length > max) arr.shift(); };
  const trim = (s, n = 120) => (s || "").replace(/\s+/g, " ").trim().slice(0, n);

  // ---- passive capture -------------------------------------------------------------
  const origFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const t0 = performance.now();
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    const rec = { at: new Date().toISOString(), method: (init.method || input.method || "GET").toUpperCase(),
                  path: url.pathname, status: null, ms: null, requestId: null };
    try {
      const res = await origFetch(input, init);
      rec.status = res.status;
      rec.requestId = res.headers.get("x-request-id");
      return res;
    } catch (e) {
      rec.status = "network-error";
      throw e;
    } finally {
      rec.ms = Math.round(performance.now() - t0);
      if (!rec.path.endsWith("/feedback")) {
        push(state.calls, rec, MAX_CALLS);
        if (rec.status === "network-error" || rec.status >= 500) trouble();
      }
    }
  };

  const origErr = console.error.bind(console);
  console.error = (...args) => {
    if (state.capturing) return origErr(...args);
    push(state.errors, { at: new Date().toISOString(), msg: trim(args.map(String).join(" "), 400) }, MAX_ERRORS);
    origErr(...args);
  };
  window.addEventListener("error", (e) => {
    push(state.errors, { at: new Date().toISOString(), msg: trim(e.message, 400), src: `${e.filename}:${e.lineno}` }, MAX_ERRORS);
    trouble();
  });
  window.addEventListener("unhandledrejection", (e) => {
    push(state.errors, { at: new Date().toISOString(), msg: trim(String(e.reason), 400) }, MAX_ERRORS);
    if (!state.capturing) trouble();
  });
  // Something went wrong on the page: nudge once, after the widget is mounted.
  function trouble() { if (!state.capturing && state.onTrouble) state.onTrouble(); else if (!state.onTrouble) state.pendingTrouble = true; }

  document.addEventListener("click", (e) => {
    if (host && host.contains(e.target)) return;
    const el = e.target.closest("button,a,[role=button],[role=tab],[role=menuitem],td,li,label") || e.target;
    push(state.clicks, { at: new Date().toISOString(), label: trim(el.innerText || el.getAttribute("aria-label"), 60),
                         selector: selectorFor(el) }, MAX_CLICKS);
  }, true);

  function selectorFor(el) {
    const parts = [];
    while (el && el.nodeType === 1 && parts.length < 5) {
      if (el.id) { parts.unshift("#" + el.id); break; }
      const tid = el.getAttribute("data-testid");
      if (tid) { parts.unshift(`[data-testid="${tid}"]`); break; }
      let p = el.tagName.toLowerCase();
      const cls = [...el.classList].filter((c) => !/^css-|^sc-|\d{3,}/.test(c)).slice(0, 2);
      if (cls.length) p += "." + cls.join(".");
      parts.unshift(p);
      el = el.parentElement;
    }
    return parts.join(" > ");
  }

  // ---- UI --------------------------------------------------------------------------
  let host, root;
  const HINT = "";   // footer line; used only for validation and send errors
  // [value, option label, Details question, placeholder example]
  const TYPES = [
    ["problem", "Report a problem", "What went wrong?", "e.g. Clicking Save shows an error and nothing is saved."],
    ["improvement", "Suggest an improvement", "What would make it better?", "e.g. Let me filter this list by study."],
  ];
  // Jira EXT priorities, P0 most urgent. The guide shows for the hovered, focused or chosen level.
  const PRIO_HINT = "P0 is the most urgent. Hover over a level to see what it means.";
  const PRIO = { P0: "Blocks work or production, no workaround", P1: "Major impact, workaround is painful",
                 P2: "Moderate impact, workaround exists", P3: "Minor or cosmetic" };

  function mount() {
    host = document.createElement("div");
    host.id = "qc-feedback-host";
    document.body.appendChild(host);
    root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
<style>
  :host { --ink:#1f2433; --muted:#626a7e; --line:#dcdfe8; --accent:var(--qcfb-accent,#543fde); --bg:#fff; --soft:#f4f3fd;
          font: 13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--ink); }
  .tab { position:fixed; right:0; top:42%; transform:translateY(-50%); writing-mode:vertical-rl; rotate:180deg;
         background:var(--accent); color:#fff; border:0; border-radius:0 6px 6px 0; padding:12px 7px; cursor:pointer;
         font:600 12px system-ui,sans-serif; letter-spacing:.02em; z-index:2147483000; }
  .tab { display:flex; align-items:center; gap:7px; transition: padding .25s cubic-bezier(.3,1.6,.5,1), box-shadow .25s; box-shadow:0 2px 8px rgba(40,30,120,.25); }
  .tab .ico { width:15px; height:15px; rotate:180deg; flex:none; transform-origin:50% 60%; }
  .tab:hover { padding-right:13px; box-shadow:0 4px 16px rgba(40,30,120,.38); }
  .tab:hover .ico { animation: fb-wiggle .6s ease-in-out; }
  .tab.peek { animation: fb-peek 1.4s cubic-bezier(.3,1.6,.5,1); }
  .tab.peek .ico { animation: fb-wiggle .7s ease-in-out .35s; }
  .tab.nudge { animation: fb-pulse 1.6s ease-out 3; }
  @keyframes fb-peek { 0%,100% { padding-right:7px; } 35%,65% { padding-right:20px; } }
  @keyframes fb-wiggle { 0%,100% { transform:rotate(0); } 20% { transform:rotate(-16deg); } 45% { transform:rotate(12deg); } 70% { transform:rotate(-6deg); } }
  @keyframes fb-pulse { 0% { box-shadow:0 0 0 0 rgba(84,63,222,.55), 0 2px 8px rgba(40,30,120,.25); } 100% { box-shadow:0 0 0 14px rgba(84,63,222,0), 0 2px 8px rgba(40,30,120,.25); } }
  .tip { position:fixed; right:44px; top:42%; transform:translateY(-50%) translateX(8px); background:var(--ink); color:#fff; font:500 12px system-ui,sans-serif;
         padding:7px 10px; border-radius:8px; white-space:nowrap; opacity:0; pointer-events:none; transition:opacity .25s, transform .25s; z-index:2147483000; }
  .tip::after { content:""; position:absolute; right:-5px; top:50%; translate:0 -50%; border:5px solid transparent; border-left-color:var(--ink); border-right:0; }
  .tip.show { opacity:1; transform:translateY(-50%) translateX(0); }
  .done-ico { width:44px; height:44px; display:block; margin:0 auto 6px; position:relative; }
  .done-ico circle { fill:var(--soft); }
  .done-ico path { fill:none; stroke:var(--accent); stroke-width:3.2; stroke-linecap:round; stroke-linejoin:round; stroke-dasharray:30; stroke-dashoffset:30; }
  .ok:not([hidden]) .done-ico path { animation: fb-draw .45s ease-out .1s forwards; }
  @keyframes fb-draw { to { stroke-dashoffset:0; } }
  .burst { position:absolute; left:50%; top:22px; width:0; height:0; pointer-events:none; }
  .burst i { position:absolute; width:6px; height:6px; border-radius:50%; opacity:0; animation: fb-burst .8s ease-out .2s forwards; }
  @keyframes fb-burst { 0% { transform:translate(0,0) scale(1); opacity:1; } 100% { transform:translate(var(--dx),var(--dy)) scale(.4); opacity:0; } }
  .ok { position:relative; }
  @media (prefers-reduced-motion: reduce) {
    .tab, .tab .ico, .tab.peek, .tab.nudge, .tab:hover .ico, .burst i, .tip { animation:none !important; transition:none !important; }
    .ok:not([hidden]) .done-ico path { animation:none; stroke-dashoffset:0; }
  }
  .tab:focus-visible, button:focus-visible, textarea:focus-visible, select:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .panel { position:fixed; right:16px; bottom:16px; width:380px; max-height:calc(100vh - 32px); overflow:auto; background:var(--bg);
           border:1px solid var(--line); border-radius:12px; box-shadow:0 16px 40px rgba(20,24,40,.18); z-index:2147483001; display:none; }
  .panel.open { display:block; }
  [hidden] { display:none !important; }
  header { display:flex; justify-content:space-between; align-items:center; padding:16px 20px 4px; }
  header h2 { margin:0; font-size:16px; font-weight:650; }
  .x { background:none; border:0; font-size:18px; cursor:pointer; color:var(--muted); }
  form { padding:12px 20px 0; display:grid; gap:20px; }
  .types { display:grid; grid-template-columns:1fr 1fr; gap:8px; border:0; margin:0; padding:0; }
  .types label { border:1px solid var(--line); border-radius:8px; cursor:pointer; color:var(--ink); background:var(--bg);
                                transition:background .15s, border-color .15s, color .15s; }
  .types label { padding:10px 12px; font-size:13px; font-weight:600; text-align:center; display:flex; align-items:center; justify-content:center; min-height:44px; }
  .types label:hover { border-color:#c3c7d4; }
  .types input { position:absolute; opacity:0; pointer-events:none; }
  .types label:has(input:checked) { border-color:var(--accent); background:var(--soft); color:var(--accent); }
  .types label:has(input:focus-visible) { outline:2px solid var(--accent); outline-offset:2px; }
  .prio-head { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:6px; }
  .prio-head .lbl { margin:0; }
  .prio-clear { background:none; border:0; padding:0; font:inherit; font-size:12px; cursor:pointer; color:var(--muted); }
  .prio-clear:hover { color:var(--ink); text-decoration:underline; }
  .levels { display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }
  .p0 { --lvl:#c4232b; } .p1 { --lvl:#c2410c; } .p2 { --lvl:#a16207; } .p3 { --lvl:#4a5568; }
  .levels label { position:relative; display:flex; align-items:center; justify-content:center; min-height:36px; border:1px solid var(--line); border-radius:8px;
                  cursor:pointer; font-size:13px; font-weight:650; color:var(--ink); background:var(--bg); transition:background .15s, border-color .15s, color .15s; }
  .levels label:hover { border-color:var(--lvl); color:var(--lvl); }
  .levels input { position:absolute; opacity:0; pointer-events:none; }
  .levels label:has(input:checked) { border-color:var(--lvl); background:color-mix(in srgb, var(--lvl) 9%, #fff); color:var(--lvl); box-shadow:inset 0 0 0 1px var(--lvl); }
  .levels label:has(input:focus-visible) { outline:2px solid var(--accent); outline-offset:2px; }
  .levels label.pop { animation: fb-pop .3s cubic-bezier(.3,1.7,.5,1); }
  @keyframes fb-pop { 0% { transform:scale(.92); } 60% { transform:scale(1.05); } 100% { transform:scale(1); } }
  .prio-cap { margin-top:6px; font-size:12px; color:var(--muted); min-height:1.45em; }
  .prio-cap strong { color:var(--lvl); }
  @media (prefers-reduced-motion: reduce) { .levels label { transition:none; } .levels label.pop { animation:none; } }
  .opt { font-weight:400; color:var(--muted); }
  fieldset { border:0; margin:0; padding:0; min-width:0; }
  legend { padding:0; }
  textarea { width:100%; box-sizing:border-box; border:1px solid var(--line); border-radius:8px; padding:10px 12px; font:inherit; resize:vertical; min-height:76px; }
  textarea:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 15%, transparent); }
  textarea::placeholder { color:#9aa0b0; }
  .lbl { font-size:12px; font-weight:600; color:var(--muted); margin-bottom:6px; display:block; }
  .lbl .req { color:#d92d20; }
  textarea.invalid { border-color:#d92d20; }
  .hint.err { color:#b42318; }
  .row { display:flex; gap:6px; flex-wrap:wrap; }
  .btn { border:1px solid var(--line); background:#fff; border-radius:6px; padding:6px 10px; cursor:pointer; font:inherit; }
  .btn.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
  .attach { display:flex; align-items:center; gap:14px; }
  .shotfig { position:relative; display:block; flex:none; width:128px; padding:0; border:0; background:none; cursor:pointer; }
  .shotfig img.thumb { display:block; width:128px; height:80px; object-fit:cover; object-position:top left; border-radius:6px; }
  .shotcta { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(31,36,51,.55); color:#fff;
             font-size:12px; font-weight:600; border-radius:6px; opacity:0; transition:opacity .15s; }
  .shotfig:hover .shotcta, .shotfig:focus-visible .shotcta { opacity:1; }
  .shotbar { display:flex; flex-direction:column; align-items:flex-start; gap:8px; font-size:12px; color:var(--muted); }
  .shotbar > span:last-child { display:flex; align-items:center; gap:10px; }
  .shotbar button, .shotempty button { background:none; border:0; padding:0; font:inherit; cursor:pointer; color:var(--muted); }
  .shotbar .mkbtn { border:1px solid var(--accent); border-radius:999px; padding:3px 11px; color:var(--accent); font-weight:600; }
  .shotbar .mkbtn:hover { background:var(--soft); }
  .shotempty .mkbtn { color:var(--accent); font-weight:600; padding-left:4px; }
  .shotbar .link:hover { color:var(--ink); text-decoration:underline; }
  .shotempty { flex:1; padding:14px; border:1px dashed var(--line); border-radius:8px; font-size:12px; color:var(--muted); text-align:center; }
  .mk-stage { position:relative; max-width:100%; line-height:0; }
  .mk-text { position:absolute; font:600 16px system-ui,sans-serif; color:#e5484d; background:rgba(255,255,255,.92); border:1.5px dashed #e5484d;
             border-radius:4px; padding:2px 6px; min-width:120px; outline:none; line-height:1.3; }
  img.thumb { max-width:100%; border:1px solid var(--line); border-radius:4px; cursor:pointer; }
  .mk { position:fixed; inset:0; background:rgba(20,24,40,.82); z-index:2147483003; display:none; flex-direction:column; align-items:center; justify-content:center; gap:10px; padding:12px; box-sizing:border-box; }
  .mk.open { display:flex; }
  .mk-bar { display:flex; gap:6px; align-items:center; background:#fff; border-radius:8px; padding:6px; }
  .mk-bar button { border:1px solid var(--line); background:#fff; border-radius:6px; padding:6px 10px; font:inherit; cursor:pointer; }
  .mk-bar button[aria-pressed="true"] { background:var(--soft); border-color:var(--accent); color:var(--accent); font-weight:600; }
  .mk-bar .sep { width:1px; height:22px; background:var(--line); margin:0 4px; }
  .mk-bar .mk-primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
  .mk canvas { max-width:100%; max-height:calc(100vh - 90px); background:#fff; border-radius:4px; cursor:crosshair; touch-action:none; box-shadow:0 8px 30px rgba(0,0,0,.35); }
  .mk-hint { color:#e8e9ef; font-size:12px; }
  .hint { color:var(--muted); font-size:12px; }
  .foot { display:flex; justify-content:space-between; align-items:center; gap:12px; margin:0 -20px; padding:14px 20px; border-top:1px solid var(--line);
          background:#fafbfc; border-radius:0 0 12px 12px; position:sticky; bottom:0; }
  .foot .hint { font-size:11.5px; line-height:1.35; }
  .btn.primary { padding:8px 16px; border-radius:8px; white-space:nowrap; }
  .ok { padding:24px 14px; text-align:center; }
  .ok a { color:var(--accent); font-weight:600; }
  .ok .jira-note { font-size:11px; }
  @media (prefers-reduced-motion:no-preference) { .panel.open { animation:in .14s ease-out; } @keyframes in { from { opacity:0; translate:0 6px; } } }
</style>
<button class="tab" part="tab" aria-haspopup="dialog"><svg class="ico" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 4h16a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H9l-4.5 3.6A.5.5 0 0 1 4 20.2V17a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Zm4 6.2a1.3 1.3 0 1 0 0 2.6 1.3 1.3 0 0 0 0-2.6Zm4 0a1.3 1.3 0 1 0 0 2.6 1.3 1.3 0 0 0 0-2.6Zm4 0a1.3 1.3 0 1 0 0 2.6 1.3 1.3 0 0 0 0-2.6Z"/></svg><span>Feedback</span></button>
<div class="tip" role="status">Something look off? Tell us.</div>
<div class="mk" role="dialog" aria-label="Mark up screenshot">
  <div class="mk-bar">
    <button type="button" data-tool="pen" aria-pressed="true">Pen</button>
    <button type="button" data-tool="arrow" aria-pressed="false">Arrow</button>
    <button type="button" data-tool="box" aria-pressed="false">Box</button>
    <button type="button" data-tool="text" aria-pressed="false">Text</button>
    <button type="button" data-tool="blur" aria-pressed="false">Blur</button>
    <span class="sep"></span>
    <button type="button" class="mk-undo">Undo</button>
    <button type="button" class="mk-cancel">Cancel</button>
    <button type="button" class="mk-primary mk-done">Done</button>
  </div>
  <div class="mk-stage"><canvas></canvas></div>
  <div class="mk-hint">Draw, add text, or blur anything sensitive. Ctrl+Z undoes.</div>
</div>
<section class="panel" role="dialog" aria-label="Send feedback">
  <header><h2>Send feedback</h2><button class="x" aria-label="Close">×</button></header>
  <form novalidate>
    <fieldset><legend class="lbl">What kind of feedback? <span class="opt">Optional</span></legend>
      <div class="types">${TYPES.map(([v, t]) =>
        `<label><input type="radio" name="type" value="${v}">${t}</label>`).join("")}</div></fieldset>
    <div><label class="lbl" for="fb-what"><span class="qtext">Details</span> <span class="opt">Optional</span></label>
      <textarea id="fb-what" name="what" rows="3" placeholder="Describe it here."></textarea></div>
    <div class="prio"><div class="prio-head"><span class="lbl" id="fb-prio-lbl">Priority <span class="opt">Optional</span></span>
        <button type="button" class="prio-clear" hidden>Clear priority</button></div>
      <div class="levels" role="radiogroup" aria-labelledby="fb-prio-lbl">${Object.keys(PRIO).map((p) =>
        `<label class="${p.toLowerCase()}"><input type="radio" name="priority" value="${p}" aria-label="${p}: ${PRIO[p]}">${p}</label>`).join("")}</div>
      <div class="prio-cap">${PRIO_HINT}</div></div>
    <div><span class="lbl">Screenshot <span class="opt">Included</span></span>
      <div class="attach"></div></div>
    <div class="foot"><span class="hint">${HINT}</span><button type="submit" class="btn primary">Send feedback</button></div>
  </form>
  <div class="ok" hidden><svg class="done-ico" viewBox="0 0 44 44" aria-hidden="true"><circle cx="22" cy="22" r="21"/><path d="M13 22.5l6 6 12-13"/></svg><span class="burst"></span><p><strong>Feedback sent.</strong></p><p class="hint ref"></p><button class="btn again">Send more</button></div>
</section>`;

    const $ = (s) => root.querySelector(s);
    const panel = $(".panel"), form = $("form"), tab = $(".tab");

    // Open at once; the screenshot fills in when ready (first capture on a page can take several seconds).
    const capture = async () => {
      const gen = (state.capGen = (state.capGen || 0) + 1);
      state.capturing = true; state.shotPending = true; renderAttach($);
      tab.style.visibility = "hidden";
      const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 15000));
      let shot = null;
      // Short pages: stretch body to the visible window so the capture isn't a thin strip.
      const body = document.body, cs = getComputedStyle(body), prevMin = body.style.minHeight;
      body.style.minHeight = `${Math.max(0, innerHeight - parseFloat(cs.marginTop) - parseFloat(cs.marginBottom))}px`;
      try { shot = await Promise.race([state.opts.screenshot(body), timeout]); } catch (e) { /* user can retake or paste */ }
      finally { body.style.minHeight = prevMin; }
      tab.style.visibility = "";
      if (gen !== state.capGen) return;
      if (!state.shot && shot) state.shot = await onWhite(shot);
      state.shotFailed = !state.shot; state.capturing = false; state.shotPending = false; renderAttach($);
    };
    const open = () => {
      if (panel.classList.contains("open")) return;
      panel.classList.add("open"); $("#fb-what").focus();
      if (state.opts.screenshot && !state.shot && !state.shotPending) capture();
    };
    const close = () => panel.classList.remove("open");
    tab.onclick = () => { hideTip(); return panel.classList.contains("open") ? close() : open(); };

    // Priority: the guide line follows hover and keyboard focus, then settles on the chosen level.
    const levels = $(".levels"), cap = $(".prio-cap"), clear = $(".prio-clear");
    const chosen = () => form.elements.priority.value;
    const caption = (p) => {
      if (!p) { cap.textContent = PRIO_HINT; return; }
      cap.className = `prio-cap ${p.toLowerCase()}`;
      cap.innerHTML = `<strong>${p}</strong> \u00b7 ${PRIO[p]}`;
    };
    const showChosen = () => { caption(chosen()); clear.hidden = !chosen(); };
    levels.querySelectorAll("label").forEach((el) => {
      const input = el.querySelector("input");
      el.addEventListener("mouseenter", () => caption(input.value));
      input.addEventListener("focus", () => caption(input.value));
      input.addEventListener("change", () => {
        showChosen();
        el.classList.remove("pop"); void el.offsetWidth; el.classList.add("pop");
      });
    });
    levels.addEventListener("mouseleave", showChosen);
    levels.addEventListener("focusout", showChosen);
    clear.onclick = () => {
      levels.querySelectorAll("input").forEach((x) => { x.checked = false; });
      levels.querySelector("input").focus(); showChosen();
    };
    // Type: tailor the Details question.
    const showType = () => {
      const v = form.elements.type.value, t = TYPES.find((x) => x[0] === v);
      $(".qtext").textContent = t ? t[2] : "Details";
      $("#fb-what").placeholder = t ? t[3] : "Describe it here.";
    };
    form.querySelectorAll('input[name="type"]').forEach((el) => el.addEventListener("change", showType));
    showType();
    $("#fb-what").addEventListener("input", (e) => {
      if (e.target.value.trim()) { e.target.classList.remove("invalid"); const h = $(".hint"); if (h.classList.contains("err")) { h.classList.remove("err"); h.textContent = HINT; } }
    });

    // Delight: peek once per browser session, nudge once per page when something fails.
    const tip = $(".tip");
    const hideTip = () => tip.classList.remove("show");
    const replay = (cls) => { tab.classList.remove(cls); void tab.offsetWidth; tab.classList.add(cls); };
    tab.addEventListener("animationend", (e) => { if (e.animationName === "fb-peek") tab.classList.remove("peek"); });
    let seen = false; try { seen = sessionStorage.getItem("qcfb-peeked") === "1"; } catch (e) {}
    if (!seen) setTimeout(() => {
      if (panel.classList.contains("open")) return;
      replay("peek"); try { sessionStorage.setItem("qcfb-peeked", "1"); } catch (e) {}
    }, 4000);
    let nudged = false;
    state.onTrouble = () => {
      if (nudged || panel.classList.contains("open")) return;
      nudged = true; replay("nudge");
      const r = tab.getBoundingClientRect(); tip.style.top = `${r.top + r.height / 2}px`;
      tip.classList.add("show");
      setTimeout(hideTip, 6000);
    };
    if (state.pendingTrouble) setTimeout(state.onTrouble, 1500);
    $(".x").onclick = close;
    document.addEventListener("keydown", (e) => {
      if (e.altKey && e.shiftKey && e.code === "KeyF") open();
      if (e.key === "Escape" && panel.classList.contains("open") && !state.marking) close();
    });


    state.retake = () => {
      if (!state.opts.screenshot) return;
      state.shot = null; state.markedUp = false; capture();
    };
    root.addEventListener("paste", (e) => {
      const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
      if (!item) return;
      const r = new FileReader();
      r.onload = () => { state.shot = r.result; state.markedUp = false; renderAttach($); };
      r.readAsDataURL(item.getAsFile());
    });

    form.onsubmit = async (e) => {
      e.preventDefault();
      const what = $("#fb-what"), hint = $(".hint");
      what.classList.remove("invalid"); hint.classList.remove("err");
      const btn = $(".primary"); btn.disabled = true; btn.textContent = "Sending";
      $(".hint").textContent = HINT;
      try {
        const out = await send({ type: form.elements.type.value || null, what: form.elements.what.value,
                                 priority: form.elements.priority.value || null });
        form.hidden = true; $(".ok").hidden = false;
        const burst = $(".burst"); burst.innerHTML = "";
        const colors = ["var(--accent)", "#f5a524", "#17c964", "#f31260", "#06b7db"];
        for (let i = 0; i < 14; i++) {
          const d = document.createElement("i"), a = (i / 14) * Math.PI * 2, r = 34 + (i % 3) * 10;
          d.style.cssText = `background:${colors[i % colors.length]};--dx:${Math.cos(a) * r}px;--dy:${Math.sin(a) * r}px`;
          burst.appendChild(d);
        }
        const ref = $(".ref"); ref.textContent = "Reference ";
        if (out.url && /^https:\/\//.test(out.url)) {
          const a = document.createElement("a");
          a.href = out.url; a.target = "_blank"; a.rel = "noopener noreferrer"; a.textContent = out.id;
          ref.append(a, document.createElement("br"));
          const note = document.createElement("span"); note.className = "jira-note";
          note.textContent = "The link above will open in Jira.";
          ref.append(note);
        } else {
          ref.append(out.id);
        }
      } catch (err) {
        $(".hint").textContent = `Not sent: ${err.message}. Try again.`; $(".hint").classList.add("err");
      } finally { btn.disabled = false; btn.textContent = "Send feedback"; }
    };
    $(".again").onclick = () => {
      form.reset(); state.shot = null; state.markedUp = false; showChosen(); showType();
      form.hidden = false; $(".ok").hidden = true; $("#fb-what").focus();
      if (state.opts.screenshot) capture(); else renderAttach($);
    };
  }

  function renderAttach($) {
    const box = $(".attach"); box.innerHTML = "";
    if (state.shotPending && !state.shot) {
      const wait = document.createElement("div"); wait.className = "shotempty"; wait.textContent = "Capturing screenshot\u2026";
      box.append(wait); return;
    }
    if (state.shot) {
      const fig = document.createElement("button"); fig.type = "button"; fig.className = "shotfig"; fig.title = "Mark up screenshot";
      fig.innerHTML = `<img class="thumb" alt="Screenshot of this page"><span class="shotcta">Click to mark up</span>`;
      fig.querySelector("img").src = state.shot;
      fig.onclick = () => startMarkup($);
      const bar = document.createElement("div"); bar.className = "shotbar";
      bar.innerHTML = `<span class="shotnote">${state.markedUp ? "Marked up" : "Mark up or blur anything sensitive."}</span>
        <span><button type="button" class="mkbtn">Mark up</button><button type="button" class="link retake">Retake</button><button type="button" class="link rm">Remove</button></span>`;
      bar.querySelector(".mkbtn").onclick = () => startMarkup($);
      bar.querySelector(".rm").onclick = () => { state.shot = null; state.markedUp = false; renderAttach($); };
      bar.querySelector(".retake").onclick = () => state.retake && state.retake();
      if (!state.opts.screenshot) bar.querySelector(".retake").remove();
      box.append(fig, bar);
    } else {
      const empty = document.createElement("div"); empty.className = "shotempty";
      empty.innerHTML = state.opts.screenshot
        ? `<span>${state.shotFailed ? "Screenshot failed." : "No screenshot."} Paste one with Ctrl+V or</span> <button type="button" class="mkbtn take">Take screenshot</button>`
        : `<span>Paste a screenshot with Ctrl+V.</span>`;
      const take = empty.querySelector(".take"); if (take) take.onclick = () => state.retake && state.retake();
      box.append(empty);
    }
  }

  // Screenshot markup: pen, arrow, box, blur (pixelate). Flattens into state.shot at full resolution.
  // Screenshots of short pages have transparent areas; put them on white so they read the same everywhere.
  function onWhite(dataUrl) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const c = document.createElement("canvas"); c.width = img.naturalWidth; c.height = img.naturalHeight;
        const x = c.getContext("2d"); x.fillStyle = "#fff"; x.fillRect(0, 0, c.width, c.height); x.drawImage(img, 0, 0);
        resolve(c.toDataURL("image/png"));
      };
      img.onerror = () => resolve(dataUrl);
      img.src = dataUrl;
    });
  }

  function startMarkup($) {
    const mk = $(".mk"), panel = $(".panel"), cv = mk.querySelector("canvas"), ctx = cv.getContext("2d");
    const base = new Image();
    const ops = []; let tool = "pen", cur = null;
    const RED = "#e5484d";
    base.onload = () => {
      cv.width = base.naturalWidth; cv.height = base.naturalHeight;
      const lw = Math.max(3, Math.round(cv.width / 400));
      const pos = (e) => { const r = cv.getBoundingClientRect(); return { x: (e.clientX - r.left) * cv.width / r.width, y: (e.clientY - r.top) * cv.height / r.height }; };
      const pixelate = (x, y, w, h) => {
        if (w < 0) { x += w; w = -w; } if (h < 0) { y += h; h = -h; }
        if (w < 2 || h < 2) return;
        const block = Math.max(8, Math.round(Math.min(w, h) / 6));
        const t = document.createElement("canvas"); t.width = Math.max(1, Math.round(w / block)); t.height = Math.max(1, Math.round(h / block));
        const tc = t.getContext("2d"); tc.drawImage(base, x, y, w, h, 0, 0, t.width, t.height);
        ctx.save(); ctx.imageSmoothingEnabled = false; ctx.drawImage(t, 0, 0, t.width, t.height, x, y, w, h); ctx.restore();
      };
      const drawOp = (o) => {
        ctx.save(); ctx.strokeStyle = RED; ctx.fillStyle = RED; ctx.lineWidth = lw; ctx.lineCap = "round"; ctx.lineJoin = "round";
        if (o.t === "pen" && o.pts.length > 1) { ctx.beginPath(); ctx.moveTo(o.pts[0].x, o.pts[0].y); o.pts.forEach((p) => ctx.lineTo(p.x, p.y)); ctx.stroke(); }
        if (o.t === "box") ctx.strokeRect(o.a.x, o.a.y, o.b.x - o.a.x, o.b.y - o.a.y);
        if (o.t === "blur") pixelate(o.a.x, o.a.y, o.b.x - o.a.x, o.b.y - o.a.y);
        if (o.t === "text") {
          ctx.font = `600 ${o.size}px system-ui,-apple-system,"Segoe UI",sans-serif`; ctx.textBaseline = "top";
          ctx.lineWidth = Math.max(3, o.size / 5); ctx.strokeStyle = "#fff"; ctx.strokeText(o.s, o.x, o.y);
          ctx.fillStyle = RED; ctx.fillText(o.s, o.x, o.y);
        }
        if (o.t === "arrow") {
          const ang = Math.atan2(o.b.y - o.a.y, o.b.x - o.a.x), hl = lw * 5;
          ctx.beginPath(); ctx.moveTo(o.a.x, o.a.y); ctx.lineTo(o.b.x, o.b.y); ctx.stroke();
          ctx.beginPath(); ctx.moveTo(o.b.x, o.b.y);
          ctx.lineTo(o.b.x - hl * Math.cos(ang - 0.45), o.b.y - hl * Math.sin(ang - 0.45));
          ctx.lineTo(o.b.x - hl * Math.cos(ang + 0.45), o.b.y - hl * Math.sin(ang + 0.45)); ctx.closePath(); ctx.fill();
        }
        ctx.restore();
      };
      // ops replay in order: later marks draw over earlier blur
      const redraw = () => {
        ctx.clearRect(0, 0, cv.width, cv.height); ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.drawImage(base, 0, 0); [...ops, ...(cur ? [cur] : [])].forEach(drawOp);
      };
      redraw();
      const fontPx = Math.max(18, Math.round(cv.width / 55));
      const stage = mk.querySelector(".mk-stage");
      const placeText = (e) => {
        const old = stage.querySelector(".mk-text"); if (old) old.blur();
        const p = pos(e), r = cv.getBoundingClientRect(), scale = r.width / cv.width;
        const inp = document.createElement("input"); inp.className = "mk-text"; inp.placeholder = "Type, then Enter";
        inp.style.left = `${e.clientX - r.left}px`; inp.style.top = `${e.clientY - r.top}px`;
        inp.style.fontSize = `${Math.max(12, fontPx * scale)}px`;
        let done = false;
        const commit = (keep) => {
          if (done) return; done = true;
          if (keep && inp.value.trim()) ops.push({ t: "text", x: p.x, y: p.y, s: inp.value.trim(), size: fontPx });
          inp.remove(); redraw();
        };
        inp.addEventListener("keydown", (k) => {
          k.stopPropagation();
          if (k.key === "Enter") commit(true);
          if (k.key === "Escape") commit(false);
        });
        inp.addEventListener("blur", () => commit(true));
        stage.appendChild(inp); setTimeout(() => inp.focus(), 0);
      };
      cv.onpointerdown = (e) => {
        if (tool === "text") { e.preventDefault(); placeText(e); return; }
        cv.setPointerCapture(e.pointerId); const p = pos(e); cur = tool === "pen" ? { t: "pen", pts: [p] } : { t: tool, a: p, b: p };
      };
      cv.onpointermove = (e) => { if (!cur) return; const p = pos(e); if (cur.t === "pen") cur.pts.push(p); else cur.b = p; redraw(); };
      cv.onpointerup = () => { if (cur) ops.push(cur); cur = null; redraw(); };
      mk.querySelectorAll("[data-tool]").forEach((b) => {
        b.onclick = () => { tool = b.dataset.tool; mk.querySelectorAll("[data-tool]").forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false")); };
      });
      const finish = (save) => {
        const pending = stage.querySelector(".mk-text"); if (pending) { if (save) pending.blur(); else pending.remove(); }
        if (save && ops.length) { cur = null; redraw(); state.shot = cv.toDataURL("image/png"); state.markedUp = true; }
        mk.classList.remove("open"); state.marking = false; panel.classList.add("open"); renderAttach($);
        document.removeEventListener("keydown", onKey, true);
      };
      const onKey = (e) => {
        if (e.composedPath().some((n) => n.classList && n.classList.contains("mk-text"))) return;
        if (e.key === "Escape") { e.stopPropagation(); finish(false); }
        if ((e.metaKey || e.ctrlKey) && e.key === "z") { e.preventDefault(); ops.pop(); redraw(); }
      };
      mk.querySelector(".mk-undo").onclick = () => { ops.pop(); redraw(); };
      mk.querySelector(".mk-cancel").onclick = () => finish(false);
      mk.querySelector(".mk-done").onclick = () => finish(true);
      document.addEventListener("keydown", onKey, true);
      state.marking = true; panel.classList.remove("open"); mk.classList.add("open");
    };
    base.src = state.shot;
  }

  // Domino user of whoever is viewing the app. Same-origin call with the viewer's session.
  async function loadViewer() {
    try {
      const r = await origFetch(state.opts.userEndpoint || "/v4/users/self", { credentials: "include" });
      if (!r.ok) return;
      const u = await r.json();
      state.viewer = { userName: u.userName, fullName: u.fullName || [u.firstName, u.lastName].filter(Boolean).join(" "), email: u.email };
    } catch (e) { /* backend still has the domino-username header */ }
  }

  // "Edge 155 on Windows" from the user agent (Edge first: its UA also says Chrome).
  function browserName() {
    const ua = navigator.userAgent;
    const m = ua.match(/Edg\/(\d+)/) ? ["Edge", ua.match(/Edg\/(\d+)/)[1]]
      : ua.match(/Firefox\/(\d+)/) ? ["Firefox", ua.match(/Firefox\/(\d+)/)[1]]
      : ua.match(/Chrome\/(\d+)/) ? ["Chrome", ua.match(/Chrome\/(\d+)/)[1]]
      : ua.match(/Version\/(\d+).*Safari/) ? ["Safari", ua.match(/Version\/(\d+)/)[1]] : ["Unknown browser", ""];
    const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "unknown OS";
    return `${m[0]} ${m[1]} on ${os}`.replace("  ", " ");
  }

  function appVersion() {
    if (state.opts.version) return state.opts.version;
    const s = [...document.scripts].map((x) => x.src).find((u) => /assets\/index-[\w-]+\.js/.test(u));
    return s ? s.match(/index-([\w-]+)\.js/)[1] : "unknown";
  }

  function parentUrl() {
    try { return window.top.location.pathname; } catch { return null; }
  }

  async function send(input) {
    const payload = {
      ...input,
      app: state.opts.app || location.pathname.split("/")[2] || "unknown",
      appVersion: appVersion(),
      viewer: state.viewer,
      markedUp: !!state.markedUp,
      context: state.context,
      page: { path: location.pathname, queryKeys: [...new URLSearchParams(location.search).keys()],
              title: document.title, dominoPath: parentUrl() },
      client: { ua: navigator.userAgent, browser: browserName(), viewport: `${innerWidth}x${innerHeight}`,
                screen: `${screen.width}x${screen.height}`, dpr: devicePixelRatio, lang: navigator.language,
                tz: Intl.DateTimeFormat().resolvedOptions().timeZone, at: new Date().toISOString() },
      recentCalls: state.calls.slice(),
      recentErrors: state.errors.slice(),
      recentClicks: state.clicks.slice(),
    };
    const fd = new FormData();
    fd.append("payload", JSON.stringify(payload));
    if (state.shot) fd.append("screenshot", await (await origFetch(state.shot)).blob(), "screenshot.png");
    const res = await origFetch(state.opts.endpoint || "api/feedback", { method: "POST", body: fd, credentials: "include" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const out = await res.json();
    state.shot = null; state.markedUp = false;
    return out;
  }

  window.QCFeedback = {
    init(opts = {}) {
      state.opts = opts;
      loadViewer();
      if (document.body) mount(); else document.addEventListener("DOMContentLoaded", mount);
    },
    setContext(obj) { state.context = { ...state.context, ...obj }; },
    clearContext(keys) { (keys || Object.keys(state.context)).forEach((k) => delete state.context[k]); },
  };
})();
