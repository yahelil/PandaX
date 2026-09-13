/* PandaX, the entrance, and the motion on the page below it.
 *
 * Motion here only ever shows something real: a chart drawn from its data,
 * evidence converging on one record, a sequence advancing. No dependencies.
 */

(function () {
  "use strict";

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  var still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ==================================================== the page below --- */

  /* ------------------------------------------------ the record builds --- */

  var HEX = "0123456789abcdef";

  /** Resolve an identifier left to right, scrambling the tail as it goes. */
  function resolve(el) {
    var target = el.textContent;
    var chars = target.split("");
    var i = 0;
    (function step() {
      if (i >= chars.length) { el.textContent = target; return; }
      var out = target.slice(0, i);
      for (var j = i; j < chars.length; j++) {
        out += /[-:.]/.test(chars[j]) ? chars[j] : HEX[(Math.random() * 16) | 0];
      }
      el.textContent = out;
      i += Math.max(1, Math.round(chars.length / 24));
      setTimeout(step, 26);
    })();
  }

  /** Count an integer up; leaves values like "6 of 6" alone. */
  function countUp(el) {
    var raw = el.getAttribute("data-count") || "";
    var n = parseInt(raw, 10);
    if (isNaN(n) || String(n) !== raw.trim()) return;
    var start = performance.now();
    (function frame(now) {
      // Clamp both ends: a rAF timestamp can precede the captured start.
      var t = Math.max(0, Math.min(1, (now - start) / 900));
      el.textContent = String(Math.round(n * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(frame);
      else el.textContent = raw;
    })(start);
  }

  function assemble(sc) {
    var run = $(".sc-run .id", sc);
    if (run) resolve(run);
    setTimeout(function () { $$(".sc-v", sc).forEach(countUp); }, 300);
    setTimeout(function () {
      sc.classList.add("ran");
      $$(".sc-checks li", sc).forEach(function (li, i) { li.style.transitionDelay = i * 90 + "ms"; });
    }, 500);
    setTimeout(function () {
      sc.classList.add("sealing");
      setTimeout(function () { sc.classList.add("sealed"); }, 260);
    }, 1300);
  }

  /** Run fn once, when el first comes into view. */
  function onView(el, fn, threshold) {
    if (!el) return;
    if (still || !("IntersectionObserver" in window)) { fn(); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        fn();
        io.disconnect();
      });
    }, { threshold: threshold == null ? 0.35 : threshold, rootMargin: "0px 0px -8% 0px" });
    io.observe(el);
  }

  function elapsed(el) {
    var from = new Date(el.getAttribute("data-since") + "T00:00:00Z");
    function tick() {
      var ms = Date.now() - from.getTime();
      if (ms < 0) { el.textContent = ""; return; }   // not yet, say nothing
      el.textContent = Math.floor(ms / 86400000) + "d " +
                       pad(Math.floor(ms / 3600000) % 24) + ":" +
                       pad(Math.floor(ms / 60000) % 60) + " elapsed";
    }
    tick();
    setInterval(tick, 30000);
  }

  /** Reveal a list one item at a time, by transition-delay. */
  function stagger(items, step, cls, host) {
    items.forEach(function (el, i) { el.style.transitionDelay = i * step + "ms"; });
    (host || items[0].parentNode).classList.add(cls);
  }

  /** Count a formatted number up, keeping its separators and any suffix. */
  function countFigure(el) {
    var raw = el.textContent.trim();
    var m = raw.match(/^([\d,]+)(.*)$/);
    if (!m) return;
    var target = parseInt(m[1].replace(/,/g, ""), 10);
    var suffix = m[2];
    if (isNaN(target)) return;
    var start = performance.now();
    (function frame(now) {
      var t = Math.max(0, Math.min(1, (now - start) / 1100));
      var v = Math.round(target * (1 - Math.pow(1 - t, 3)));
      el.textContent = v.toLocaleString("en-US") + suffix;
      if (t < 1) requestAnimationFrame(frame);
      else el.textContent = raw;
    })(start);
  }

  /* --------------------------------------------- the machine keeps running --- */

  /** Rotate the record through the example releases, so the hero is not a still. */
  function cycle() {
    var recs = window.PANDAX_RECORDS;
    if (!recs || recs.length < 2 || still) return;
    $$(".laptop-screen .sc, [data-cycle] .sc").forEach(function (sc) { turn(sc, recs); });
  }

  /** One screen, rotating through the example releases on its own clock. */
  function turn(sc, recs) {
    var at = 0;
    function put(rec) {
      var set = function (f, v) { var el = $('[data-f="' + f + '"]', sc); if (el) el.textContent = v; };
      set("product", rec.product);
      set("release", rec.release);
      set("cve", rec.finding.cve);
      set("component", rec.finding.component);
      set("fix", rec.finding.fix);
      $$(".sc-v", sc).forEach(function (el, i) {
        if (rec.stats[i]) el.setAttribute("data-count", rec.stats[i].value);
      });
      var run = $('[data-f="runId"]', sc);
      if (run) { run.textContent = rec.runId; resolve(run); }
      $$(".sc-v", sc).forEach(countUp);
    }

    setInterval(function () {
      at = (at + 1) % recs.length;
      sc.classList.remove("sealed", "sealing");
      sc.classList.add("turning");
      setTimeout(function () {
        put(recs[at]);
        sc.classList.remove("turning");
        setTimeout(function () {
          sc.classList.add("sealing");
          setTimeout(function () { sc.classList.add("sealed"); }, 240);
        }, 900);
      }, 320);
    }, 6500);
  }

  function page() {
    // Each section lights its marker and its rule as it is reached.
    $$(".sec").forEach(function (sec) {
      if (still || !("IntersectionObserver" in window)) { sec.classList.add("lit"); return; }
      // Armed here rather than in the stylesheet: a page that never runs this
      // shows its content instead of hiding it.
      sec.classList.add("rise");
      onView(sec, function () { sec.classList.add("lit"); }, 0.1);
    });


    cycle();

    $$(".figure-v").forEach(function (el) {
      if (still) return;
      onView(el, function () { countFigure(el); }, 0.4);
    });

    $$(".since").forEach(elapsed);

    // The record on the page builds itself once, when it is reached.
    $$(".sc").forEach(function (sc) {
      if (still) { sc.classList.add("ran", "sealed"); return; }
      onView(sc, function () { assemble(sc); }, 0.25);
    });

    // The evidence table and the two state lists, arriving in order.
    var arrive = function (host, items, step) {
      if (!items.length || still || !("IntersectionObserver" in window)) return;
      host.classList.add("armed");
      onView(host, function () { stagger(items, step, "ran", host); }, 0);
    };
    $$(".tbl").forEach(function (t) { arrive(t, $$("tbody tr", t), 85); });
    $$(".rule-list").forEach(function (l) { arrive(l, $$("li", l), 80); });

    // The engine, typing itself out.
    var term = $("#term");
    onView(term, function () {
      stagger($$(".term-lines li", term), 110, "ran", term);
    }, 0.3);

    // The rail fills to the date that is actually in effect.
    var tl = $("#tl"), tlFill = $("#tlFill");
    if (tl && tlFill) {
      onView(tl, function () {
        var marks = $$(".tl-mark", tl);
        var live = marks.findIndex(function (m) { return m.classList.contains("is-live"); });
        var reached = (live < 0 ? marks.length : live + 1) / marks.length;
        var vertical = matchMedia("(max-width: 860px)").matches;
        tlFill.style[vertical ? "height" : "width"] = reached * 100 + "%";
      }, 0.3);
    }

    // Only the SBOM crosses the line.
    var bound = $("#bound");
    onView(bound, function () {
      stagger($$(".bound-side-x .bound-item", bound), 130, "lit", bound);
    }, 0.35);

    var chart = $("#chart");
    onView(chart, function () { chart.classList.add("lit"); }, 0.25);

    // The four reporting deadlines light along their rail.
    var wfs = $("#wfs"), wfFill = $("#wfFill");
    if (wfs && wfFill) {
      onView(wfs, function () {
        wfs.classList.add("lit");
        var vertical = matchMedia("(max-width: 860px)").matches;
        wfFill.style[vertical ? "height" : "width"] = "100%";
      }, 0.25);
    }

    var flow = $("#flow");
    onView(flow, function () { flow.classList.add("lit"); }, 0.3);

    var steps = $("#steps"), fill = $("#stepFill");
    if (steps && fill) {
      var items = $$(".step", steps);
      if (still) {
        fill.style.width = "100%";
        items.forEach(function (s) { s.classList.add("lit"); });
        return;
      }
      var seen = 0;
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          e.target.classList.add("lit");
          seen = Math.max(seen, +e.target.getAttribute("data-i") + 1);
          fill.style.width = (seen / items.length) * 100 + "%";
          io.unobserve(e.target);
        });
      }, { threshold: 0.6, rootMargin: "0px 0px -12% 0px" });
      items.forEach(function (s) { io.observe(s); });
    }
  }

  /* ------------------------------------------------- the products menu --- */

  function menu() {
    var wrap = $("#menu"), btn = $("#menuBtn");
    if (!wrap || !btn) return;

    var open = function (v) { btn.setAttribute("aria-expanded", v ? "true" : "false"); };

    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      open(btn.getAttribute("aria-expanded") !== "true");
    });
    // Hover and focus are handled in CSS; these close the tapped-open state.
    document.addEventListener("click", function (e) {
      if (!wrap.contains(e.target)) open(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { open(false); btn.blur(); }
    });
  }

  /** Send the form without leaving the page, and say so when it lands. */
  function contactForm() {
    var f = $(".form");
    if (!f || !window.fetch) return;
    var post = f.getAttribute("data-post");
    var done = $(".form-done");
    if (!post || !done) return;

    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = $('button[type="submit"]', f);
      var data = {};
      new FormData(f).forEach(function (v, k) { data[k] = String(v).slice(0, 4000); });

      if (btn) { btn.disabled = true; btn.textContent = btn.getAttribute("data-busy") || btn.textContent; }

      fetch(post, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(data),
      }).then(function (r) {
        if (!r.ok) throw new Error(String(r.status));
        // The whole ask goes, heading and all, and the thank-you takes its place.
        var ask = f.closest ? f.closest(".form-ask") : null;
        (ask || f).hidden = true;
        done.hidden = false;
        done.focus();
      }).catch(function () {
        // Nobody is stranded: hand the message back to their mail client.
        if (btn) { btn.disabled = false; btn.textContent = btn.getAttribute("data-idle") || btn.textContent; }
        f.submit();
      });
    });
  }

  /** The notices, in a panel. Escape closes it, focus goes in and comes back,
   *  and a modified click is left alone so the real page still opens. */
  function sheet() {
    var box = $("#sheet");
    if (!box) return;
    var panel = $(".sheet-panel", box), body = $("#sheetBody"),
        title = $("#sheetTitle"), eyebrow = $("#sheetEyebrow"), full = $("#sheetFull");
    var last = null;

    function open(key, label, href) {
      var tpl = $('[data-sheet-body="' + key + '"]', box);
      if (!tpl) return false;
      last = document.activeElement;
      title.textContent = label;
      eyebrow.textContent = "PandaX";
      full.setAttribute("href", href);
      body.innerHTML = "";
      body.appendChild(tpl.content.cloneNode(true));
      body.scrollTop = 0;
      box.hidden = false;
      // a frame, so the transition has a start to move from
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { box.classList.add("open"); });
      });
      document.documentElement.style.overflow = "hidden";
      panel.focus();
      return true;
    }

    function close() {
      if (box.hidden) return;
      box.classList.remove("open");
      document.documentElement.style.overflow = "";
      var done = function () { box.hidden = true; };
      if (still) done();
      else setTimeout(done, 340);
      if (last && last.focus) last.focus();
    }

    document.addEventListener("click", function (e) {
      var link = e.target.closest ? e.target.closest("[data-sheet]") : null;
      if (link) {
        // cmd/ctrl/middle click, or a new tab, belongs to the browser
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
        if (open(link.getAttribute("data-sheet"),
                 link.getAttribute("data-sheet-title") || link.textContent,
                 link.getAttribute("href"))) e.preventDefault();
        return;
      }
      if (e.target.closest && e.target.closest("[data-sheet-close]")) close();
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !box.hidden) close();
      if (e.key !== "Tab" || box.hidden) return;
      // keep the tab ring inside the panel while it is open
      var f = $$('a[href], button, [tabindex]:not([tabindex="-1"])', panel)
        .filter(function (el) { return el.offsetParent !== null; });
      if (!f.length) return;
      var first = f[0], lastEl = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); lastEl.focus(); }
      else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); first.focus(); }
    });
  }

  function init() { menu(); page(); contactForm(); sheet(); }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
