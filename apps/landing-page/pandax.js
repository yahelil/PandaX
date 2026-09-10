/* PandaX — motion.
 *
 * Every animation here shows something the product actually does: a record
 * assembling, a statutory clock running, a sequence advancing. Nothing fades
 * in for decoration.
 *
 * No dependencies. Honours prefers-reduced-motion by rendering the finished
 * state immediately.
 */

(function () {
  "use strict";

  var still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };

  /* ---------------------------------------------------- the hero record --- */

  var HEX = "0123456789abcdef";

  /** Resolve an identifier left to right, scrambling the tail as it goes. */
  function resolve(el, done) {
    var target = el.textContent;
    var chars = target.split("");
    var i = 0;

    (function step() {
      if (i >= chars.length) { el.textContent = target; if (done) done(); return; }
      var out = target.slice(0, i);
      for (var j = i; j < chars.length; j++) {
        out += chars[j] === "-" || chars[j] === ":" || chars[j] === "."
          ? chars[j]
          : HEX[(Math.random() * 16) | 0];
      }
      el.textContent = out;
      i += Math.max(1, Math.round(chars.length / 26));
      setTimeout(step, 26);
    })();
  }

  /** Count an integer up; leaves non-numeric values (like "6 of 6") alone. */
  function countUp(el) {
    var raw = el.getAttribute("data-count") || "";
    var n = parseInt(raw, 10);
    if (isNaN(n) || String(n) !== raw.trim()) return;
    var start = performance.now();
    var dur = 900;
    (function frame(now) {
      // Clamp both ends: a rAF timestamp can precede the captured start,
      // and a negative t sends the easing curve below zero.
      var t = Math.max(0, Math.min(1, (now - start) / dur));
      var eased = 1 - Math.pow(1 - t, 3);
      el.textContent = String(Math.round(n * eased));
      if (t < 1) requestAnimationFrame(frame);
      else el.textContent = raw;
    })(start);
  }

  function assemble(rec) {
    var ids = $$(".rec-ids .id", rec);
    var stats = $$(".rec-stat-v", rec);
    var checks = $$(".checks li", rec);

    ids.forEach(function (el, i) { setTimeout(function () { resolve(el); }, i * 130); });

    setTimeout(function () { stats.forEach(countUp); }, 420);

    setTimeout(function () {
      rec.classList.add("ran");
      checks.forEach(function (li, i) {
        li.style.transitionDelay = i * 95 + "ms";
      });
    }, 620);

    setTimeout(function () {
      rec.classList.add("sealing");
      setTimeout(function () { rec.classList.add("sealed"); }, 260);
    }, 620 + checks.length * 95 + 260);
  }

  function startHero() {
    var lap = $("#lap");
    var rec = $("#rec");
    if (!lap || !rec) return;

    if (still) {
      lap.classList.add("open");
      rec.classList.add("ran", "sealed");
      return;
    }
    requestAnimationFrame(function () {
      setTimeout(function () { lap.classList.add("open"); }, 180);
      setTimeout(function () { assemble(rec); }, 1180);
    });
  }

  /* ------------------------------------------- the date already running --- */

  /* The label is derived from the date, never asserted. A page that argues for
     precision cannot say "in effect" the day before it is. */
  function deadlineState(el) {
    var from = new Date(el.getAttribute("data-since") + "T00:00:00Z");
    var row = el.closest("tr");
    var live = row && row.querySelector(".live");
    var label = live && live.lastChild;

    function tick() {
      var ms = Date.now() - from.getTime();
      var live_ = ms >= 0;
      var abs = Math.abs(ms);
      var days = Math.floor(abs / 86400000);
      var h = Math.floor(abs / 3600000) % 24;
      var m = Math.floor(abs / 60000) % 60;

      if (label) label.nodeValue = live_ ? "In effect" : "Applies soon";
      if (row) row.classList.toggle("dl-soon", !live_);
      el.textContent = live_
        ? days + "d " + pad(h) + ":" + pad(m) + " elapsed"
        : "in " + days + "d " + pad(h) + ":" + pad(m);
    }
    tick();
    setInterval(tick, 30000);
  }

  /* --------------------------------------------------- the Article 14 clock --- */

  /* Anchored to the moment this page opened: a live demonstration of how the
     deadlines run from recorded awareness. Not a real incident. */
  var WINDOWS = [24 * 3600, 72 * 3600, 14 * 86400];

  function runClock(els) {
    var opened = Date.now();
    function tick() {
      var gone = Math.floor((Date.now() - opened) / 1000);
      els.forEach(function (el) {
        var left = WINDOWS[+el.getAttribute("data-countdown")] - gone;
        if (left < 0) left = 0;
        var d = Math.floor(left / 86400);
        var h = Math.floor(left / 3600) % 24;
        var m = Math.floor(left / 60) % 60;
        var s = left % 60;
        el.textContent = (d ? d + "d " : "") + pad(h) + ":" + pad(m) + ":" + pad(s) + " remaining";
      });
    }
    tick();
    setInterval(tick, 1000);
  }

  /* ------------------------------------------------------ the four stages --- */

  function stages() {
    var list = $("#stages");
    var fill = $("#stageFill");
    if (!list || !fill) return;
    var items = $$(".stage", list);

    if (still) { fill.style.width = "100%"; items.forEach(function (s) { s.classList.add("lit"); }); return; }

    var seen = 0;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var i = +e.target.getAttribute("data-i");
        e.target.classList.add("lit");
        seen = Math.max(seen, i + 1);
        fill.style.width = (seen / items.length) * 100 + "%";
        io.unobserve(e.target);
      });
    }, { threshold: 0.6, rootMargin: "0px 0px -12% 0px" });

    items.forEach(function (s) { io.observe(s); });
  }

  /* ---------------------------------------------------------------- go --- */

  function init() {
    startHero();
    $$(".since").forEach(deadlineState);
    var clock = $$("[data-countdown]");
    if (clock.length) runClock(clock);
    stages();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
