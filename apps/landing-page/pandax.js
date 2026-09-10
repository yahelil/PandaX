/* PandaX — motion.
 *
 * Every animation shows something the product actually does: a machine waking,
 * a record assembling, evidence converging, a sequence advancing. Nothing fades
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
    }, { threshold: threshold || 0.35, rootMargin: "0px 0px -8% 0px" });
    io.observe(el);
  }

  /* ------------------------------------------------ the machine wakes --- */

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
      // Clamp both ends: a rAF timestamp can precede the captured start, and a
      // negative t sends the easing curve below zero.
      var t = Math.max(0, Math.min(1, (now - start) / 900));
      el.textContent = String(Math.round(n * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(frame);
      else el.textContent = raw;
    })(start);
  }

  function assemble(sc) {
    var run = $(".sc-run .id", sc);
    if (run) resolve(run);
    setTimeout(function () { $$(".sc-v", sc).forEach(countUp); }, 320);
    setTimeout(function () {
      sc.classList.add("ran");
      $$(".sc-checks li", sc).forEach(function (li, i) { li.style.transitionDelay = i * 90 + "ms"; });
    }, 520);
    setTimeout(function () {
      sc.classList.add("sealing");
      setTimeout(function () { sc.classList.add("sealed"); }, 260);
    }, 1400);
  }

  function startHero() {
    var laptop = $("#laptop");
    var sc = $("#sc");
    if (!laptop || !sc) return;
    if (still) {
      laptop.classList.add("open");
      sc.classList.add("ran", "sealed");
      return;
    }
    requestAnimationFrame(function () {
      setTimeout(function () { laptop.classList.add("open"); }, 240);
      setTimeout(function () { assemble(sc); }, 1500);
    });
  }

  /* ------------------------------------------------ the date in effect --- */

  function elapsed(el) {
    var from = new Date(el.getAttribute("data-since") + "T00:00:00Z");
    function tick() {
      var ms = Date.now() - from.getTime();
      if (ms < 0) { el.textContent = ""; return; }   // not yet — say nothing
      var days = Math.floor(ms / 86400000);
      el.textContent = days + "d " + pad(Math.floor(ms / 3600000) % 24) + ":" +
                       pad(Math.floor(ms / 60000) % 60) + " elapsed";
    }
    tick();
    setInterval(tick, 30000);
  }

  /* --------------------------------------------------------------- go --- */

  function init() {
    startHero();
    $$(".since").forEach(elapsed);

    // Bars grow from the baseline when the chart is reached.
    var chart = $("#chart");
    onView(chart, function () { chart.classList.add("lit"); });

    // Sources converge, then the outputs appear.
    var flow = $("#flow");
    onView(flow, function () { flow.classList.add("lit"); }, 0.3);

    // The three manual steps light in order as you pass them.
    var steps = $("#steps"), fill = $("#stepFill");
    if (steps && fill) {
      var items = $$(".step", steps);
      if (still) {
        fill.style.width = "100%";
        items.forEach(function (s) { s.classList.add("lit"); });
      } else {
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
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
