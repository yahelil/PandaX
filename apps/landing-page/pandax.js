/* PandaX — the entrance, and the motion on the page below it.
 *
 * The boot is the one cinematic moment: the lid comes up onto the PandaX mark,
 * the camera pushes into the screen, the chassis dissolves, and the page opens
 * through the transparent counter at the crossing of the X. It is driven by
 * scroll, not by a timer, so the visitor is the one moving.
 *
 * Everything below the boot moves only to show something real: a chart drawn
 * from its data, evidence converging on one record, a sequence advancing.
 *
 * GSAP is self-hosted; the site makes no external requests.
 */

(function () {
  "use strict";

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  var still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* =====================================================================
     BOOT — the lid opens onto the mark, then the camera flies through the
     X at the centre of the panda and out into the page.
     ===================================================================== */

  /** True when this view came from elsewhere on the site rather than fresh. */
  function seenAlready() {
    var entry = (performance.getEntriesByType &&
                 performance.getEntriesByType("navigation")[0]) || null;

    // A reload is a deliberate restart: play it.
    if (entry && entry.type === "reload") return false;

    // Back and forward within the site: already seen.
    if (entry && entry.type === "back_forward") return true;

    // Otherwise it depends on where they came from. Same origin means they
    // were just here; anything else is a first arrival.
    try {
      return !!document.referrer &&
             new URL(document.referrer).origin === location.origin;
    } catch (e) {
      return false;
    }
  }

  function boot() {
    var boot = $("#boot");
    var laptop = $("#laptop");
    var lid = $("#laptopLid");
    var hint = $("#bootHint");
    var lpImg = $("#lpImg");

    if (!boot || !laptop) { document.body.classList.add("entered"); return; }

    document.body.classList.add("boot-on");

    // A deep link wants the section, not the overture. Reduced motion wants no
    // overture at all. And neither does someone coming back from another page
    // on this site — sitting through it again to reach the nav is a tax on
    // every visit. A reload still plays it.
    var deepLink = location.hash && location.hash !== "#top";
    if (deepLink || still || seenAlready() || !window.gsap || !window.ScrollTrigger) {
      boot.style.display = "none";
      document.body.classList.add("entered");
      return;
    }

    document.body.classList.add("has-boot");
    gsap.registerPlugin(ScrollTrigger);

    var base = boot.querySelector(".laptop-base");
    var cam = boot.querySelector(".laptop-camera");
    var shNav = boot.querySelector(".sh-nav");
    var swm = boot.querySelector(".swm");
    var grade = boot.querySelector(".sh-grade");
    var glare = boot.querySelector(".laptop-glare");
    var lidBack = boot.querySelector(".laptop-lid-back");
    var shadow = boot.querySelector(".laptop-shadow");
    var small = matchMedia("(max-width: 760px)").matches;

    /* Scale and offset that make the open lid exactly fill the viewport.
       Measured with the lid flat, otherwise we would capture the closed lid
       lying on the base and end up centred on the keyboard. */
    function fit() {
      var rot = gsap.getProperty(lid, "rotateX");
      var sc = gsap.getProperty(laptop, "scale");
      var px = gsap.getProperty(laptop, "x");
      var py = gsap.getProperty(laptop, "y");
      gsap.set(lid, { rotateX: 0 });
      gsap.set(laptop, { scale: 1, x: 0, y: 0 });

      var r = lid.getBoundingClientRect();
      var lr = laptop.getBoundingClientRect();

      // Scale about the centre of the LID, not of the whole chassis. The
      // chassis is taller than the lid, so its centre sits below the screen
      // and scaling around it walks the screen off the viewport centre.
      gsap.set(laptop, { transformOrigin: "50% " + (r.top + r.height / 2 - lr.top) + "px" });

      // Cover, not contain: we fly through the mark in the middle of the
      // screen, so filling the viewport beats keeping the corners in frame.
      var s = Math.max(innerWidth / r.width, innerHeight / r.height);
      var out = {
        s: s,
        tx: innerWidth / 2 - (r.left + r.width / 2),
        ty: innerHeight / 2 - (r.top + r.height / 2),
      };

      gsap.set(lid, { rotateX: rot });
      gsap.set(laptop, { scale: sc, x: px, y: py });
      return out;
    }
    var target = fit();

    /* How far to push through the X. The transparent counter at the crossing
       is about 12.8% of the artwork's width, so this is what carries its
       edges past the corners of the screen. */
    var PUSH = small ? 15 : 22;
    var closedRot = small ? -108 : -100;

    gsap.set(lid, { rotateX: closedRot, transformOrigin: "50% 100%" });
    gsap.set(base, { opacity: 0 });
    if (shadow) gsap.set(shadow, { opacity: 0 });
    gsap.set(laptop, { scale: 1, x: 0, y: 0, transformOrigin: "50% 50%" });
    gsap.set(lpImg, { xPercent: -49.9, yPercent: -66.6, transformOrigin: "49.9% 66.6%" });
    gsap.to(lpImg, { opacity: 1, duration: 1.2, delay: 0.5, ease: "power2.out" });
    if (swm) gsap.to(swm, { opacity: 1, duration: 0.8, delay: 1.15, ease: "power2.out" });

    var tl = gsap.timeline({
      defaults: { ease: "none" },
      scrollTrigger: {
        trigger: boot,
        start: "top top",
        end: function () { return "+=" + Math.round(innerHeight * 2.7); },
        scrub: 0.6,
        pin: true,
        pinSpacing: true,
        anticipatePin: 1,
        invalidateOnRefresh: true,
        onRefresh: function () { target = fit(); },
      },
    });

    /* 1 — the lid comes up */
    tl.to(lid, { rotateX: 0, duration: 0.20, ease: "power3.out" }, 0);
    tl.to([hint, boot.querySelector(".boot-meta")], { opacity: 0, duration: 0.06 }, 0);
    if (lidBack) tl.to(lidBack, { opacity: 0, duration: 0.04, ease: "power3.out" }, 0);
    tl.to([base, shadow], { opacity: 1, duration: 0.09, ease: "power1.out" }, 0.03);
    tl.to({}, { duration: 0.06 });

    /* 2 — the camera pushes into the screen */
    tl.to(laptop, {
      duration: 0.36,
      x: function () { return target.tx; },
      y: function () { return target.ty; },
      scale: function () { return target.s; },
      ease: "power2.inOut",
    }, 0.26);

    /* 3 — the chassis dissolves; the screen becomes the page */
    tl.to([base, cam, glare, shadow], { opacity: 0, duration: 0.12, ease: "power1.out" }, 0.52);
    tl.to(lid, {
      "--bezel": "0px",
      "--radius": "0px",
      borderColor: "rgba(255,255,255,0)",
      boxShadow: "0 0 0 rgba(0,0,0,0)",
      duration: 0.14, ease: "power1.out",
    }, 0.52);

    /* 4 — everything but the mark clears out of the way */
    tl.to([shNav, swm], { opacity: 0, duration: 0.10, ease: "power1.out" }, 0.40);
    if (grade) tl.to(grade, { opacity: 0, duration: 0.16 }, 0.48);

    /* 5 — through the X. The counter is transparent, so the page ground
           behind it simply opens up as the arms sweep past the corners. */
    tl.to(lpImg, { scale: PUSH, duration: 0.50, ease: "power2.in" }, 0.42);
    tl.fromTo(lpImg, { filter: "blur(0px)" },
              { filter: "blur(12px)", duration: 0.22, ease: "power2.in" }, 0.70);
    tl.to(lpImg, { opacity: 0, duration: 0.13, ease: "power1.out" }, 0.79);

    /* 6 — the boot dissolves so the page is simply there behind it */
    tl.to(boot, { opacity: 0, duration: 0.12, ease: "power1.inOut" }, 0.86);

    /* 7 — hand off to the real page */
    tl.add(function () { document.body.classList.add("entered"); }, 0.90);
    tl.add(function () { document.body.classList.remove("entered"); }, 0.89);
  }

  /* ==================================================== the page below --- */

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

  function elapsed(el) {
    var from = new Date(el.getAttribute("data-since") + "T00:00:00Z");
    function tick() {
      var ms = Date.now() - from.getTime();
      if (ms < 0) { el.textContent = ""; return; }   // not yet — say nothing
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

  function page() {
    $$(".since").forEach(elapsed);

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

  function init() { boot(); menu(); page(); }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
