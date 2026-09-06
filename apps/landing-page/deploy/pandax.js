/* PandaX — CRA Compliance-in-a-Box · interactions */
(() => {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const yr = $('#yr'); if (yr) yr.textContent = new Date().getFullYear();

  /* ===================================================================
     BOOT — the lid opens onto the PandaX mark, then the camera flies
     through the X at the centre of the panda and out into the page.
     =================================================================== */
  const boot   = $('#boot');
  const laptop = $('#laptop');
  const lid    = $('#laptopLid');
  const hint   = $('#bootHint');
  const lpImg  = $('#lpImg');

  if (boot && laptop) {
    document.body.classList.add('boot-on');

    const deepLink = location.hash && location.hash !== '#top';

    if (deepLink || reduced || !window.gsap || !window.ScrollTrigger) {
      boot.style.display = 'none';
      document.body.classList.add('entered');
    } else {
      document.body.classList.add('has-boot');
      gsap.registerPlugin(ScrollTrigger);

      const base   = boot.querySelector('.laptop-base');
      const cam    = boot.querySelector('.laptop-camera');
      const shNav  = boot.querySelector('.sh-nav');
      const swm    = boot.querySelector('.swm');
      const grade  = boot.querySelector('.sh-grade');
      const glare  = boot.querySelector('.laptop-glare');
      const lidBack = boot.querySelector('.laptop-lid-back');
      const small  = matchMedia('(max-width: 760px)').matches;

      /* Scale + offset that makes the open lid exactly fill the viewport.
         Measured with the lid flat (rotateX 0), otherwise we'd capture the
         closed lid lying on the base and end up centred on the keyboard. */
      const fit = () => {
        const rot = gsap.getProperty(lid, 'rotateX');
        const sc  = gsap.getProperty(laptop, 'scale');
        const px  = gsap.getProperty(laptop, 'x');
        const py  = gsap.getProperty(laptop, 'y');
        gsap.set(lid,    { rotateX: 0 });
        gsap.set(laptop, { scale: 1, x: 0, y: 0 });

        const r  = lid.getBoundingClientRect();
        const lr = laptop.getBoundingClientRect();

        // Scale about the centre of the LID, not of the whole chassis. The
        // chassis is taller than the lid, so its centre sits below the screen
        // and scaling around it walks the screen off the viewport centre.
        gsap.set(laptop, { transformOrigin: `50% ${r.top + r.height / 2 - lr.top}px` });

        // cover, not contain: we fly through the mark in the middle of the
        // screen, so filling the viewport beats keeping the corners in frame.
        const s = Math.max(innerWidth / r.width, innerHeight / r.height);
        const out = {
          s,
          tx: innerWidth  / 2 - (r.left + r.width  / 2),
          ty: innerHeight / 2 - (r.top  + r.height / 2),
        };

        gsap.set(lid,    { rotateX: rot });
        gsap.set(laptop, { scale: sc, x: px, y: py });
        return out;
      };
      let target = fit();

      /* How far to push through the X. The transparent counter at the
         crossing is ~12.8% of the artwork's width, so this is what carries
         its edges past the corners of the screen. */
      const PUSH = small ? 15 : 22;

      const closedRot = small ? -108 : -100;
      gsap.set(lid,    { rotateX: closedRot, transformOrigin: '50% 100%' });
      gsap.set(base,   { opacity: 0 });
      gsap.set(laptop, { scale: 1, x: 0, y: 0, transformOrigin: '50% 50%' });
      gsap.set(lpImg,  { xPercent: -49.9, yPercent: -66.6, transformOrigin: '49.9% 66.6%' });
      gsap.to(lpImg, { opacity: 1, duration: 1.2, delay: 0.5, ease: 'power2.out' });
      if (swm) gsap.to(swm, { opacity: 1, duration: 0.8, delay: 1.15, ease: 'power2.out' });

      const tl = gsap.timeline({
        defaults: { ease: 'none' },
        scrollTrigger: {
          trigger: boot,
          start: 'top top',
          end: () => '+=' + Math.round(innerHeight * 2.7),
          scrub: 0.6,
          pin: true,
          pinSpacing: true,
          anticipatePin: 1,
          invalidateOnRefresh: true,
          onRefresh: () => { target = fit(); },
        },
      });

      /* 1 — the lid comes up */
      tl.to(lid,  { rotateX: 0, duration: 0.20, ease: 'power3.out' }, 0);
      tl.to([hint, boot.querySelector('.boot-meta')], { opacity: 0, duration: 0.06 }, 0);
      if (lidBack) tl.to(lidBack, { opacity: 0, duration: 0.04, ease: 'power3.out' }, 0);
      tl.to(base, { opacity: 1, duration: 0.09, ease: 'power1.out' }, 0.03);
      tl.to({}, { duration: 0.06 });

      /* 2 — the camera pushes into the screen */
      tl.to(laptop, {
        duration: 0.36,
        x:     () => target.tx,
        y:     () => target.ty,
        scale: () => target.s,
        ease:  'power2.inOut',
      }, 0.26);

      /* 3 — the chassis dissolves; the screen becomes the page */
      tl.to([base, cam, glare], { opacity: 0, duration: 0.12, ease: 'power1.out' }, 0.52);
      tl.to(lid, {
        '--bezel': '0px',
        '--radius': '0px',
        borderColor: 'rgba(255,255,255,0)',
        boxShadow: '0 0 0 rgba(0,0,0,0)',
        duration: 0.14, ease: 'power1.out',
      }, 0.52);

      /* 4 — everything but the mark clears out of the way */
      tl.to([shNav, swm], { opacity: 0, duration: 0.10, ease: 'power1.out' }, 0.40);
      if (grade) tl.to(grade, { opacity: 0, duration: 0.16 }, 0.48);

      /* 5 — through the X. The counter is transparent, so the page ground
             behind it simply opens up as the arms sweep past the corners. */
      tl.to(lpImg, {
        scale: PUSH,
        duration: 0.50,
        ease: 'power2.in',
      }, 0.42);
      tl.fromTo(lpImg,
        { filter: 'blur(0px)' },
        { filter: 'blur(12px)', duration: 0.22, ease: 'power2.in' }, 0.70);
      tl.to(lpImg, { opacity: 0, duration: 0.13, ease: 'power1.out' }, 0.79);

      /* 6 — the whole boot dissolves so the page is simply there behind it */
      tl.to(boot, { opacity: 0, duration: 0.12, ease: 'power1.inOut' }, 0.86);

      /* 7 — hand off to the real page */
      tl.add(() => document.body.classList.add('entered'), 0.90);
      tl.add(() => document.body.classList.remove('entered'), 0.89);
    }
  } else {
    document.body.classList.add('entered');
  }

  /* ===================== nav + progress ===================== */
  const nav = $('#nav'), prog = $('#progress');
  const onScroll = () => {
    const y = scrollY;
    nav?.classList.toggle('scrolled', y > 40);
    if (prog) {
      const max = document.documentElement.scrollHeight - innerHeight;
      prog.style.width = (y / Math.max(1, max)) * 100 + '%';
    }
  };
  addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* ===================== cursor ===================== */
  const ring = $('#curRing'), dot = $('#curDot');
  if (matchMedia('(pointer: fine)').matches && ring && dot) {
    document.body.classList.add('cur-on');
    let mx = innerWidth / 2, my = innerHeight / 2, rx = mx, ry = my;
    addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; });
    (function tick() {
      rx += (mx - rx) * 0.18; ry += (my - ry) * 0.18;
      dot.style.left = mx + 'px';  dot.style.top = my + 'px';
      ring.style.left = rx + 'px'; ring.style.top = ry + 'px';
      requestAnimationFrame(tick);
    })();
    const hov = 'a, button, .scr, .tri-i, .plan, .step, .why-row, .kpi';
    document.addEventListener('mouseover', e => { if (e.target.closest(hov)) document.body.classList.add('cur-hover'); });
    document.addEventListener('mouseout',  e => { if (e.target.closest(hov)) document.body.classList.remove('cur-hover'); });
  }

  /* ===================== countdowns ===================== */
  const pad = n => String(n).padStart(2, '0');
  const clocks = $$('[data-countdown]').map(el => ({
    el,
    at: new Date(el.dataset.countdown).getTime(),
    d: $('[data-cd="d"]', el), h: $('[data-cd="h"]', el),
    m: $('[data-cd="m"]', el), s: $('[data-cd="s"]', el),
  }));
  if (clocks.length) {
    const tickClocks = () => {
      const now = Date.now();
      clocks.forEach(c => {
        let ms = c.at - now;
        if (ms < 0) ms = 0;
        const sec = Math.floor(ms / 1000);
        c.d.textContent = Math.floor(sec / 86400).toLocaleString('en-US');
        c.h.textContent = pad(Math.floor(sec / 3600) % 24);
        c.m.textContent = pad(Math.floor(sec / 60) % 60);
        c.s.textContent = pad(sec % 60);
      });
    };
    tickClocks();
    setInterval(tickClocks, 1000);
  }

  /* ===================== count-up figures ===================== */
  const fmt = (v, kind) => kind === 'dec'
    ? v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : Math.round(v).toLocaleString('en-US');

  const countUp = el => {
    const to = parseFloat(el.dataset.count);
    const kind = el.dataset.format || 'int';
    if (reduced) { el.textContent = fmt(to, kind); return; }
    const dur = 1500, t0 = performance.now();
    const step = now => {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);           // easeOutCubic
      el.textContent = fmt(to * e, kind);
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  /* ===================== word splitter ===================== */
  $$('[data-reveal-words]').forEach(el => {
    const wrap = node => {
      if (node.nodeType === Node.TEXT_NODE) {
        if (!node.textContent.trim()) return;
        const frag = document.createDocumentFragment();
        node.textContent.split(/(\s+)/).forEach(part => {
          if (/^\s+$/.test(part)) frag.appendChild(document.createTextNode(part));
          else if (part) {
            const s = document.createElement('span');
            s.className = 'w'; s.textContent = part;
            frag.appendChild(s);
          }
        });
        node.replaceWith(frag);
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        [...node.childNodes].forEach(wrap);
      }
    };
    [...el.childNodes].forEach(wrap);
    $$('.w', el).forEach((w, i) => { w.style.transitionDelay = i * 0.035 + 's'; });
  });

  /* ===================== reveal on scroll ===================== */
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      e.target.classList.add('in-view');
      $$('[data-count]', e.target).forEach(countUp);
      if (e.target.matches('[data-count]')) countUp(e.target);
      io.unobserve(e.target);
    });
  }, { threshold: 0.18, rootMargin: '0px 0px -10% 0px' });

  $$('[data-reveal], [data-reveal-words], [data-reveal-dial], [data-count]')
    .forEach(el => io.observe(el));

  /* ===================== anchors ===================== */
  $$('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const id = a.getAttribute('href');
      if (id.length < 2) return;
      const t = document.querySelector(id);
      if (!t) return;
      e.preventDefault();
      t.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    });
  });


  /* ===================== FAQ ===================== */
  $$('.faq-q').forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.faq-i');
      const open = item.classList.toggle('open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  });

  /* ===================== applicability check ===================== */
  const chkV = $('#chkV'), chkP = $('#chkP');
  if (chkV && chkP) {
    const answers = [1, 1, 1];
    const verdicts = () => {
      // no code inside -> the regulation simply does not reach it
      if (!answers[0]) return ['no', 'Probably not in scope',
        'A product with no software or programmable chip sits outside the Cyber Resilience Act. If that changes — even a Bluetooth module or a companion app — it comes into scope straight away.'];
      // sold outside the EU only
      if (!answers[2]) return ['no', 'Not in scope today',
        'The rules bite when a product is placed on the <b>EU market</b>. Sell, import or distribute there later and every obligation applies from day one, so it is worth being ready before you expand.'];
      // software, but genuinely nothing to connect to
      if (!answers[1]) return ['yes', 'Likely in scope',
        'Products with digital elements are covered even when the connection is <b>indirect</b> — a service port, a phone app, an occasional update over USB all count. Very few connected-adjacent products fall outside.'];
      return ['yes', 'The CRA applies',
        'Your product almost certainly falls in scope, and most likely on the <b>self-check</b> route — the lightest one. That still means a software list, ongoing vulnerability monitoring and a technical file.'];
    };
    const paint = () => {
      const [cls, title, body] = verdicts();
      chkV.className = 'chk-v ' + cls;
      chkV.textContent = title;
      chkP.innerHTML = body;
    };
    $$('.chk-b').forEach(b => {
      b.addEventListener('click', () => {
        const q = +b.dataset.q;
        answers[q] = +b.dataset.v;
        $$(`.chk-b[data-q="${q}"]`).forEach(o => o.setAttribute('aria-pressed', o === b ? 'true' : 'false'));
        paint();
      });
    });
    paint();
  }

  /* ===================== console ===================== */
  console.log('%cPANDAX', 'font-family: Archivo, sans-serif; font-size: 26px; font-weight: 800; letter-spacing: 0.18em; color: #F2F5F9;');
  console.log('%cEU Cyber Resilience Act compliance, without a security team.', 'font-family: monospace; font-size: 11px; color: #98A2B0;');
})();
