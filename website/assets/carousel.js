/* Progressive, local-only application carousel. No cloned cards or remote calls. */
(() => {
  'use strict';
  const carousel = document.querySelector('[data-carousel]');
  if (!carousel) return;
  const track = carousel.querySelector('.core-carousel-track');
  const cards = [...track.children];
  const controls = carousel.querySelector('.core-carousel-controls');
  const rotation = carousel.querySelector('[data-carousel-rotation]');
  const count = carousel.querySelector('[data-carousel-count]');
  const announcement = carousel.querySelector('[data-carousel-announcement]');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let columns = 1;
  let start = 0;
  let timer;
  let paused = reducedMotion.matches;
  let inView = false;
  let hovered = false;
  let touch;
  let suppressSwipeClick = false;

  const stop = () => { window.clearTimeout(timer); timer = undefined; };
  const schedule = () => {
    stop();
    if (paused || !inView || hovered || document.hidden || carousel.contains(document.activeElement)) return;
    timer = window.setTimeout(() => move(1, false), 6000);
  };
  const render = (manual = false) => {
    const end = Math.min(start + columns, cards.length);
    track.style.transform = `translateX(-${start * 100 / columns}%)`;
    cards.forEach((card, index) => {
      const visible = index >= start && index < end;
      card.inert = !visible;
      if (visible) card.removeAttribute('aria-hidden');
      else card.setAttribute('aria-hidden', 'true');
      card.toggleAttribute('data-first', index === start);
    });
    const message = `Applications ${start + 1}–${end} of ${cards.length}`;
    count.textContent = `${start + 1}–${end} / ${cards.length}`;
    count.setAttribute('aria-label', message);
    if (manual) announcement.textContent = message;
    rotation.textContent = paused ? 'Start rotation' : 'Pause rotation';
    carousel.dataset.rotation = paused ? 'paused' : 'playing';
    carousel.dataset.start = String(start);
    schedule();
  };
  const move = (direction, manual = true) => {
    const pages = Math.ceil(cards.length / columns);
    const nextPage = (Math.floor(start / columns) + direction + pages) % pages;
    start = nextPage * columns;
    render(manual);
  };
  const resize = () => {
    const next = Number.parseInt(getComputedStyle(carousel).getPropertyValue('--carousel-columns'), 10) || 1;
    if (columns !== next) {
      columns = next;
      // Keep a keyboard-focused card on screen when the layout changes.
      const focused = cards.findIndex(card => card.contains(document.activeElement));
      start = Math.floor((focused < 0 ? start : focused) / columns) * columns;
    }
    render();
  };

  carousel.setAttribute('aria-roledescription', 'carousel');
  carousel.dataset.enhanced = '';
  controls.hidden = false;
  carousel.querySelector('[data-carousel-previous]').addEventListener('click', () => move(-1));
  carousel.querySelector('[data-carousel-next]').addEventListener('click', () => move(1));
  rotation.addEventListener('click', () => { paused = !paused; render(); });
  carousel.addEventListener('focusin', stop);
  carousel.addEventListener('focusout', () => window.setTimeout(schedule, 0));
  carousel.addEventListener('pointerenter', event => { if (event.pointerType !== 'touch') { hovered = true; stop(); } });
  carousel.addEventListener('pointerleave', event => { if (event.pointerType !== 'touch') { hovered = false; schedule(); } });
  const viewport = carousel.querySelector('.core-carousel-viewport');
  viewport.addEventListener('pointerdown', event => {
    if (event.pointerType === 'touch') { suppressSwipeClick = false; touch = { x: event.clientX, y: event.clientY }; stop(); }
  });
  viewport.addEventListener('pointerup', event => {
    if (!touch) return;
    const dx = event.clientX - touch.x;
    const dy = event.clientY - touch.y;
    touch = undefined;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) {
      suppressSwipeClick = true;
      move(dx < 0 ? 1 : -1);
      window.setTimeout(() => { suppressSwipeClick = false; }, 400);
    } else schedule();
  });
  viewport.addEventListener('click', event => {
    if (!suppressSwipeClick) return;
    event.preventDefault();
    event.stopPropagation();
    suppressSwipeClick = false;
  }, true);
  viewport.addEventListener('pointercancel', () => { touch = undefined; schedule(); });
  document.addEventListener('visibilitychange', schedule);
  reducedMotion.addEventListener('change', event => {
    if (event.matches) paused = true;
    render();
  });
  new IntersectionObserver(entries => {
    inView = entries[0].isIntersecting;
    schedule();
  }, { threshold: .25 }).observe(carousel);
  new ResizeObserver(resize).observe(carousel);
  resize();
})();
