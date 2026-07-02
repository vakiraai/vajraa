/* Vajraa Docs — shared JS */
(function () {
  // ── Back-to-top button ──
  const btn = document.getElementById('back-to-top');
  if (btn) {
    window.addEventListener('scroll', () => {
      btn.classList.toggle('visible', window.scrollY > 400);
    });
    btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }

  // ── Highlight active sidebar link ──
  const links = document.querySelectorAll('.sidebar-link');
  links.forEach(l => {
    if (l.href === location.href ||
        l.getAttribute('href') === location.pathname.split('/').pop()) {
      l.classList.add('active');
    }
  });

  // ── Search ──
  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.trim().toLowerCase();
      // Remove existing marks
      document.querySelectorAll('mark').forEach(m => {
        m.replaceWith(document.createTextNode(m.textContent));
      });
      if (q.length < 2) return;
      // Walk text nodes and mark matches
      walk(document.querySelector('.main'), q);
    });
  }

  function walk(node, q) {
    if (!node) return;
    if (node.nodeType === 3) { // text node
      const text = node.textContent;
      const idx = text.toLowerCase().indexOf(q);
      if (idx === -1) return;
      const before = document.createTextNode(text.slice(0, idx));
      const mark = document.createElement('mark');
      mark.textContent = text.slice(idx, idx + q.length);
      const after = document.createTextNode(text.slice(idx + q.length));
      const parent = node.parentNode;
      parent.insertBefore(before, node);
      parent.insertBefore(mark, node);
      parent.insertBefore(after, node);
      parent.removeChild(node);
    } else if (!['SCRIPT', 'STYLE', 'CODE', 'PRE'].includes(node.tagName)) {
      [...node.childNodes].forEach(child => walk(child, q));
    }
  }

  // ── Smooth anchor headings ──
  document.querySelectorAll('h2[id], h3[id]').forEach(h => {
    const anchor = document.createElement('a');
    anchor.href = '#' + h.id;
    anchor.className = 'anchor';
    anchor.textContent = '#';
    h.appendChild(anchor);
  });
})();
