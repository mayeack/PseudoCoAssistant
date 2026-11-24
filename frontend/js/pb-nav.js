// PatchBot / Change Board header: the page title is a <details> dropdown that
// switches between PatchBot, Change Board and Chat. Close it on an outside
// click or Escape; the open/close itself is the browser's.
(() => {
  const menus = Array.from(document.querySelectorAll('details.pb-switch'));
  document.addEventListener('click', (e) => {
    menus.forEach((d) => { if (d.open && !d.contains(e.target)) d.open = false; });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    menus.forEach((d) => {
      if (!d.open) return;
      d.open = false;
      d.querySelector('summary').focus();
    });
  });
})();
