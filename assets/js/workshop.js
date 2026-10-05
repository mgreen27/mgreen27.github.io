(() => {
  const tasks = document.querySelectorAll('.workshop-task');
  const controls = document.querySelector('.workshop-task-controls');
  if (!tasks.length) return;

  if (controls) {
    controls.hidden = false;
    controls.querySelector('[data-workshop-expand]').addEventListener('click', () => {
      tasks.forEach(task => { task.open = true; });
    });
    controls.querySelector('[data-workshop-collapse]').addEventListener('click', () => {
      tasks.forEach(task => { task.open = false; });
    });
  }

  function revealFragment(hash) {
    let id;
    try { id = decodeURIComponent(hash.slice(1)); } catch { return; }
    const target = document.getElementById(id);
    if (!target) return;
    for (let ancestor = target.closest('details'); ancestor;
      ancestor = ancestor.parentElement?.closest('details')) {
      ancestor.open = true;
    }
    target.scrollIntoView({ block: 'start' });
  }

  window.addEventListener('hashchange', () => revealFragment(window.location.hash));
  // Also handle clicking the current hash after its task has been collapsed.
  document.querySelector('.workshop-toc')?.addEventListener('click', event => {
    const link = event.target.closest('a[href^="#"]');
    if (link) revealFragment(link.getAttribute('href'));
  });
  revealFragment(window.location.hash);
})();
