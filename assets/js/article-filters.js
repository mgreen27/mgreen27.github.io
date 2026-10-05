(() => {
  const controls = document.querySelector('.article-filters');
  if (!controls) return;
  const entries = [...document.querySelectorAll('.list-container [data-article-tags]')];
  const buttons = [...controls.querySelectorAll('[data-topic]')];
  const status = document.querySelector('.filter-status');
  const topics = {
    all: null,
    dfir: ['dfir'],
    malware: ['malware'],
    'threat-intel': ['cti', 'threat intelligence', 'threat intel'],
    velociraptor: ['velociraptor'],
    ai: ['ai']
  };
  function applyFilter(topic) {
    if (!Object.hasOwn(topics, topic)) topic = 'all';
    let count = 0;
    for (const entry of entries) {
      const tags = entry.dataset.articleTags.split('|');
      const visible = topic === 'all' || topics[topic].some(tag => tags.includes(tag));
      entry.hidden = !visible;
      if (visible) count++;
    }
    for (const button of buttons) {
      button.setAttribute('aria-pressed', String(button.dataset.topic === topic));
    }
    const label = buttons.find(button => button.dataset.topic === topic).textContent;
    status.textContent = `${count} ${count === 1 ? 'article' : 'articles'}${topic === 'all' ? '' : ` · ${label}`}`;
  }
  controls.hidden = false;
  status.hidden = false;
  controls.addEventListener('click', event => {
    const button = event.target.closest('button[data-topic]');
    if (!button) return;
    const topic = button.dataset.topic;
    const url = new URL(window.location.href);
    if (topic === 'all') url.searchParams.delete('topic');
    else url.searchParams.set('topic', topic);
    window.history.pushState(null, '', url);
    applyFilter(topic);
  });
  const restore = () => applyFilter(new URL(window.location.href).searchParams.get('topic') || 'all');
  window.addEventListener('popstate', restore);
  restore();
})();
