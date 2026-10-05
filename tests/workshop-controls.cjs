// Exercise the actual workshop controller without executing any archived lab code.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const script = fs.readFileSync(path.join(__dirname, '../assets/js/workshop.js'), 'utf8');
const events = {};
const buttons = {};
const tasks = [
  { open: false, parentElement: { closest: () => null } },
  { open: false, parentElement: { closest: () => null } },
];
let scrolls = 0;
const target = { closest: () => tasks[1], scrollIntoView: () => { scrolls++; } };
const controls = {
  hidden: true,
  querySelector: selector => ({ addEventListener: (_, fn) => { buttons[selector] = fn; } }),
};
const window = {
  location: { hash: '#disk' },
  addEventListener: (name, fn) => { events[name] = fn; },
};
const document = {
  querySelectorAll: () => tasks,
  getElementById: id => id === 'disk' ? target : null,
  querySelector: selector => selector === '.workshop-task-controls' ? controls : {
    addEventListener: (name, fn) => { events[`toc-${name}`] = fn; },
  },
};
vm.runInNewContext(script, { document, window });
assert.equal(controls.hidden, false);
assert.deepEqual(tasks.map(task => task.open), [false, true], 'Initial deep link opens only its task');
buttons['[data-workshop-expand]']();
assert.ok(tasks.every(task => task.open));
buttons['[data-workshop-collapse]']();
assert.ok(tasks.every(task => !task.open));
events['toc-click']({ target: { closest: () => ({ getAttribute: () => '#disk' }) } });
assert.equal(tasks[1].open, true, 'Clicking the current fragment reopens a collapsed task');
tasks[1].open = false;
events.hashchange();
assert.equal(tasks[1].open, true);
assert.equal(scrolls, 3);
for (const hash of ['#missing', '#%ZZ', '']) {
  window.location.hash = hash;
  assert.doesNotThrow(() => events.hashchange());
}
assert.equal(scrolls, 3, 'Invalid fragments leave the page position alone');
