/* TrustVault — Client-side interactions */
"use strict";

// ─── Sidebar Toggle (Mobile) ──────────────────────────────────────────────────
const sidebarToggle  = document.getElementById('sidebar-toggle');
const sidebar        = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebar-overlay');

function openSidebar() {
  sidebar && sidebar.classList.add('open');
  sidebarOverlay && sidebarOverlay.classList.add('show');
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  sidebar && sidebar.classList.remove('open');
  sidebarOverlay && sidebarOverlay.classList.remove('show');
  document.body.style.overflow = '';
}

sidebarToggle  && sidebarToggle.addEventListener('click', openSidebar);
sidebarOverlay && sidebarOverlay.addEventListener('click', closeSidebar);

// Close sidebar on ESC
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeSidebar();
});

// ─── Password visibility toggle ───────────────────────────────────────────────
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

// ─── Password Strength Meter ──────────────────────────────────────────────────
function checkPasswordStrength(value) {
  const bar    = document.getElementById('pwd-strength');
  const fill   = document.getElementById('strength-fill');
  const label  = document.getElementById('strength-label');
  if (!bar || !fill || !label) return;

  if (!value) { bar.style.display = 'none'; return; }
  bar.style.display = 'flex';

  let score = 0;
  if (value.length >= 8)              score++;
  if (value.length >= 12)             score++;
  if (/[A-Z]/.test(value))           score++;
  if (/[0-9]/.test(value))           score++;
  if (/[^A-Za-z0-9]/.test(value))   score++;

  const levels = [
    { pct: '20%', color: '#ef4444', text: 'Very weak' },
    { pct: '40%', color: '#f97316', text: 'Weak' },
    { pct: '60%', color: '#f59e0b', text: 'Fair' },
    { pct: '80%', color: '#22c55e', text: 'Strong' },
    { pct: '100%',color: '#06b6d4', text: 'Very strong' },
  ];
  const lvl = levels[Math.min(score - 1, 4)] || levels[0];
  fill.style.width     = lvl.pct;
  fill.style.background = lvl.color;
  label.textContent    = lvl.text;
  label.style.color    = lvl.color;
}

// ─── Form submit spinner ──────────────────────────────────────────────────────
function setupSubmitSpinner(formId, btnId) {
  const form = document.getElementById(formId);
  const btn  = document.getElementById(btnId);
  if (!form || !btn) return;

  form.addEventListener('submit', () => {
    const textEl    = btn.querySelector('.btn-text');
    const spinnerEl = btn.querySelector('.btn-spinner');
    if (textEl)    textEl.style.opacity = '0';
    if (spinnerEl) spinnerEl.classList.remove('hidden');
    btn.disabled = true;
  });
}

setupSubmitSpinner('login-form',    'login-submit-btn');
setupSubmitSpinner('register-form', 'register-submit-btn');
setupSubmitSpinner('upload-form',   'upload-submit-btn');

// ─── Textarea character counter ───────────────────────────────────────────────
const descTextarea = document.getElementById('description');
const descCount    = document.getElementById('desc-count');
if (descTextarea && descCount) {
  descTextarea.addEventListener('input', () => {
    descCount.textContent = descTextarea.value.length;
  });
}

// ─── Drag & Drop Upload ───────────────────────────────────────────────────────
const dropZone   = document.getElementById('drop-zone');
const fileInput  = document.getElementById('file-input');
const submitBtn  = document.getElementById('upload-submit-btn');

function formatBytes(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1_048_576)   return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(2)} MB`;
}

function onFileSelected(input) {
  const file = input.files[0];
  if (!file) return;

  const idleEl    = document.getElementById('drop-zone-idle');
  const selectedEl = document.getElementById('drop-zone-selected');
  const nameEl    = document.getElementById('selected-file-name');
  const sizeEl    = document.getElementById('selected-file-size');

  if (idleEl)    idleEl.classList.add('hidden');
  if (selectedEl) selectedEl.classList.remove('hidden');
  if (nameEl)    nameEl.textContent = file.name;
  if (sizeEl)    sizeEl.textContent = formatBytes(file.size);
  if (submitBtn) submitBtn.disabled = false;

  // Update file icon
  const ext = file.name.split('.').pop().toLowerCase();
  const iconEl = document.querySelector('#drop-zone-selected .selected-file-icon');
  if (iconEl) iconEl.textContent = getFileEmoji(ext);
}

if (dropZone) {
  ['dragenter', 'dragover'].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });
  dropZone.addEventListener('drop', e => {
    const file = e.dataTransfer.files[0];
    if (!file || !fileInput) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    onFileSelected(fileInput);
  });
}

// ─── File emoji helper ────────────────────────────────────────────────────────
function getFileEmoji(ext) {
  const map = {
    pdf: '📕', doc: '📝', docx: '📝', txt: '📄', md: '📄',
    xls: '📊', xlsx: '📊', csv: '📊',
    ppt: '📊', pptx: '📊',
    jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
    mp4: '🎬', mov: '🎬', avi: '🎬', mkv: '🎬',
    mp3: '🎵', wav: '🎵', flac: '🎵',
    zip: '🗜️', rar: '🗜️', '7z': '🗜️', tar: '🗜️',
    py: '🐍', js: '📜', ts: '📜', html: '🌐', css: '🎨',
    json: '🔧', yml: '🔧', yaml: '🔧',
  };
  return map[ext] || '📄';
}

// Apply file emoji to all .file-icon elements in tables
document.querySelectorAll('.file-icon[data-ext]').forEach(el => {
  el.textContent = getFileEmoji(el.dataset.ext);
});

// ─── Table search / filter ────────────────────────────────────────────────────
function filterTable(tableId, query) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const q = query.toLowerCase().trim();
  table.querySelectorAll('.table-row').forEach(row => {
    const text = (row.dataset.search || row.textContent).toLowerCase();
    row.style.display = (!q || text.includes(q)) ? '' : 'none';
  });
}

// ─── Auto-dismiss flash messages (after 6 s) ─────────────────────────────────
document.querySelectorAll('.flash').forEach(flash => {
  setTimeout(() => {
    flash.style.transition = 'opacity .4s';
    flash.style.opacity = '0';
    setTimeout(() => flash.remove(), 450);
  }, 6000);
});

// ─── Permission level card: highlight selected ────────────────────────────────
document.querySelectorAll('.perm-level-option input[type=radio]').forEach(radio => {
  radio.addEventListener('change', () => {
    document.querySelectorAll('.perm-level-card').forEach(c => c.style.pointerEvents = '');
  });
});
