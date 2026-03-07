import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

// ── State ────────────────────────────────────────────────────────────────────
let allResults = [];

// ── DOM refs ─────────────────────────────────────────────────────────────────
const dropZone      = document.getElementById('drop-zone');
const btnOpenFiles  = document.getElementById('btn-open-files');
const btnOpenFolder = document.getElementById('btn-open-folder');
const statusBar     = document.getElementById('status-bar');
const statusText    = document.getElementById('status-text');
const spinner       = document.getElementById('spinner');
const resultsSection   = document.getElementById('results-section');
const resultsContainer = document.getElementById('results-container');
const btnSave  = document.getElementById('btn-save');
const btnClear = document.getElementById('btn-clear');

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatBytes(n) {
  if (n === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(n) / Math.log(k));
  return (n / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1) + ' ' + sizes[i];
}

function confClass(c) {
  if (c >= 0.75) return 'high';
  if (c >= 0.45) return 'mid';
  return 'low';
}

function pct(c) { return Math.round(c * 100); }

function fileIcon(ext, finalType) {
  const e = (ext || '').toLowerCase();
  const t = (finalType || '').toLowerCase();
  if (['jpg','jpeg','png','gif','bmp','webp','tiff','svg','ico','psd'].includes(e) || t.includes('image')) return '🖼️';
  if (['mp4','mkv','avi','mov','flv','wmv'].includes(e) || t.includes('video')) return '🎬';
  if (['mp3','flac','ogg','wav','aac','m4a'].includes(e) || t.includes('audio')) return '🎵';
  if (['zip','rar','7z','gz','bz2','xz','tar'].includes(e) || t.includes('archive') || t.includes('compress')) return '📦';
  if (['pdf'].includes(e) || t.includes('pdf')) return '📄';
  if (['doc','docx','odt'].includes(e)) return '📝';
  if (['xls','xlsx','ods','csv'].includes(e)) return '📊';
  if (['ppt','pptx','odp'].includes(e)) return '📋';
  if (['exe','elf','dll','so','dylib'].includes(e) || t.includes('execut')) return '⚙️';
  if (['rs','py','js','ts','c','cpp','java','go','rb','sh','php'].includes(e)) return '💻';
  if (['html','htm','xml','json','yaml','toml','md'].includes(e)) return '🌐';
  if (t.includes('text') || t.includes('ascii')) return '📃';
  return '📁';
}

// ── Status bar ───────────────────────────────────────────────────────────────

function showStatus(msg, loading = false) {
  statusBar.classList.remove('hidden');
  statusText.textContent = msg;
  loading ? spinner.classList.remove('hidden') : spinner.classList.add('hidden');
}

function hideStatus() { statusBar.classList.add('hidden'); }

// ── Analyse files ─────────────────────────────────────────────────────────────

async function runAnalysis(paths) {
  if (!paths || paths.length === 0) return;

  showStatus(`Analysing ${paths.length} file(s)…`, true);
  btnOpenFiles.disabled = true;
  btnOpenFolder.disabled = true;

  try {
    const results = await invoke('analyse_files', { paths });
    allResults = [...allResults, ...results];
    renderResults();
    showStatus(`Analysis complete — ${results.length} file(s) processed.`, false);
  } catch (err) {
    showStatus(`Error: ${err}`, false);
  } finally {
    btnOpenFiles.disabled = false;
    btnOpenFolder.disabled = false;
  }
}

// ── Render ───────────────────────────────────────────────────────────────────

function renderResults() {
  resultsSection.classList.remove('hidden');
  resultsContainer.innerHTML = '';

  for (const result of allResults) {
    resultsContainer.appendChild(buildCard(result));
  }
}

function buildCard(r) {
  const conf   = r.overall_confidence;
  const cls    = confClass(conf);
  const icon   = fileIcon(r.extension, r.final_type);

  const card = document.createElement('div');
  card.className = 'result-card';

  // ── Header ──────────────────────────────────────────────────
  const header = document.createElement('div');
  header.className = 'card-header';
  header.innerHTML = `
    <div class="card-icon">${icon}</div>
    <div class="card-meta">
      <div class="card-filename">${esc(r.file_name)}</div>
      <div class="card-path">${esc(r.file_path)}</div>
      <div class="card-badges">
        <span class="badge badge-type">${esc(r.final_type)}</span>
        <span class="badge badge-size">${formatBytes(r.file_size)}</span>
        ${r.extension ? `<span class="badge badge-ext">.${esc(r.extension)}</span>` : ''}
      </div>
    </div>`;
  card.appendChild(header);

  // ── Confidence bar ───────────────────────────────────────────
  const confRow = document.createElement('div');
  confRow.className = 'confidence-row';
  confRow.innerHTML = `
    <span class="confidence-label">Overall certainty</span>
    <div class="confidence-bar-wrap">
      <div class="confidence-bar bar-${cls}" style="width:${pct(conf)}%"></div>
    </div>
    <span class="confidence-pct conf-${cls}">${pct(conf)}%</span>`;
  card.appendChild(confRow);

  // ── Description ──────────────────────────────────────────────
  if (r.final_type_description) {
    const desc = document.createElement('div');
    desc.className = 'card-description';
    desc.textContent = r.final_type_description;
    card.appendChild(desc);
  }

  // ── Error ─────────────────────────────────────────────────────
  if (r.error) {
    const errDiv = document.createElement('div');
    errDiv.className = 'card-error';
    errDiv.textContent = `⚠ ${r.error}`;
    card.appendChild(errDiv);
  }

  // ── Methods accordion ────────────────────────────────────────
  if (r.methods && r.methods.length > 0) {
    const toggle = document.createElement('button');
    toggle.className = 'methods-toggle';
    toggle.innerHTML = `<span class="toggle-arrow">▶</span> Show analysis method details (${r.methods.length})`;

    const list = document.createElement('div');
    list.className = 'methods-list';

    for (const m of r.methods) {
      list.appendChild(buildMethodItem(m));
    }

    toggle.addEventListener('click', () => {
      const arrow = toggle.querySelector('.toggle-arrow');
      list.classList.toggle('open');
      arrow.classList.toggle('open');
      toggle.innerHTML = list.classList.contains('open')
        ? `<span class="toggle-arrow open">▶</span> Hide analysis method details (${r.methods.length})`
        : `<span class="toggle-arrow">▶</span> Show analysis method details (${r.methods.length})`;
    });

    card.appendChild(toggle);
    card.appendChild(list);
  }

  return card;
}

function buildMethodItem(m) {
  const cls = confClass(m.confidence);
  const div = document.createElement('div');
  div.className = 'method-item';

  const header = document.createElement('div');
  header.className = 'method-header';
  header.innerHTML = `
    <span class="method-name">${esc(m.method_name)}</span>
    <span class="method-conf-pill conf-${cls}" style="background:${pillBg(cls)}">
      ${pct(m.confidence)}% confidence
    </span>`;
  div.appendChild(header);

  const body = document.createElement('div');
  body.className = 'method-body';

  if (m.reason) {
    const reason = document.createElement('p');
    reason.className = 'method-reason';
    reason.textContent = m.reason;
    body.appendChild(reason);
  }

  if (m.proposals && m.proposals.length > 0) {
    const ul = document.createElement('ul');
    ul.className = 'proposals-list';
    for (const p of m.proposals) {
      const pcls = confClass(p.confidence);
      const li = document.createElement('li');
      li.className = 'proposal-item';
      li.innerHTML = `
        <span class="proposal-type">${esc(p.type_name)}</span>
        <div class="proposal-bar-wrap">
          <div class="proposal-bar bar-${pcls}" style="width:${pct(p.confidence)}%"></div>
        </div>
        <span class="proposal-pct conf-${pcls}">${pct(p.confidence)}%</span>
        <span class="proposal-desc">${esc(p.description)}</span>`;
      ul.appendChild(li);
    }
    body.appendChild(ul);
  }

  div.appendChild(body);
  return div;
}

function pillBg(cls) {
  if (cls === 'high') return '#0e2f25';
  if (cls === 'mid')  return '#2e2810';
  return '#2a1212';
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Save results ─────────────────────────────────────────────────────────────

async function saveResults() {
  if (allResults.length === 0) { showStatus('No results to save.'); return; }

  try {
    const [localTs, utcTs] = await invoke('current_timestamps');
    const savePath = await invoke('pick_save_path');
    if (!savePath) return;

    const lines = [];
    lines.push('================================================');
    lines.push('  FILE TYPE ANALYSER — ANALYSIS REPORT');
    lines.push('================================================');
    lines.push(`Saved (local):  ${localTs}`);
    lines.push(`Saved (UTC):    ${utcTs}`);
    lines.push(`Files analysed: ${allResults.length}`);
    lines.push('');

    for (const r of allResults) {
      lines.push('------------------------------------------------');
      lines.push(`FILE: ${r.file_name}`);
      lines.push(`PATH: ${r.file_path}`);
      lines.push(`SIZE: ${formatBytes(r.file_size)}`);
      lines.push(`EXTENSION: ${r.extension || '(none)'}`);
      lines.push('');
      lines.push(`FINAL TYPE:        ${r.final_type}`);
      lines.push(`OVERALL CERTAINTY: ${pct(r.overall_confidence)}%`);
      lines.push(`DESCRIPTION:`);
      lines.push(`  ${r.final_type_description}`);
      lines.push('');

      if (r.error) {
        lines.push(`ERROR: ${r.error}`);
        lines.push('');
      }

      if (r.methods && r.methods.length > 0) {
        lines.push('ANALYSIS METHODS:');
        for (const m of r.methods) {
          lines.push('');
          lines.push(`  [${m.method_name}]`);
          lines.push(`  Method confidence: ${pct(m.confidence)}%`);
          lines.push(`  Reason: ${m.reason}`);
          if (m.proposals && m.proposals.length > 0) {
            lines.push('  Proposals:');
            for (const p of m.proposals) {
              lines.push(`    - ${p.type_name} (${pct(p.confidence)}%): ${p.description}`);
            }
          }
        }
      }
      lines.push('');
    }

    lines.push('================================================');
    lines.push(`END OF REPORT — ${localTs}  |  ${utcTs}`);
    lines.push('================================================');

    const content = lines.join('\n');
    await invoke('save_results', { path: savePath, content });
    showStatus(`Results saved to: ${savePath}`);
  } catch (err) {
    showStatus(`Save failed: ${err}`);
  }
}

// ── Drag and drop (Tauri v2 native events) ──────────────────────────────────

// Visual feedback while dragging
await listen('tauri://drag', () => {
  dropZone.classList.add('drag-over');
});
await listen('tauri://drag-cancelled', () => {
  dropZone.classList.remove('drag-over');
});

// Files dropped
await listen('tauri://drop', async (event) => {
  dropZone.classList.remove('drag-over');
  const paths = event.payload?.paths ?? [];
  if (paths.length > 0) {
    await runAnalysis(paths);
  }
});

// ── Button handlers ──────────────────────────────────────────────────────────

btnOpenFiles.addEventListener('click', async () => {
  try {
    const paths = await invoke('pick_files');
    if (paths && paths.length > 0) await runAnalysis(paths);
  } catch (err) {
    showStatus(`Error opening files: ${err}`);
  }
});

btnOpenFolder.addEventListener('click', async () => {
  try {
    showStatus('Collecting files from folder…', true);
    const paths = await invoke('pick_folder');
    hideStatus();
    if (paths && paths.length > 0) {
      await runAnalysis(paths);
    } else {
      showStatus('No files found in the selected folder, or selection was cancelled.');
    }
  } catch (err) {
    showStatus(`Error opening folder: ${err}`);
  }
});

btnSave.addEventListener('click', saveResults);

btnClear.addEventListener('click', () => {
  allResults = [];
  resultsContainer.innerHTML = '';
  resultsSection.classList.add('hidden');
  hideStatus();
});
