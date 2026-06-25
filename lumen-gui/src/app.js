// ============================================================
// Lumen — app.js
// ============================================================

// ----- State -----
let lastScanResult = null;
let lastFilePath = null;
let allSignatures = [];
let lastBatchFolder = null;  // track folder for batch→hex navigation

// ----- Tab switching -----
const tabs = document.querySelectorAll('.tab[data-tab]');
tabs.forEach(tab => {
  tab.addEventListener('click', (e) => {
    e.preventDefault();
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(tc => tc.style.display = 'none');
    const target = document.getElementById('tab-' + tab.dataset.tab);
    if (target) {
      target.style.display = 'grid';
      if (tab.dataset.tab === 'db') refreshDbView();
      if (tab.dataset.tab === 'hex' && lastScanResult) renderHexTab();
      if (tab.dataset.tab === 'cli') { $('#cli-input')?.focus(); initCli(); }
    }
  });
});
document.querySelectorAll('.tab-content').forEach((el, i) => {
  el.style.display = i === 0 ? 'grid' : 'none';
});

// ----- Helpers -----
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function fmtSize(bytes) {
  if (!bytes && bytes !== 0) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function hexToBytes(hexStr) {
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substring(i, i + 2), 16));
  }
  return bytes;
}

function bytesToAscii(bytes) {
  return bytes.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
}

function escHtml(s) {
  const el = document.createElement('span');
  el.textContent = String(s);
  return el.innerHTML;
}

// ----- Tauri IPC wrapper -----
async function invokeTauri(cmd, args = {}) {
  if (window.__TAURI_INTERNALS__) {
    const { invoke } = window.__TAURI_INTERNALS__;
    return await invoke(cmd, args);
  }
  console.warn('Tauri unavailable — cmd:', cmd);
  return null;
}

// ----- Native file/folder picker (via rfd on Rust side) -----
async function pickFile() {
  try {
    const result = await invokeTauri('pick_file');
    return result || null;
  } catch (err) {
    if (err === 'cancelled') return null;
    console.error('pick_file error:', err);
    return null;
  }
}

async function pickFolder() {
  try {
    const result = await invokeTauri('pick_folder');
    return result || null;
  } catch (err) {
    if (err === 'cancelled') return null;
    console.error('pick_folder error:', err);
    return null;
  }
}

// ============================================================
// SCAN
// ============================================================
async function doScan(filePath, mode, segmentCount) {
  lastFilePath = filePath;
  $('#progress-wrap').style.display = 'flex';
  $('#progress-fill').style.width = '20%';
  $('#progress-text').textContent = 'reading...';
  $('#segment-map').style.display = 'none';
  $('#btn-scan-inspect-hex').style.display = 'none';
  $('#result-tree').innerHTML = '<span class="muted">Scanning...</span>';

  try {
    if (!filePath) {
      $('#result-tree').innerHTML = '<span class="keyword">No file path — dialog cancelled</span>';
      $('#progress-wrap').style.display = 'none';
      return;
    }
    $('#progress-text').textContent = 'calling engine...';
    $('#loading-overlay').style.display = 'flex';
    $('#loading-overlay .loading-spinner span').textContent = 'Scanning...';
    const nSegs = parseInt(segmentCount) || 8;
    const deep = $('#deep-scan').checked;
    let raw;
    try {
      raw = await invokeTauri('scan_file', { path: filePath, mode, segments: nSegs, deepScan: deep });
      if (!raw) {
        $('#result-tree').innerHTML = '<span class="muted">Engine unavailable. Is Tauri running?</span>';
        $('#progress-wrap').style.display = 'none';
        return;
      }
    } finally {
      $('#loading-overlay').style.display = 'none';
    }
    const data = JSON.parse(raw);
    lastScanResult = data;

    $('#progress-fill').style.width = '80%';
    $('#progress-text').textContent = 'parsing...';

    updateScanUI(data, filePath);
    updateHexPreview(filePath, data);
    $('#btn-rescan').disabled = false;
    $('#btn-rescan').dataset.lastFile = filePath;
    // Show Inspect in Hex button after scan
    $('#btn-scan-inspect-hex').style.display = 'block';
    $('#btn-scan-inspect-hex').disabled = false;
    $('#btn-scan-inspect-hex').dataset.targetPath = filePath;

    $('#progress-fill').style.width = '100%';
    $('#progress-text').textContent = 'done';
    setTimeout(() => { $('#progress-wrap').style.display = 'none'; }, 1200);

  } catch (err) {
    console.error('Scan error:', err);
    $('#result-tree').innerHTML = `<span class="keyword">Error: ${escHtml(err)}</span>`;
    $('#progress-wrap').style.display = 'none';
  }
}

function updateScanUI(data, filePath) {
  const fname = filePath.split(/[\\/]/).pop();
  $('#scan-filename').textContent = fname;
  $('#scan-filesize').textContent = fmtSize(data.total_size);
  $('#scan-sig').textContent = data.combined.file_type;

  const tree = $('#result-tree');
  tree.innerHTML = '';
  if (data.segments.length === 1) {
    renderResultTree(data.segments[0].result, tree);
  } else {
    renderResultTree(data.combined, tree);
    data.segments.forEach(seg => renderResultTree(seg.result, tree, 1));
  }

  if (data.segments.length > 1) renderSegmentMap(data.segments);

  $('#status-file-info').textContent = data.segments.length > 1
    ? `${data.segments.length} segments`
    : data.combined.file_type;
}

function renderResultTree(result, container, depth = 0) {
  if (!result) return;
  const div = document.createElement('div');
  div.className = 'result-item';
  if (depth > 0) div.style.paddingLeft = (depth * 18) + 'px';

  // Choose icon based on type
  let iconHtml;
  if (result.file_type === 'Folder') {
    iconHtml = '<i class="fas fa-folder-open" style="color:var(--accent-4);"></i>';
  } else if (result.file_type === 'Unknown') {
    iconHtml = '<i class="fas fa-question-circle"></i>';
  } else if (result.mime && result.mime.startsWith('image/')) {
    iconHtml = '<i class="fas fa-file-image"></i>';
  } else if (result.mime && result.mime.startsWith('audio/')) {
    iconHtml = '<i class="fas fa-file-audio"></i>';
  } else if (result.mime && result.mime.startsWith('video/')) {
    iconHtml = '<i class="fas fa-file-video"></i>';
  } else if (result.extension === '.zip' || result.extension === '.rar' || result.extension === '.7z' || result.extension === '.tar' || result.extension === '.gz') {
    iconHtml = '<i class="fas fa-file-archive"></i>';
  } else if (result.mime && (result.mime.startsWith('text/') || result.mime === 'application/json' || result.mime === 'application/xml')) {
    iconHtml = '<i class="fas fa-file-code"></i>';
  } else if (result.extension === '.exe' || result.extension === '.dll' || result.file_type.includes('ELF') || result.file_type.includes('Mach-O')) {
    iconHtml = '<i class="fas fa-file-code"></i>';
  } else {
    iconHtml = '<i class="fas fa-file"></i>';
  }

  let html;
  if (result.file_type === 'Folder') {
    html = `<span class="result-type"><i class="fas fa-chevron-right" style="font-size:0.5rem;color:var(--muted);margin-right:2px;"></i> ${iconHtml} ${escHtml(result.inner_name || '')}/</span>`;
  } else {
    html = `<span class="result-type">${iconHtml} ${escHtml(result.file_type)}</span>`;
    if (result.inner_name) {
      html += ` <span class="result-mime">(${escHtml(result.inner_name)})</span>`;
    }
    if (result.has_password) {
      html += ` <i class="fas fa-lock" style="color:var(--accent-1);font-size:var(--text-xs);" title="Password protected"></i>`;
    } else if (result.extension === '.zip' || result.file_type.includes('ZIP') || result.file_type.includes('archive')) {
      html += ` <i class="fas fa-unlock" style="color:var(--accent-3);font-size:var(--text-xs);" title="Not encrypted"></i>`;
    }
    if (result.mime) html += ` <span class="result-mime">${escHtml(result.mime)}</span>`;
    if (result.extension) html += ` <span class="result-type"> (${escHtml(result.extension)})</span>`;
    if (result.compression) html += ` <span class="result-comp"> | ${escHtml(result.compression)}</span>`;
    html += ` <span class="muted" style="font-size:var(--text-xs)">@0x${result.offset.toString(16).toUpperCase()}</span>`;
    if (result.confidence > 0) html += ` <span class="muted" style="font-size:var(--text-xs)">${(result.confidence*100).toFixed(0)}%</span>`;
    if (result.header_hex) {
      const truncated = result.header_hex.length > 32 ? result.header_hex.substring(0, 32) + '…' : result.header_hex;
      html += `<br><span class="muted" style="font-size:0.55rem;"><i class="fas fa-file-signature"></i> Header: ${truncated}</span>`;
    }
  }

  div.innerHTML = html;
  container.appendChild(div);

  if (result.children && result.children.length > 0) {
    result.children.forEach(c => renderResultTree(c, container, depth + 1));
  }
}

function renderSegmentMap(segments) {
  const blocks = $('#segment-blocks');
  blocks.innerHTML = '';
  segments.forEach(seg => {
    const b = document.createElement('div');
    b.className = 'segment-block ' + (seg.result.file_type === 'Unknown' ? 'unknown' : 'known');
    b.title = `${seg.result.file_type} @ ${fmtSize(seg.offset)}–${fmtSize(seg.offset + seg.size)}`;
    b.textContent = seg.result.extension || seg.result.file_type.substring(0, 4);
    blocks.appendChild(b);
  });
  $('#segment-map').style.display = 'block';
}

async function updateHexPreview(filePath, data) {
  if (!$('#hex-preview-toggle').checked) return;
  try {
    const sigOffset = data.segments[0]?.result.offset || 0;
    const readOff = Math.max(0, sigOffset - 16);
    const hex = await invokeTauri('read_hex', { path: filePath, offset: readOff, len: 64 });
    if (!hex) return;
    const bytes = hexToBytes(hex);
    let rowHtml = '';
    for (let r = 0; r < 4; r++) {
      const off = readOff + r * 16;
      const rowBytes = bytes.slice(r * 16, r * 16 + 16);
      if (rowBytes.length === 0) break;
      const hexStr = rowBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      const ascii = bytesToAscii(rowBytes);
      rowHtml += `<div class="hex-row"><span class="hex-offset">${off.toString(16).padStart(6, '0').toUpperCase()}</span><span class="hex-bytes">${hexStr}</span><span class="hex-ascii">${ascii}</span></div>`;
    }
    $('#hex-preview-row').innerHTML = rowHtml;
  } catch (e) { /* ignore */ }
}

// ----- File selection (native dialog) -----
$('#btn-select-file')?.addEventListener('click', async () => {
  const filePath = await pickFile();
  if (!filePath) return;
  const mode = $('#scan-mode').value === 'segmented' ? 'segmented' : 'quick';
  const segs = $('#scan-segments').value;
  doScan(filePath, mode, segs);
});

$('#btn-rescan')?.addEventListener('click', () => {
  const lastFile = $('#btn-rescan').dataset.lastFile;
  if (lastFile) {
    const mode = $('#scan-mode').value === 'segmented' ? 'segmented' : 'quick';
    const segs = $('#scan-segments').value;
    doScan(lastFile, mode, segs);
  }
});

$('#btn-scan-inspect-hex')?.addEventListener('click', async () => {
  const path = $('#btn-scan-inspect-hex').dataset.targetPath;
  if (!path) return;
  lastFilePath = path;
  // lastScanResult already set from previous scan
  document.querySelector('.tab[data-tab="hex"]')?.click();
});

// Drag-drop — only works if the file path is available
const scanTab = document.getElementById('tab-scan');
scanTab?.addEventListener('dragover', (e) => { e.preventDefault(); });
scanTab?.addEventListener('drop', async (e) => {
  e.preventDefault();
  // ponytail: Tauri webview exposes file path on drop items
  // fallback: use first file's name (won't scan without full path)
  const file = e.dataTransfer.files[0];
  if (!file) return;
  // Tauri webview: file.path may be available
  const fpath = file.path;
  if (fpath) {
    const mode = $('#scan-mode').value === 'segmented' ? 'segmented' : 'quick';
    const segs = $('#scan-segments').value;
    doScan(fpath, mode, segs);
  } else {
    $('#result-tree').innerHTML = '<span class="keyword">Drag-drop needs full path. Use [Select File] instead.</span>';
  }
});

// ============================================================
// HEX INSPECTOR TAB
// ============================================================
function renderHexTab() {
  if (!lastScanResult && !lastFilePath) {
    $('#hex-full').innerHTML = '<span class="muted">Run a scan first, then switch to _hex tab</span>';
    return;
  }
  updateHexFileIndicator();
  loadHexView();
  loadSigList();
}

function updateHexFileIndicator() {
  let el = $('#hex-file-indicator');
  if (!el) {
    el = document.createElement('div');
    el.id = 'hex-file-indicator';
    el.className = 'hex-file-indicator';
    // Insert after panel-header in hex center panel
    const header = $('#tab-hex .panel-center .panel-header');
    if (header && header.nextSibling) {
      header.parentNode.insertBefore(el, header.nextSibling);
    } else {
      $('#tab-hex .panel-center .panel-body')?.before(el);
    }
  }
  if (lastFilePath) {
    const fname = lastFilePath.split(/[\\/]/).pop();
    el.innerHTML = `<i class="fas fa-file"></i> ${escHtml(fname)} <span class="muted">— ${escHtml(lastFilePath)}</span>`;
  } else {
    el.textContent = 'No file selected';
  }
}

let currentHighlightOffset = null;

async function loadHexView(highlightOffset) {
  if (!lastFilePath) return;
  currentHighlightOffset = highlightOffset;
  const hexFull = $('#hex-full');
  hexFull.innerHTML = '<span class="muted">Loading hex...</span>';

  try {
    // Calculate read window aligned to 16-byte boundary
    const viewLen = 512;
    let readStart = 0;
    if (highlightOffset !== undefined && highlightOffset !== null) {
      readStart = Math.floor(highlightOffset / 16) * 16;
      readStart = Math.max(0, readStart - Math.floor(viewLen / 4)); // some context before
      readStart = Math.floor(readStart / 16) * 16;
    }

    const hex = await invokeTauri('read_hex', { path: lastFilePath, offset: readStart, len: viewLen });
    if (!hex) { hexFull.innerHTML = '<span class="muted">Failed to read file</span>'; return; }

    const bytes = hexToBytes(hex);
    let html = '<div class="hex-table">';

    for (let r = 0; r < bytes.length; r += 16) {
      const rowBytes = bytes.slice(r, r + 16);
      const fileOffset = readStart + r;
      const offStr = fileOffset.toString(16).padStart(6, '0').toUpperCase();
      html += `<div class="hex-row" data-offset="${fileOffset}">`;
      html += `<span class="hex-offset">${offStr}</span>`;

      html += '<span class="hex-bytes">';
      for (let b = 0; b < 16; b++) {
        const byteOff = fileOffset + b;
        const byteVal = rowBytes[b];
        if (byteVal === undefined) {
          html += '<span class="hex-byte empty">  </span>';
        } else {
          const hexChar = byteVal.toString(16).padStart(2, '0').toUpperCase();
          let cssClass = 'hex-byte';
          if (highlightOffset !== undefined && highlightOffset !== null) {
            if (byteOff >= highlightOffset && byteOff < highlightOffset + 8) {
              cssClass += ' hex-highlight sakura';
            }
          } else if (lastScanResult) {
            for (const seg of lastScanResult.segments) {
              const sigStart = Number(seg.result.offset);
              if (byteOff >= sigStart && byteOff < sigStart + 8) {
                cssClass += ' hex-highlight sakura';
              }
            }
          }
          html += `<span class="${cssClass}">${hexChar}</span>`;
        }
        if (b === 7) html += ' ';
        html += ' ';
      }
      html += '</span>';

      html += '<span class="hex-ascii">';
      for (let b = 0; b < 16; b++) {
        const byteVal = rowBytes[b];
        if (byteVal === undefined) { html += ' '; }
        else { html += escHtml(bytesToAscii([byteVal])); }
        if (b === 7) html += ' ';
      }
      html += '</span></div>';
    }
    html += '</div>';
    html += `<div class="hex-nav" style="display:flex;gap:8px;margin-top:8px;font-size:var(--text-xs);align-items:center;border-top:1px solid var(--border-subtle);padding-top:6px;">
      <button class="btn" id="hex-prev-page" style="width:auto;padding:2px 10px;"><i class="fas fa-chevron-left"></i> Prev</button>
      <span class="muted">@ 0x${readStart.toString(16).padStart(6, '0').toUpperCase()}</span>
      <button class="btn" id="hex-next-page" style="width:auto;padding:2px 10px;">Next <i class="fas fa-chevron-right"></i></button>
    </div>`;
    hexFull.innerHTML = html;

    // Wire up pagination
    const pageSize = viewLen;
    $('#hex-prev-page')?.addEventListener('click', () => {
      const newOff = Math.max(0, readStart - pageSize);
      loadHexView(newOff);
    });
    $('#hex-next-page')?.addEventListener('click', () => {
      loadHexView(readStart + pageSize);
    });
  } catch (err) {
    hexFull.innerHTML = `<span class="keyword">Error: ${escHtml(err)}</span>`;
  }
}

async function loadSigList() {
  if (!lastScanResult) return;
  const sigList = $('#sig-list');
  sigList.innerHTML = '';

  const seen = new Set();
  const allSigs = [];

  function collectSigs(result) {
    if (!result || result.file_type === 'Unknown') return;
    const key = result.file_type + '@' + result.offset;
    if (!seen.has(key)) {
      seen.add(key);
      allSigs.push({ name: result.file_type, offset: result.offset });
    }
    if (result.children) result.children.forEach(collectSigs);
  }

  if (lastScanResult.segments) {
    lastScanResult.segments.forEach(seg => collectSigs(seg.result));
  }

  allSigs.forEach((sig, i) => {
    const div = document.createElement('div');
    div.className = 'sig-item';
    div.innerHTML = `▶ ${escHtml(sig.name)} <span class="muted" style="font-size:var(--text-xs)">@0x${sig.offset.toString(16).toUpperCase()}</span>`;
    div.addEventListener('click', () => {
      document.querySelectorAll('.sig-item').forEach(el => el.classList.remove('active'));
      div.classList.add('active');
      loadHexView(sig.offset);
      showHexDetails(sig.name);
    });
    sigList.appendChild(div);
  });

  if (allSigs.length === 0) {
    sigList.innerHTML = '<span class="muted">No signatures found</span>';
  }
}

function showHexDetails(name) {
  const details = $('#sig-details');
  const sig = allSignatures.find(s => s.name === name);
  if (sig) {
    details.innerHTML = `
      <div class="keyval"><span class="key">Name:</span><span class="val">${escHtml(sig.name)}</span></div>
      <div class="keyval"><span class="key">MIME:</span><span class="val">${escHtml(sig.mime || '—')}</span></div>
      <div class="keyval"><span class="key">Ext:</span><span class="val">${escHtml(sig.extension || '—')}</span></div>
      <div class="keyval"><span class="key">Patterns:</span><span class="val">${sig.patterns ? sig.patterns.length : 0}</span></div>
    `;
  } else {
    details.innerHTML = `<div class="keyval"><span class="key">Name:</span><span class="val">${escHtml(name)}</span></div>`;
  }
}

// ============================================================
// BATCH SCAN (native folder dialog)
// ============================================================
let batchFiles = [];
let batchResults = {};    // filename -> scan result
let batchSelectedFile = null; // currently highlighted file

$('#btn-select-folder')?.addEventListener('click', async () => {
  // Show loading
  $('#loading-overlay').style.display = 'flex';

  const folderPath = await pickFolder();
  if (!folderPath) { $('#loading-overlay').style.display = 'none'; return; }

  $('#batch-folder').textContent = folderPath;
  $('#batch-identified').textContent = '—';
  batchResults = {};
  batchSelectedFile = null;
  $('#inspect-hex-btn-wrap').style.display = 'none';

  const list = $('#batch-list');
  list.dataset.folderPath = folderPath;
  batchFiles = [];

  try {
    const recurse = $('#recursive-toggle').checked;
    const entries = await invokeTauri('list_folder_files', { path: folderPath, recursive: recurse });
    if (entries) {
      batchFiles = JSON.parse(entries);
      $('#batch-count').textContent = String(batchFiles.length);
      list.innerHTML = '';
      const frag = document.createDocumentFragment();
      batchFiles.forEach((f, i) => {
        const div = document.createElement('div');
        div.className = 'batch-item';
        div.dataset.index = i;
        div.dataset.filename = f;
        div.innerHTML = `
          <input type="checkbox" ${$('#batch-select-all').checked ? 'checked' : ''} id="batch-cb-${i}">
          <span class="batch-name">${escHtml(f)}</span>
          <span class="batch-status wait">—</span>
        `;
        // Click = highlight, show Inspect button
        div.addEventListener('click', () => selectBatchItem(i, div));
        frag.appendChild(div);
      });
      list.appendChild(frag);
    }
  } catch (e) {
    list.innerHTML = `<span class="keyword">Error: ${escHtml(e)}</span>`;
  } finally {
    $('#loading-overlay').style.display = 'none';
  }
});

function selectBatchItem(index, el) {
  document.querySelectorAll('.batch-item.selected').forEach(e => e.classList.remove('selected'));
  el.classList.add('selected');
  batchSelectedFile = index;

  const f = batchFiles[index];
  const folderPath = $('#batch-list').dataset.folderPath;
  const fullPath = folderPath.replace(/\\/g, '/').replace(/\/$/, '') + '/' + f;

  $('#selected-batch-file').textContent = f;

  // Show the inspect button area
  $('#inspect-hex-btn-wrap').style.display = 'block';

  // Enable button as long as scan produced a result
  const result = batchResults[f];
  $('#btn-inspect-hex').disabled = !result;

  // Store full path for hex inspection
  $('#btn-inspect-hex').dataset.targetPath = fullPath;

  // Open in Scan button: show for container files
  const isContainer = result && (result.file_type.toLowerCase().includes('zip')
    || result.file_type.toLowerCase().includes('rar')
    || result.file_type.toLowerCase().includes('7z')
    || result.file_type.toLowerCase().includes('tar')
    || result.file_type.toLowerCase().includes('cab'));
  if (isContainer && result && !result.has_password) {
    $('#btn-open-in-scan').disabled = false;
  } else {
    $('#btn-open-in-scan').disabled = true;
  }
  $('#btn-open-in-scan').dataset.targetPath = fullPath;
}

$('#batch-select-all')?.addEventListener('change', function () {
  $$('.batch-item input[type=checkbox]').forEach(cb => { cb.checked = this.checked; });
});

$('#btn-open-in-scan')?.addEventListener('click', async () => {
  const path = $('#btn-open-in-scan').dataset.targetPath;
  if (!path) return;
  // Switch to scan tab and scan the file
  document.querySelector('.tab[data-tab="scan"]')?.click();
  await doScan(path, 'quick', '8');
});

$('#btn-inspect-hex')?.addEventListener('click', async () => {
  const path = $('#btn-inspect-hex').dataset.targetPath;
  if (!path) return;
  // Scan the file first to get signatures for hex view
  try {
    const raw = await invokeTauri('scan_file', { path, mode: 'quick' });
    if (raw) {
      lastScanResult = JSON.parse(raw);
    }
  } catch (e) {
    // proceed without scan result
  }
  lastFilePath = path;
  // Switch to hex tab — renderHexTab will use lastScanResult + lastFilePath
  document.querySelector('.tab[data-tab="hex"]')?.click();
});

$('#btn-run-batch')?.addEventListener('click', async () => {
  const folderPath = $('#batch-list').dataset.folderPath;
  if (!folderPath || batchFiles.length === 0) {
    $('#btn-select-folder').click();
    return;
  }

  // Show loading overlay — prevents "not responding"
  $('#loading-overlay').style.display = 'flex';
  $('#loading-overlay .loading-spinner span').textContent = 'Scanning...';

  const items = $$('.batch-item');
  let identified = 0, total = 0;

  for (let i = 0; i < batchFiles.length; i++) {
    const cb = $(`#batch-cb-${i}`);
    if (cb && !cb.checked) continue;
    total++;

    const statusEl = items[i]?.querySelector('.batch-status');
    if (statusEl) { statusEl.textContent = 'scanning...'; statusEl.className = 'batch-status wait'; }

    const fullPath = folderPath.replace(/\\/g, '/').replace(/\/$/, '') + '/' + batchFiles[i];
    try {
      const raw = await invokeTauri('scan_file', { path: fullPath, mode: 'quick' });
      if (raw) {
        const data = JSON.parse(raw);
        const type = data.combined.file_type;
        if (statusEl) { statusEl.textContent = type; statusEl.className = 'batch-status ' + (type !== 'Unknown' ? 'ok' : 'fail'); }
        if (type !== 'Unknown') identified++;

        batchResults[batchFiles[i]] = data.combined;

        // Show container icon
        if (type.toLowerCase().includes('zip') || type.toLowerCase().includes('rar') || type.toLowerCase().includes('7z') || type.toLowerCase().includes('tar')) {
          const stEl = items[i]?.querySelector('.batch-status');
          if (stEl) stEl.innerHTML = stEl.textContent + ' <i class="fas fa-file-archive"></i>';
        }

        if (batchSelectedFile === i) {
          $('#btn-inspect-hex').disabled = false;
          // Enable Open in Scan for containers
          const isContainer = type.toLowerCase().includes('zip')
            || type.toLowerCase().includes('rar') || type.toLowerCase().includes('7z')
            || type.toLowerCase().includes('tar') || type.toLowerCase().includes('cab');
          if (isContainer && !data.combined.has_password) {
            $('#btn-open-in-scan').disabled = false;
          }
        }
      }
    } catch {
      if (statusEl) { statusEl.textContent = 'error'; statusEl.className = 'batch-status fail'; }
    }

    // Yield to event loop every 5 items to keep UI responsive
    if (i % 5 === 0) {
      await new Promise(r => setTimeout(r, 1));
    }
  }

  $('#batch-identified').textContent = `${identified}/${total}`;
  $('#status-file-info').textContent = `Batch: ${identified}/${total}`;

  // Hide loading overlay
  $('#loading-overlay').style.display = 'none';
});

// ============================================================
// DB TAB
// ============================================================
async function refreshDbView() {
  try {
    const raw = await invokeTauri('list_signatures');
    if (!raw) { $('#db-list').innerHTML = '<span class="muted">Engine unavailable</span>'; return; }
    const sigs = JSON.parse(raw);
    allSignatures = sigs;
    const list = $('#db-list');
    list.innerHTML = '';
    sigs.forEach(sig => {
      const div = document.createElement('div');
      div.className = 'db-item';
      div.style.display = 'flex';
      div.style.justifyContent = 'space-between';
      div.innerHTML = `<span class="string">${escHtml(sig.name)}</span><span class="muted">${escHtml(sig.extension || '—')}</span>`;
      div.addEventListener('click', () => showDbDetails(sig));
      list.appendChild(div);
    });
    $('#db-count').textContent = String(sigs.length);
    $('#db-path').textContent = 'signatures.db';
  } catch (err) {
    console.error('DB load:', err);
    $('#db-list').innerHTML = `<span class="keyword">Error: ${escHtml(err)}</span>`;
  }
}

function showDbDetails(sig) {
  const box = $('#db-detail-box');
  if (!box) return;
  let hexHtml = '';
  if (sig.patterns && sig.patterns.length > 0) {
    sig.patterns.forEach((p, i) => {
      const formatted = p.hex_bytes.match(/.{1,2}/g)?.join(' ') || p.hex_bytes;
      hexHtml += `<span class="hex-chip">@0x${p.offset.toString(16).toUpperCase()} ${formatted}</span>`;
    });
  }
  box.innerHTML = `
    <div class="detail-divider"></div>
    <div class="keyval"><span class="key">Name:</span><span class="val string">${escHtml(sig.name)}</span></div>
    <div class="keyval"><span class="key">MIME:</span><span class="val">${escHtml(sig.mime || '—')}</span></div>
    <div class="keyval"><span class="key">Ext:</span><span class="val">${escHtml(sig.extension || '—')}</span></div>
    <div class="keyval"><span class="key">ID:</span><span class="val string">#${sig.id}</span></div>
    <div class="keyval"><span class="key">Patterns:</span><span class="val">${sig.patterns ? sig.patterns.length : 0}</span></div>
    ${hexHtml ? `<div class="keyval" style="margin-top:6px;"><span class="key">Hex:</span></div><div style="display:flex;flex-wrap:wrap;gap:2px;margin-top:2px;">${hexHtml}</div>` : ''}
  `;
}

$('#btn-refresh-db')?.addEventListener('click', refreshDbView);

$('#btn-rebuild-seed')?.addEventListener('click', async () => {
  $('#db-list').innerHTML = '<span class="muted">Rebuilding...</span>';
  try {
    const result = await invokeTauri('rebuild_seed_db');
    if (result) {
      alert(result);
      refreshDbView();
    }
  } catch (err) {
    alert('Error: ' + err);
  }
});

$('#btn-update-web')?.addEventListener('click', async () => {
  const url = $('#remote-sig-url')?.value?.trim();
  if (!url) { alert('Enter a remote URL first'); return; }

  const btn = $('#btn-update-web');
  const origText = btn.innerHTML;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Fetching...';
  btn.disabled = true;

  try {
    const result = await invokeTauri('fetch_signatures', { url });
    if (result) {
      alert(result);
      refreshDbView();
    } else {
      alert('Engine unavailable');
    }
  } catch (err) {
    console.error('Fetch error:', err);
    alert('Error: ' + err);
  } finally {
    btn.innerHTML = origText;
    btn.disabled = false;
  }
});

// Hex jump to offset
$('#hex-go-btn')?.addEventListener('click', () => {
  const input = $('#hex-offset-jump');
  if (!input) return;
  let val = input.value.trim();
  if (!val) return;
  // Accept hex with or without 0x prefix, also accept decimal
  let offset;
  if (val.startsWith('0x') || val.startsWith('0X')) {
    offset = parseInt(val, 16);
  } else if (/^[0-9a-fA-F]+$/.test(val)) {
    offset = parseInt(val, 16);
  } else {
    offset = parseInt(val, 10);
  }
  if (isNaN(offset)) return;
  loadHexView(offset);
});

$('#hex-offset-jump')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#hex-go-btn').click();
});

// ============================================================
// CLI TAB
// ============================================================
let cliInited = false;

function initCli() {
  if (cliInited) return;
  cliInited = true;
  cliPrint('Lumen CLI v0.1.2 — embedded terminal', 'cli-info');
  cliPrint('Type `help` for available commands', 'muted');
}

function cliPrint(text, className = '') {
  const el = $('#cli-output');
  if (!el) return;
  const div = document.createElement('div');
  div.className = 'cli-line' + (className ? ' ' + className : '');
  div.textContent = text;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  // Trim old lines
  while (el.children.length > 500) el.removeChild(el.firstChild);
}

function cliPrintHtml(html) {
  const el = $('#cli-output');
  if (!el) return;
  const div = document.createElement('div');
  div.className = 'cli-line';
  div.innerHTML = html;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  while (el.children.length > 500) el.removeChild(el.firstChild);
}

const cliCommands = {
  help() {
    cliPrint('Available commands:');
    cliPrint('  help              — show this help');
    cliPrint('  clear             — clear terminal');
    cliPrint('  sigs              — list all signatures');
    cliPrint('  info              — show engine info');
    cliPrint('  scan <path>       — scan a file (quick mode)');
    cliPrint('  deep <path>       — deep scan a file');
    cliPrint('  jump <offset>     — jump to offset in hex view');
    cliPrint('  echo <text>       — print text');
  },
  clear() {
    const el = $('#cli-output');
    if (el) el.innerHTML = '';
    cliInited = false;
    initCli();
  },
  async sigs() {
    cliPrint('Fetching signatures...', 'muted');
    try {
      const raw = await invokeTauri('list_signatures');
      if (!raw) { cliPrint('Engine unavailable', 'cli-error'); return; }
      const sigs = JSON.parse(raw);
      cliPrint(`Loaded ${sigs.length} signatures:`);
      const maxShow = 30;
      sigs.slice(0, maxShow).forEach(s => cliPrint(`  ${s.name}  (${s.extension || '—'})`));
      if (sigs.length > maxShow) cliPrint(`  ... and ${sigs.length - maxShow} more`);
    } catch (e) { cliPrint(`Error: ${e}`, 'cli-error'); }
  },
  info() {
    cliPrint(`Engine: lumen-engine v0.1.2`);
    cliPrint(`Signatures loaded: ${allSignatures.length || '?'}`);
    cliPrint(`Platform: Windows`);
    cliPrint(`Frontend: Tauri v2 + WebView`);
  },
  async scan(path) {
    if (!path) { cliPrint('Usage: scan <filepath>', 'cli-error'); return; }
    document.querySelector('.tab[data-tab="scan"]')?.click();
    await doScan(path, 'quick', '8');
    if (lastScanResult) {
      const r = lastScanResult;
      cliPrint(`File: ${path.split(/[\\/]/).pop()}  (${fmtSize(r.total_size)})`);
      cliPrint(`Type: ${r.combined.file_type}  (${r.combined.mime || '—'})`);
      cliPrint(`Confidence: ${(r.combined.confidence * 100).toFixed(0)}%`);
      if (r.combined.offset > 0) cliPrint(`Match @ 0x${r.combined.offset.toString(16).toUpperCase()}`);
      cliPrint(`Segments: ${r.segments.length}`);
    }
  },
  async deep(path) {
    if (!path) { cliPrint('Usage: deep <filepath>', 'cli-error'); return; }
    cliPrint(`Deep scanning: ${path}`, 'muted');
    try {
      const raw = await invokeTauri('scan_file', { path, mode: 'segmented', segments: 16, deepScan: true });
      if (!raw) { cliPrint('No result', 'cli-error'); return; }
      const r = JSON.parse(raw);
      cliPrint(`Segments: ${r.segments.length}  |  Total size: ${fmtSize(r.total_size)}`);
      r.segments.forEach((s, i) => {
        cliPrint(`  [${i}] @0x${s.offset.toString(16).toUpperCase()}  ${s.result.file_type}`);
      });
      cliPrint(`Combined: ${r.combined.file_type}`);
    } catch (e) { cliPrint(`Error: ${e}`, 'cli-error'); }
  },
  jump(offset) {
    if (!offset) { cliPrint('Usage: jump <hex_offset>', 'cli-error'); return; }
    const off = parseInt(offset, 16);
    if (isNaN(off)) { cliPrint('Invalid offset', 'cli-error'); return; }
    loadHexView(off);
    document.querySelector('.tab[data-tab="hex"]')?.click();
  },
  echo(...args) { cliPrint(args.join(' ')); },
};

$('#cli-input')?.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const input = e.target.value.trim();
  e.target.value = '';
  if (!input) return;

  // Echo
  cliPrintHtml(`<span class="prompt">$</span> ${escHtml(input)}`);

  const parts = input.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  const cmd = parts[0]?.toLowerCase() || '';
  const args = parts.slice(1).map(a => a.replace(/^"(.*)"$/, '$1'));

  if (cliCommands[cmd]) {
    try {
      const result = cliCommands[cmd](...args);
      if (result && typeof result.then === 'function') {
        result.catch(err => cliPrint(`Command error: ${err}`, 'cli-error'));
      }
    } catch (err) {
      cliPrint(`Command error: ${err}`, 'cli-error');
    }
  } else {
    cliPrint(`Unknown command: ${cmd}`, 'cli-error');
  }
});

// ============================================================

// Load DB on startup
(async () => {
  try {
    const raw = await invokeTauri('list_signatures');
    if (raw) {
      allSignatures = JSON.parse(raw);
      $('#db-count').textContent = String(allSignatures.length);
    }
  } catch { /* Tauri not running yet */ }
})();
