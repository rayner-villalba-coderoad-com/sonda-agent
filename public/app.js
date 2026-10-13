(() => {
  'use strict';
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const nf = new Intl.NumberFormat('es-ES');
  const fmtN = n => nf.format(n);
  const fmtB = Engine.fmtBytes;
  const fmtDur = s => { if (s < 1) return Math.round(s * 1000) + ' ms'; if (s < 60) return s.toFixed(1).replace('.', ',') + ' s'; const m = Math.floor(s / 60), r = Math.round(s % 60); if (m < 60) return m + ' min ' + r + ' s'; return Math.floor(m / 60) + ' h ' + (m % 60) + ' min'; };
  const relT = t => { const r = Math.max(0, t - S.M.start); const m = Math.floor(r / 60); return m + ':' + (r % 60).toFixed(3).padStart(6, '0'); };
  const relShort = r => { const m = Math.floor(r / 60), s = Math.floor(r % 60); return m + ':' + String(s).padStart(2, '0'); };
  const SEV_LABEL = {alta: 'Alta', media: 'Media', baja: 'Baja'};
  const SERIES = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];

  const S = {M: null, file: '', rules: [], ruleSeq: 0, chat: [], sample: null, downloads: null, ai: 'pending', tab: 'resumen', selPkt: null, pktFilter: '', flowSort: 'bytes', flowFilter: '', hits: {}, busy: false, abort: null, interp: '', aiRuleDraft: null, curBot: null,
    follow: null, followDir: 'ambos', followFmt: 'ascii', fileFilter: '', loadSeq: 0, cancelLoad: null};

  // ---------- Runtime capabilities ----------
  (async () => {
    const c = window.claude;
    if (!c || typeof c.use !== 'function') { S.ai = 'off'; updateAiStatus(); return; }
    try { S.downloads = await c.use('downloads'); } catch (e) { S.downloads = null; }
    try { S.sample = await c.use('sample'); } catch (e) { S.sample = null; }
    S.ai = S.sample ? 'ready' : 'off'; updateAiStatus();
  })();
  setTimeout(() => { if (S.ai === 'pending') { S.ai = 'off'; updateAiStatus(); } }, 12000);
  function updateAiStatus() {
    const st = $('#aiStatus');
    const map = {pending: ['var(--muted)', 'Conectando…'], ready: ['var(--baja)', 'Listo'], off: ['var(--alta)', 'Sin clave de API'], denied: ['var(--alta)', 'Sin permiso']};
    const [c, t] = map[S.ai] || map.off;
    st.innerHTML = '<span class="dot" style="background:' + c + '"></span>' + t;
  }

  // ---------- Helpers ----------
  let toastTimer;
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 2800); }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) {
      const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (e2) {} ta.remove(); return ok;
    }
  }
  async function saveFile(filename, data) {
    if (S.downloads) {
      try { const r = await S.downloads.save({filename, data}); if (r && r.status === 'saved') toast('Archivo guardado: ' + filename); return; }
      catch (e) { if (e && (e.code === 'declined' || e.code === 'rate_limited')) return; }
    }
    const ok = await copyText(data);
    toast(ok ? 'La descarga no está disponible aquí; copié el contenido al portapapeles.' : 'No se pudo descargar ni copiar el archivo.');
  }
  async function saveBinary(filename, parts, type = 'application/octet-stream') {
    if (!S.downloads) { toast('La descarga no está disponible aquí.'); return; }
    try { const r = await S.downloads.save({filename, data: new Blob(parts, {type})}); if (r && r.status === 'saved') toast('Archivo guardado: ' + filename); }
    catch (e) { if (!e || (e.code !== 'declined' && e.code !== 'rate_limited')) toast('No se pudo guardar ' + filename + '.'); }
  }
  // ZIP without compression (method "stored"), enough to bundle the extracted files with their hashes.
  const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  const crc32 = b => { let c = 0xFFFFFFFF; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
  function zipParts(entries) {
    const parts = [], central = [], d = new Date(), enc = new TextEncoder();
    const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    let off = 0;
    for (const e of entries) {
      const name = enc.encode(e.name), crc = crc32(e.data), h = new DataView(new ArrayBuffer(30)), c = new DataView(new ArrayBuffer(46));
      [[0, 0x04034b50, 4], [4, 20, 2], [6, 0x0800, 2], [8, 0, 2], [10, time, 2], [12, date, 2], [14, crc, 4], [18, e.data.length, 4], [22, e.data.length, 4], [26, name.length, 2], [28, 0, 2]].forEach(([o, v, n]) => n === 4 ? h.setUint32(o, v, true) : h.setUint16(o, v, true));
      [[0, 0x02014b50, 4], [4, 20, 2], [6, 20, 2], [8, 0x0800, 2], [10, 0, 2], [12, time, 2], [14, date, 2], [16, crc, 4], [20, e.data.length, 4], [24, e.data.length, 4], [28, name.length, 2], [42, off, 4]].forEach(([o, v, n]) => n === 4 ? c.setUint32(o, v, true) : c.setUint16(o, v, true));
      parts.push(h, name, e.data); central.push(c, name);
      off += 30 + name.length + e.data.length;
    }
    const cdSize = central.reduce((a, x) => a + x.byteLength, 0), end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true); end.setUint16(8, entries.length, true); end.setUint16(10, entries.length, true); end.setUint32(12, cdSize, true); end.setUint32(16, off, true);
    return parts.concat(central, [end]);
  }
  const sevCounts = () => { const c = {alta: 0, media: 0, baja: 0}; (S.M ? S.M.findings : []).forEach(f => c[f.sev]++); return c; };

  // ---------- Tabs ----------
  const layout = $('#layout');
  $('#tabs').addEventListener('click', e => { const b = e.target.closest('button[data-tab]'); if (b) setTab(b.dataset.tab); });
  function setTab(name) {
    document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    if (name === 'chat') { layout.classList.add('show-chat'); setTimeout(() => $('#chatInput').focus(), 0); return; }
    layout.classList.remove('show-chat');
    if (S.tab !== name) $('#content').scrollTop = 0;
    S.tab = name; showPanels();
    if (name === 'resumen') requestAnimationFrame(drawTimeline);
    if (name === 'incidente') requestAnimationFrame(drawIncident);
  }
  function showPanels() {
    const loading = !$('#progressState').hidden;
    const showEmpty = !loading && !S.M && S.tab !== 'reglas';
    $('#emptyState').hidden = !showEmpty;
    document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', !loading && !showEmpty && p.id === 'p-' + S.tab));
  }
  function updateCounts() {
    $('#cntFind').textContent = S.M ? S.M.findings.length : 0;
    $('#cntFiles').textContent = S.M ? S.M.files.length : 0;
    $('#cntRules').textContent = S.rules.filter(r => !r.test || !r.test.comment).length;
  }

  // ---------- Loading ----------
  const fileInput = $('#fileInput');
  [$('#btnOpen'), $('#btnOpen2')].forEach(b => b.addEventListener('click', () => fileInput.click()));
  fileInput.addEventListener('change', async () => { const f = fileInput.files[0]; if (f) await loadFile(f); fileInput.value = ''; });
  $('#btnSample').addEventListener('click', () => loadBuffer(Engine.sampleCapture(), 'captura-ejemplo.pcap'));
  let dragDepth = 0;
  window.addEventListener('dragenter', e => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { e.preventDefault(); dragDepth++; $('#drop').classList.add('over'); } });
  window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $('#drop').classList.remove('over'); });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', async e => { e.preventDefault(); dragDepth = 0; $('#drop').classList.remove('over'); const f = e.dataTransfer.files[0]; if (f) await loadFile(f); });
  async function loadFile(f) {
    let buf; try { buf = await f.arrayBuffer(); } catch (e) { showLoadError('No se pudo leer el archivo: ' + e.message); return; }
    await loadBuffer(buf, f.name);
  }
  // Parsing runs in a Web Worker (worker.js) so the interface keeps responding with large captures.
  // The capture is sent only once the worker says it is ready: if it cannot start (old browser, file://),
  // the buffer is still ours and loadBuffer parses on this thread instead.
  function parseInWorker(buf, rules, progress) {
    return new Promise((resolve, reject) => {
      let w; try { w = new Worker('worker.js'); } catch (e) { reject({noWorker: true}); return; }
      let ready = false, M = null, data = null, tests = null, total = 0;
      const stop = err => { w.terminate(); S.cancelLoad = null; if (err) reject(err); };
      S.cancelLoad = () => stop({code: 'cancelled'});
      w.onmessage = ({data: m}) => {
        if (m.type === 'ready') { ready = true; w.postMessage({buf, rules}, [buf]); }
        else if (m.type === 'progress') progress(m.frac, m.n, m.stage);
        else if (m.type === 'model') { M = m.M; data = m.buf; tests = m.tests; total = m.total; }
        else if (m.type === 'pkts') { Engine.addPackets(M, data, m.batch); progress(total ? M.pkts.length / total : 1, M.pkts.length, 'paquetes', total); }
        else if (m.type === 'end') { stop(); resolve({M, tests}); }
        else if (m.type === 'error') stop(new Error(m.message));
      };
      w.onerror = e => { e.preventDefault(); stop(ready ? new Error('El análisis en segundo plano falló' + (e.message ? ' (' + e.message + ')' : '') + '. Si la captura es muy grande, divídela con editcap -c 500000.') : {noWorker: true}); };
    });
  }
  const STAGE = {leer: n => fmtN(n) + ' paquetes leídos', archivos: n => fmtN(n) + ' paquetes leídos. Reconstruyendo flujos TCP y extrayendo archivos…', reglas: () => 'Probando tus reglas Snort…', evidencias: () => 'Buscando las tramas de evidencia de cada hallazgo…', hash: () => 'Calculando el SHA-256 de la captura…', paquetes: (n, total) => 'Preparando la tabla: ' + fmtN(n) + ' de ' + fmtN(total) + ' paquetes'};
  $('#btnCancelLoad').addEventListener('click', () => { if (S.cancelLoad) S.cancelLoad(); });
  async function loadBuffer(buf, name) {
    if (S.cancelLoad) S.cancelLoad();
    const seq = ++S.loadSeq, current = () => seq === S.loadSeq;
    $('#btnCancelLoad').hidden = true;
    $('#progressState').hidden = false; $('#progTitle').textContent = 'Leyendo ' + name + '…'; $('#progBar').style.width = '0%'; $('#progText').textContent = fmtB(buf.byteLength);
    showPanels();
    const progress = (frac, n, stage, total) => {
      if (!current()) return;
      $('#progBar').style.width = (frac * 100).toFixed(1) + '%'; $('#progText').textContent = (STAGE[stage] || STAGE.leer)(n, total);
      $('#btnCancelLoad').hidden = !S.cancelLoad;
    };
    try {
      const rules = S.rules.map(r => r.text);
      let res;
      try { res = await parseInWorker(buf, rules, progress); }
      catch (e) {
        if (!e || !e.noWorker) throw e;
        progress(0, 0, 'leer');
        const M = await Engine.parse(buf, progress);
        res = {M, tests: rules.map(t => Engine.testRule(t, M))};
      }
      if (!current()) return;
      const M = res.M, tested = new Map(rules.map((t, i) => [t, res.tests[i]]));
      S.M = M; S.file = name; S.selPkt = null; S.pktFilter = ''; S.flowFilter = ''; S.interp = ''; S.hits = {}; S.follow = null; S.fileFilter = '';
      $('#tabFollow').hidden = true;
      for (const r of S.rules) { r.test = tested.get(r.text) || Engine.testRule(r.text, M); storeHits(r); }
      $('#progressState').hidden = true;
      $('#fileMeta').hidden = false; $('#btnReport').hidden = false;
      $('#fileName').textContent = name; $('#fileName').title = name;
      $('#fileInfo').textContent = fmtN(M.count) + ' paquetes, ' + fmtB(M.bytes) + ', ' + fmtDur(M.duration);
      renderAll(); setTab('resumen');
      if (!S.chat.length) renderChatIntro();
    } catch (e) {
      if (!current()) return;
      $('#progressState').hidden = true;
      if (e && e.code === 'cancelled') { showPanels(); toast('Lectura cancelada'); return; }
      showLoadError(e.message || String(e));
    }
  }
  function showLoadError(msg) {
    showPanels();
    const d = $('#drop'); let p = d.querySelector('.error');
    if (!p) { p = document.createElement('p'); p.className = 'error'; d.insertBefore(p, d.querySelector('.actions')); }
    p.textContent = msg;
  }

  function renderAll() { renderSummary(); renderPackets(); renderFlows(); renderFiles(); renderFollow(); renderFindings(); renderIncident(); renderRules(); updateCounts(); showPanels(); }

  // ---------- Summary ----------
  function barList(items, max, opts = {}) {
    if (!items.length) return '<p class="muted">Sin datos.</p>';
    return '<div class="bl">' + items.map(it => {
      const segs = it.segs || [{v: it.v, c: it.c || 'var(--s1)'}];
      return '<div class="bl-row"><div class="bl-label" title="' + esc(it.title || it.label) + '">' + it.labelHtml + '</div><div class="bl-track">' +
        segs.map(s => '<i style="width:' + (max ? (s.v / max * 100).toFixed(2) : 0) + '%;background:' + s.c + '"></i>').join('') +
        '</div><div class="bl-val">' + esc(it.valText) + '</div></div>';
    }).join('') + '</div>' + (opts.legend || '');
  }
  function renderSummary() {
    const M = S.M, el = $('#p-resumen'); if (!M) { el.innerHTML = ''; return; }
    const sev = sevCounts();
    const protos = Object.entries(M.proto).sort((a, b) => b[1].pkts - a[1].pkts).slice(0, 8);
    const pMax = protos.length ? protos[0][1].pkts : 0;
    const hosts = M.hostList.slice(0, 8), hMax = hosts.length ? hosts[0].bytesIn + hosts[0].bytesOut : 0;
    const ports = M.portList.slice(0, 8), poMax = ports.length ? ports[0].flows : 0;
    const dnsTop = [...M.dnsCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const web = [...[...M.sniCount.entries()].map(([k, v]) => [k, 'TLS', v]), ...[...M.httpHostCount.entries()].map(([k, v]) => [k, 'HTTP', v])].sort((a, b) => b[2] - a[2]).slice(0, 10);
    const keyColor = {}; M.timeline.keys.forEach((k, i) => keyColor[k] = SERIES[i % SERIES.length]);
    el.innerHTML = `
      <div class="facts">
        <div class="fact"><b>${fmtN(M.count)}</b><span>paquetes</span></div>
        <div class="fact"><b>${esc(fmtB(M.bytes))}</b><span>de tráfico</span></div>
        <div class="fact"><b>${esc(fmtDur(M.duration))}</b><span>de captura</span></div>
        <div class="fact"><b>${fmtN(M.hosts.size)}</b><span>hosts</span></div>
        <div class="fact"><b>${fmtN(M.flows.length)}</b><span>conversaciones</span></div>
        <div class="fact"><b>${M.findings.length}</b><span>hallazgos</span>
          <div class="sevline"><em><i class="dot alta"></i>${sev.alta} alta</em><em><i class="dot media"></i>${sev.media} media</em><em><i class="dot baja"></i>${sev.baja} baja</em></div></div>
      </div>
      ${M.truncated ? '<p class="warn">El archivo parece truncado: se analizaron los paquetes legibles hasta el corte.</p>' : ''}
      ${M.pktsTruncated ? '<p class="warn">Captura grande: las estadísticas cubren todos los paquetes, pero la tabla y las pruebas de reglas usan los primeros ' + fmtN(Engine.MAX_PKTS) + '.</p>' : ''}
      <div class="box hero">
        <div class="box-head"><h2>Tráfico en el tiempo<small>paquetes por intervalo de ${esc(fmtDur(M.timeline.width))}, desde ${esc(new Date(M.start * 1000).toLocaleString('es-ES'))}</small></h2></div>
        <div class="tl" id="tl"></div>
        <div class="legend">${M.timeline.keys.map(k => '<span><i style="background:' + keyColor[k] + '"></i>' + esc(k) + '</span>').join('')}
          ${M.findings.length ? '<span><i class="mark" style="background:var(--alta)"></i>Inicio de un hallazgo</span>' : ''}</div>
        <div class="readout" id="tlReadout">Pasa el cursor sobre el gráfico para ver el detalle de cada intervalo.</div>
      </div>
      <div class="box ai-box">
        <div class="box-head"><h2>Interpretación del agente</h2><button class="btn small" id="btnInterp">${S.interp ? 'Volver a interpretar' : 'Interpretar captura'}</button></div>
        <div class="ai-out md" id="interpOut">${S.interp ? md(S.interp) : ''}</div>
        ${S.interp ? '' : '<p class="muted" id="interpHint" style="margin:0">El agente redacta un informe en lenguaje claro: qué ocurrió, qué es grave y qué hacer primero.</p>'}
      </div>
      <div class="grid2">
        <div class="box"><div class="box-head"><h2>Protocolos<small>por paquetes</small></h2></div>
          ${barList(protos.map(([k, v], i) => ({labelHtml: esc(k), label: k, v: v.pkts, c: keyColor[k] || SERIES[i % 8], valText: fmtN(v.pkts) + ' (' + fmtB(v.bytes) + ')'})), pMax)}</div>
        <div class="box"><div class="box-head"><h2>Hosts con más tráfico</h2></div>
          ${barList(hosts.map(h => ({labelHtml: '<span class="mono">' + esc(h.ip) + '</span>' + (M.ipNames.get(h.ip) ? ' <span class="muted">' + esc(M.ipNames.get(h.ip)) + '</span>' : (Engine.isInternal(h.ip) ? ' <span class="muted">interno</span>' : '')), label: h.ip, segs: [{v: h.bytesOut, c: 'var(--s1)'}, {v: h.bytesIn, c: 'var(--s2)'}], valText: fmtB(h.bytesIn + h.bytesOut)})), hMax,
            {legend: '<div class="legend"><span><i style="background:var(--s1)"></i>Enviado</span><span><i style="background:var(--s2)"></i>Recibido</span></div>'})}</div>
      </div>
      <div class="grid2">
        <div class="box"><div class="box-head"><h2>Servicios más usados<small>por conversaciones</small></h2></div>
          ${barList(ports.map(p => ({labelHtml: '<span class="mono">' + p.proto.toLowerCase() + '/' + p.port + '</span>' + (p.app ? ' <span class="muted">' + esc(p.app) + '</span>' : ''), label: p.proto + '/' + p.port, v: p.flows, c: 'var(--s3)', valText: fmtN(p.flows) + ' conv.'})), poMax)}</div>
        <div class="box"><div class="box-head"><h2>Hallazgos principales</h2>${M.findings.length ? '<button class="btn small ghost" data-goto="hallazgos">Ver todos</button>' : ''}</div>
          ${M.findings.length ? '<ul class="top-findings">' + M.findings.slice(0, 7).map(f => '<li><i class="dot ' + f.sev + '"></i><button data-finding="' + f.id + '">' + esc(f.title) + '</button></li>').join('') + '</ul>' : '<p class="muted">No se detectaron patrones sospechosos con las heurísticas actuales. Puedes pedirle al agente una revisión más detallada.</p>'}</div>
      </div>
      <div class="grid2">
        <div class="box"><div class="box-head"><h2>Dominios consultados<small>DNS</small></h2></div>
          ${dnsTop.length ? '<div class="scroll-x"><table><thead><tr><th>Dominio</th><th class="num">Consultas</th></tr></thead><tbody>' + dnsTop.map(([d, n]) => '<tr><td class="trunc mono" title="' + esc(d) + '">' + esc(d) + '</td><td class="num">' + fmtN(n) + '</td></tr>').join('') + '</tbody></table></div>' : '<p class="muted">No hay consultas DNS en la captura.</p>'}</div>
        <div class="box"><div class="box-head"><h2>Sitios web<small>HTTP y TLS (SNI)</small></h2></div>
          ${web.length ? '<div class="scroll-x"><table><thead><tr><th>Sitio</th><th>Tipo</th><th class="num">Veces</th></tr></thead><tbody>' + web.map(([h, t, n]) => '<tr><td class="trunc mono" title="' + esc(h) + '">' + esc(h) + '</td><td>' + t + (t === 'HTTP' ? ' <span class="warn">(sin cifrar)</span>' : '') + '</td><td class="num">' + fmtN(n) + '</td></tr>').join('') + '</tbody></table></div>' : '<p class="muted">No se vieron peticiones HTTP ni saludos TLS con nombre de servidor.</p>'}</div>
      </div>`;
    $('#btnInterp').addEventListener('click', interpret);
    requestAnimationFrame(drawTimeline);
  }
  $('#content').addEventListener('click', e => {
    const g = e.target.closest('[data-goto]'); if (g) { setTab(g.dataset.goto); return; }
    const fw = e.target.closest('[data-follow]'); if (fw) { const [fid, k] = fw.dataset.follow.split(':').map(Number); openFollow(fid, k || 0); return; }
    const f = e.target.closest('[data-finding]');
    if (f) { setTab('hallazgos'); const t = document.getElementById('f-' + f.dataset.finding); if (t) { t.scrollIntoView({block: 'start'}); t.querySelector('h3').focus({preventScroll: true}); } }
  });

  function niceMax(v) { if (v <= 0) return 1; const p = Math.pow(10, Math.floor(Math.log10(v))); const n = v / p; return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p; }
  function drawTimeline() {
    const M = S.M, wrap = document.getElementById('tl'); if (!M || !wrap || !wrap.clientWidth) return;
    const W = wrap.clientWidth, H = wrap.clientHeight || 260, L = 48, R = 10, T = 18, B = 24;
    const tl = M.timeline, nb = tl.nb, pw = W - L - R, ph = H - T - B, bw = pw / nb;
    const totals = new Array(nb).fill(0); tl.keys.forEach(k => tl.series[k].forEach((v, i) => totals[i] += v));
    const ymax = niceMax(Math.max(...totals));
    let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Paquetes por intervalo de tiempo">';
    for (let g = 0; g <= 4; g++) { const y = T + ph - ph * g / 4; svg += '<line class="grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + y.toFixed(1) + '" y2="' + y.toFixed(1) + '"/><text class="axis" x="' + (L - 6) + '" y="' + (y + 4).toFixed(1) + '" text-anchor="end">' + fmtN(Math.round(ymax * g / 4)) + '</text>'; }
    for (let i = 0; i < nb; i++) svg += '<rect class="hover-col" data-i="' + i + '" x="' + (L + i * bw).toFixed(1) + '" y="' + T + '" width="' + bw.toFixed(1) + '" height="' + ph + '"/>';
    const gap = bw > 6 ? 1.5 : 0.5;
    for (let i = 0; i < nb; i++) {
      let acc = 0;
      tl.keys.forEach((k, ki) => {
        const v = tl.series[k][i]; if (!v) return;
        const h = v / ymax * ph, y = T + ph - acc - h; acc += h;
        svg += '<rect x="' + (L + i * bw + gap / 2).toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + Math.max(0.5, bw - gap).toFixed(1) + '" height="' + Math.max(0.5, h).toFixed(1) + '" fill="' + SERIES[ki % 8] + '" pointer-events="none"/>';
      });
    }
    const ticks = Math.max(2, Math.min(7, Math.floor(pw / 110)));
    for (let t = 0; t <= ticks; t++) { const x = L + pw * t / ticks; svg += '<text class="axis" x="' + x.toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + (t === 0 ? 'start' : t === ticks ? 'end' : 'middle') + '">' + relShort(M.duration * t / ticks) + '</text>'; }
    if (M.duration > 0) {
      const seen = new Set();
      M.findings.forEach(f => {
        const x = L + (f.t - M.start) / M.duration * pw, key = Math.round(x / 4);
        const col = 'var(--' + f.sev + ')';
        svg += '<line x1="' + x.toFixed(1) + '" x2="' + x.toFixed(1) + '" y1="' + (T - 6) + '" y2="' + (T + ph) + '" stroke="' + col + '" stroke-width="1.5" stroke-dasharray="3 3" pointer-events="none"/>';
        if (!seen.has(key)) svg += '<circle cx="' + x.toFixed(1) + '" cy="' + (T - 8) + '" r="4" fill="' + col + '"><title>' + esc(f.title) + '</title></circle>';
        seen.add(key);
      });
    }
    svg += '</svg>';
    wrap.innerHTML = svg;
    const s = wrap.querySelector('svg'), ro = $('#tlReadout');
    s.addEventListener('mousemove', e => {
      const rect = s.getBoundingClientRect(), x = (e.clientX - rect.left) * (W / rect.width);
      const i = Math.floor((x - L) / bw); if (i < 0 || i >= nb) return;
      s.querySelectorAll('.hover-col.on').forEach(r => r.classList.remove('on'));
      const col = s.querySelector('.hover-col[data-i="' + i + '"]'); if (col) col.classList.add('on');
      const parts = tl.keys.map(k => [k, tl.series[k][i]]).filter(p => p[1]).sort((a, b) => b[1] - a[1]).map(p => p[0] + ' ' + fmtN(p[1]));
      const evs = M.findings.filter(f => f.t >= M.start + i * tl.width && f.t < M.start + (i + 1) * tl.width).map(f => f.title);
      ro.innerHTML = 'De <b>' + relShort(i * tl.width) + '</b> a <b>' + relShort((i + 1) * tl.width) + '</b>: ' + fmtN(totals[i]) + ' paquetes (' + esc(fmtB(tl.bytes[i])) + ')' + (parts.length ? '. ' + esc(parts.join(', ')) + '.' : '.') + (evs.length ? ' Empieza: ' + esc(evs.join('; ')) + '.' : '');
    });
    s.addEventListener('mouseleave', () => { s.querySelectorAll('.hover-col.on').forEach(r => r.classList.remove('on')); ro.textContent = 'Pasa el cursor sobre el gráfico para ver el detalle de cada intervalo.'; });
  }
  let lastW = 0;
  new ResizeObserver(() => { const w = $('#content').clientWidth; if (w !== lastW) { lastW = w; drawTimeline(); drawIncident(); } }).observe($('#content'));

  // ---------- Interpretation ----------
  function aiErrorText(e) {
    const c = e && e.code;
    if (c === 'not_granted') { S.ai = 'off'; updateAiStatus(); return 'El servidor no tiene una clave de API válida. Revisa ANTHROPIC_API_KEY en .env.'; }
    if (c === 'upstream_error' && e.message) return 'Error de la API: ' + e.message;
    const m = {rate_limited: 'Hay demasiadas solicitudes seguidas. Espera un momento y vuelve a intentarlo.', prompt_too_large: 'La conversación es demasiado larga. Pulsa "Nueva" para empezar otra.', invalid_json: 'El agente no devolvió el formato esperado. Reformula la descripción e inténtalo de nuevo.', session_expired: 'La sesión caducó. Recarga la página.', refused: 'El agente no quiso responder a esta solicitud.', empty_completion: 'El agente no devolvió texto. Inténtalo de nuevo.', queue_overflow: 'Hay demasiadas solicitudes en cola. Espera un momento.'};
    return m[c] || 'No se pudo obtener respuesta del agente' + (c ? ' (' + c + ')' : '') + '. Inténtalo de nuevo.';
  }
  function aiUnavailableText() { return S.ai === 'pending' ? 'El agente todavía se está conectando. Prueba de nuevo en unos segundos.' : 'El agente no está disponible: define ANTHROPIC_API_KEY en el archivo .env y reinicia el servidor (npm start).'; }
  async function interpret() {
    const out = $('#interpOut'), btn = $('#btnInterp'), hint = $('#interpHint');
    if (!S.sample) { out.innerHTML = '<p class="error">' + esc(aiUnavailableText()) + '</p>'; return; }
    btn.disabled = true; if (hint) hint.remove();
    out.innerHTML = '<p class="thinking">Analizando la captura…</p>';
    const data = {resumen: Engine.summary(S.M, S.file), hallazgos: S.M.findings.map(f => ({severidad: f.sev, categoria: f.cat, fase: phaseLabel(f.phase), mitre: f.mitre.map(m => m.id + ' ' + m.name), inicio_t: +(f.t - S.M.start).toFixed(1), titulo: f.title, descripcion: f.desc, evidencia: f.evidence.slice(0, 4)}))};
    const prompt = 'Eres un analista SOC senior. A partir de este resumen de una captura de red (pcap) y de los hallazgos de detección automática, escribe en español un informe breve para alguien que está aprendiendo análisis de tráfico.\n\n' +
      'Estructura (Markdown, máximo 320 palabras):\n### Qué muestra la captura\n2-3 frases sobre la red, los equipos y el tipo de tráfico.\n### Lo más importante\nLos 2-4 hechos más graves, citando IPs y cifras concretas del resumen, y por qué importan. Si parecen formar una secuencia de ataque, ordénalos por fase (reconocimiento, acceso, comando y control, exfiltración) según inicio_t y di si las fases encajan o parecen actividades independientes. Cita la técnica MITRE ATT&CK de cada hecho entre paréntesis, por ejemplo (T1046).\n### Qué hacer ahora\nHasta 5 acciones concretas y priorizadas.\n### Qué revisar a continuación\n2-3 preguntas útiles para profundizar.\n\nNo inventes datos que no estén abajo. Indica cuando algo sea una hipótesis.\n\nDATOS:\n' + JSON.stringify(data);
    try {
      const {text} = await S.sample(prompt, {onText: ({text}) => { out.innerHTML = md(text); }});
      S.interp = text; out.innerHTML = md(text); btn.textContent = 'Volver a interpretar';
    } catch (e) { out.innerHTML = (e.text ? md(e.text) : '') + '<p class="error">' + esc(aiErrorText(e)) + '</p>'; }
    finally { btn.disabled = false; }
  }

  // ---------- Packets ----------
  function renderPackets() {
    const el = $('#p-paquetes'); if (!S.M) { el.innerHTML = ''; return; }
    el.innerHTML = `
      <div class="toolbar"><label class="sr" for="pktFilter">Filtro de paquetes</label>
        <input type="search" id="pktFilter" placeholder="Filtrar: ip:192.168.1.10  puerto:443  proto:dns  o texto libre" value="${esc(S.pktFilter)}">
        <span class="hint" id="pktCount"></span></div>
      <p class="hint" style="margin:-4px 0 10px">Filtros: <span class="mono">ip:</span>, <span class="mono">origen:</span>, <span class="mono">destino:</span>, <span class="mono">puerto:</span>, <span class="mono">proto:</span>, <span class="mono">regla:SID</span> y texto libre. Se combinan con Y.</p>
      <div class="box scroll-x" style="padding:6px 14px"><table class="pkt-table"><thead><tr><th>N.º</th><th>Tiempo</th><th>Origen</th><th>Destino</th><th>Protocolo</th><th class="num">Long.</th><th>Información</th></tr></thead><tbody id="pktBody"></tbody></table></div>
      <div class="box detail" id="pktDetail" hidden></div>`;
    let tmr; $('#pktFilter').addEventListener('input', e => { clearTimeout(tmr); tmr = setTimeout(() => { S.pktFilter = e.target.value; fillPackets(); }, 180); });
    $('#pktBody').addEventListener('click', e => { const tr = e.target.closest('tr[data-i]'); if (tr) showPacket(+tr.dataset.i); });
    fillPackets();
    if (S.selPkt) showPacket(S.selPkt);
  }
  function packetFilter(q) {
    const toks = q.trim().split(/\s+/).filter(Boolean), conds = [];
    for (const t of toks) {
      const m = t.match(/^(ip|origen|src|destino|dst|puerto|port|proto|protocolo|regla|sid|n):(.+)$/i);
      if (!m) { const s = t.toLowerCase(); conds.push(p => (p.info + ' ' + p.src + ' ' + p.dst + ' ' + p.label + ' ' + p.sport + ' ' + p.dport).toLowerCase().includes(s)); continue; }
      const k = m[1].toLowerCase(), v = m[2].toLowerCase();
      if (k === 'ip') conds.push(p => p.src === v || p.dst === v);
      else if (k === 'origen' || k === 'src') conds.push(p => p.src === v);
      else if (k === 'destino' || k === 'dst') conds.push(p => p.dst === v);
      else if (k === 'puerto' || k === 'port') conds.push(p => p.sport === +v || p.dport === +v);
      else if (k === 'proto' || k === 'protocolo') conds.push(p => p.label.toLowerCase() === v || p.proto.toLowerCase() === v);
      else if (k === 'regla' || k === 'sid') { const set = new Set(S.hits[v] || []); conds.push(p => set.has(p.i)); }
      else if (k === 'n') { const set = new Set(v.split(',').map(Number)); conds.push(p => set.has(p.i)); }
    }
    return p => conds.every(c => c(p));
  }
  function fillPackets() {
    const fn = packetFilter(S.pktFilter), rows = [], LIMIT = 1000; let total = 0;
    for (const p of S.M.pkts) { if (!fn(p)) continue; total++; if (rows.length < LIMIT) rows.push(p); }
    $('#pktCount').textContent = S.pktFilter.trim() ? fmtN(total) + ' coinciden' + (total > LIMIT ? ', se muestran ' + fmtN(LIMIT) : '') : fmtN(S.M.pkts.length) + ' paquetes' + (S.M.pkts.length > LIMIT ? ', se muestran los primeros ' + fmtN(LIMIT) : '');
    $('#pktBody').innerHTML = rows.length ? rows.map(p => '<tr data-i="' + p.i + '"' + (p.i === S.selPkt ? ' class="sel"' : '') + '><td>' + p.i + '</td><td>' + relT(p.t) + '</td><td>' + esc(p.src || p.smac || '') + '</td><td>' + esc(p.dst || p.dmac || '') + '</td><td><span class="proto-tag">' + esc(p.label) + '</span></td><td class="num">' + p.len + '</td><td class="info">' + esc(p.info) + '</td></tr>').join('')
      : '<tr><td colspan="7" class="info muted" style="padding:18px 0">Ningún paquete coincide con el filtro. Revisa la sintaxis o bórralo para ver todos.</td></tr>';
  }
  function hexdump(b, max = 512, base = 0) {
    const n = Math.min(b.length, max); let out = '';
    for (let o = 0; o < n; o += 16) {
      const row = b.subarray(o, Math.min(o + 16, n)); let hx = '', asc = '';
      for (let i = 0; i < 16; i++) { if (i < row.length) { hx += row[i].toString(16).padStart(2, '0') + ' '; asc += row[i] >= 32 && row[i] < 127 ? String.fromCharCode(row[i]) : '.'; } else hx += '   '; if (i === 7) hx += ' '; }
      out += (o + base).toString(16).padStart(base ? 8 : 4, '0') + '  ' + hx + ' ' + asc + '\n';
    }
    return out + (b.length > max ? '… ' + fmtN(b.length - max) + ' bytes más' : '');
  }
  function showPacket(i) {
    const p = S.M.pkts[i - 1]; if (!p) return;
    S.selPkt = i;
    document.querySelectorAll('#pktBody tr.sel').forEach(r => r.classList.remove('sel'));
    const tr = document.querySelector('#pktBody tr[data-i="' + i + '"]'); if (tr) tr.classList.add('sel');
    const rows = [['Número', p.i], ['Hora', new Date(p.t * 1000).toLocaleString('es-ES') + ' (+' + relT(p.t) + ')'], ['Longitud', p.len + ' bytes' + (p.cap < p.len ? ', capturados ' + p.cap : '')]];
    if (p.smac) rows.push(['Ethernet', p.smac + ' → ' + p.dmac + (p.vlan !== undefined ? ', VLAN ' + p.vlan : '')]);
    if (p.ipv) rows.push(['IPv' + p.ipv, p.src + ' → ' + p.dst + ', TTL ' + p.ttl]);
    if (p.proto === 'TCP') rows.push(['TCP', p.sport + ' → ' + p.dport + ', flags [' + Engine.flagStr(p.flags) + '], seq ' + p.seq]);
    if (p.proto === 'UDP') rows.push(['UDP', p.sport + ' → ' + p.dport]);
    if (p.proto === 'ICMP' || p.proto === 'ICMPv6') rows.push([p.proto, 'tipo ' + p.itype + ', código ' + p.icode]);
    if (p.proto === 'ARP') rows.push(['ARP', p.info]);
    if (p.dns) { const q = p.dns.qs[0]; rows.push(['DNS', (p.dns.qr ? 'Respuesta' : 'Consulta') + ' id ' + p.dns.id + ': ' + (Engine.QT[q.qt] || q.qt) + ' ' + q.name + (p.dns.ans.length ? ' → ' + p.dns.ans.join(', ') : '')]); }
    if (p.http && p.http.method) { rows.push(['HTTP', p.http.method + ' ' + p.http.uri]); if (p.http.host) rows.push(['Host', p.http.host]); if (p.http.ua) rows.push(['User-Agent', p.http.ua]); if (p.http.auth) rows.push(['Authorization', p.http.auth.split(' ')[0] + ' (valor oculto)']); }
    if (p.sni) rows.push(['TLS SNI', p.sni]);
    rows.push(['Resumen', p.info]);
    const host = S.M.ipNames.get(p.dst) || S.M.ipNames.get(p.src);
    if (host) rows.push(['Nombre DNS visto', host]);
    const d = $('#pktDetail'); d.hidden = false;
    const k = p.proto === 'TCP' && p.fid ? Engine.tcpConnections(S.M, p.fid).findIndex(c => c.pkts.includes(p)) : -1;
    d.innerHTML = '<div class="box-head"><h2>Paquete ' + p.i + '</h2><div class="row-actions">' + (k >= 0 ? '<button class="btn small" data-follow="' + p.fid + ':' + k + '">Seguir flujo TCP</button>' : '') + '<button class="btn small" id="askPkt">Preguntar al agente</button></div></div><dl>' + rows.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd' + (/IP|Ethernet|TCP|UDP/.test(k) ? ' class="mono"' : '') + '>' + esc(v) + '</dd>').join('') + '</dl>' +
      (p.pl && p.pl.length ? '<h2 style="font-size:14px;margin:0 0 6px">Carga útil, ' + fmtN(p.pl.length) + ' bytes</h2><pre class="hexdump">' + esc(hexdump(p.pl)) + '</pre>' : '<p class="muted" style="margin:0">Este paquete no lleva carga útil capturada.</p>');
    $('#askPkt').addEventListener('click', () => askAgent('Explícame el paquete n.º ' + p.i + ': qué es, quién habla con quién y si hay algo sospechoso en él.'));
  }

  // ---------- Conversations ----------
  function renderFlows() {
    const el = $('#p-conversaciones'); if (!S.M) { el.innerHTML = ''; return; }
    el.innerHTML = `
      <div class="toolbar"><label class="sr" for="flowFilter">Filtrar conversaciones</label>
        <input type="search" id="flowFilter" placeholder="Filtrar por IP, puerto o protocolo" value="${esc(S.flowFilter)}">
        <label class="hint" for="flowSort">Ordenar por</label>
        <select id="flowSort" class="btn small"><option value="bytes">Bytes</option><option value="pkts">Paquetes</option><option value="dur">Duración</option><option value="first">Inicio</option></select>
        <span class="hint" id="flowCount"></span></div>
      <div class="box scroll-x" style="padding:6px 14px"><table><thead><tr><th>Protocolo</th><th>Extremo A</th><th>Extremo B</th><th class="num">Paquetes</th><th class="num">Bytes</th><th class="num">A → B</th><th class="num">B → A</th><th class="num">Inicio</th><th class="num">Duración</th><th><span class="sr">Acciones</span></th></tr></thead><tbody id="flowBody"></tbody></table></div>`;
    $('#flowSort').value = S.flowSort;
    $('#flowSort').addEventListener('change', e => { S.flowSort = e.target.value; fillFlows(); });
    let tmr; $('#flowFilter').addEventListener('input', e => { clearTimeout(tmr); tmr = setTimeout(() => { S.flowFilter = e.target.value; fillFlows(); }, 180); });
    $('#flowBody').addEventListener('click', e => { const tr = e.target.closest('tr[data-a]'); if (!tr || e.target.closest('[data-follow]')) return; S.pktFilter = 'ip:' + tr.dataset.a + ' ip:' + tr.dataset.b + ' puerto:' + tr.dataset.p; renderPackets(); setTab('paquetes'); });
    fillFlows();
  }
  function fillFlows() {
    const q = S.flowFilter.trim().toLowerCase();
    let list = S.M.flows.filter(f => !q || (f.a + ' ' + f.b + ' ' + f.ap + ' ' + f.bp + ' ' + f.app + ' ' + f.proto).toLowerCase().includes(q));
    const k = S.flowSort;
    list = list.slice().sort((x, y) => k === 'pkts' ? y.pkts - x.pkts : k === 'dur' ? (y.last - y.first) - (x.last - x.first) : k === 'first' ? x.first - y.first : y.bytes - x.bytes);
    $('#flowCount').textContent = fmtN(list.length) + ' conversaciones' + (list.length > 500 ? ', se muestran 500' : '') + '. Haz clic en una para ver sus paquetes, o en "Seguir" para leer el diálogo TCP.';
    $('#flowBody').innerHTML = list.slice(0, 500).map(f => '<tr data-a="' + esc(f.a) + '" data-b="' + esc(f.b) + '" data-p="' + f.bp + '" style="cursor:pointer"><td><span class="proto-tag">' + esc(f.app) + '</span></td><td class="mono">' + esc(f.a) + (f.ap ? ':' + f.ap : '') + '</td><td class="mono">' + esc(f.b) + (f.bp ? ':' + f.bp : '') + '</td><td class="num">' + fmtN(f.pkts) + '</td><td class="num">' + fmtB(f.bytes) + '</td><td class="num">' + fmtB(f.ab) + '</td><td class="num">' + fmtB(f.ba) + '</td><td class="num mono">' + relShort(f.first - S.M.start) + '</td><td class="num">' + fmtDur(f.last - f.first) + '</td><td>' + (f.proto === 'TCP' ? '<button class="btn small ghost" data-follow="' + f.id + ':0">Seguir</button>' : '') + '</td></tr>').join('') ||
      '<tr><td colspan="10" class="muted" style="padding:18px 0">Ninguna conversación coincide con el filtro.</td></tr>';
  }

  // ---------- Follow TCP stream ----------
  const endp = e => e.ip + ':' + e.port;
  function openFollow(fid, k) { S.follow = {fid, k}; $('#tabFollow').hidden = false; renderFollow(); setTab('flujo'); }
  function followTurnsHtml(r) {
    const fmt = S.followFmt, sel = S.followDir, dec = fmt === 'utf8' ? new TextDecoder('utf-8') : null;
    let budget = fmt === 'hex' ? 64 * 1024 : 512 * 1024, shown = 0, cut = false, html = '';
    for (const tu of r.turns) {
      if (sel !== 'ambos' && String(tu.dir) !== sel) continue;
      const who = tu.dir ? 'Servidor' : 'Cliente';
      if (tu.gap) { html += '<div class="turn gap">' + who + ': faltan ' + fmtN(tu.len) + ' bytes que no están en la captura</div>'; continue; }
      if (budget <= 0 || shown >= 3000) { cut = true; break; }
      const n = Math.min(tu.len, budget), b = r.dirs[tu.dir].bytes.subarray(tu.off, tu.off + n);
      budget -= n; shown++;
      const body = fmt === 'hex' ? hexdump(b, n, tu.off) : fmt === 'utf8' ? dec.decode(b).replace(/\r\n/g, '\n').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '.') : Engine.printable(b);
      html += '<div class="turn ' + (tu.dir ? 's' : 'c') + (fmt === 'hex' ? ' hex' : '') + '"><span class="th">' + who + ', paquete ' + tu.i + ', ' + relT(tu.t) + ', ' + fmtN(tu.len) + ' bytes</span>' + esc(body) + '</div>';
      if (n < tu.len) { cut = true; break; }
    }
    if (cut) html += '<p class="muted">Se muestra solo el principio de la conversación. Descárgala para verla completa.</p>';
    return html || '<p class="muted">Esta conexión no lleva datos de aplicación: solo paquetes de control TCP.</p>';
  }
  function dialogText(r) {
    const out = ['# Flujo TCP ' + endp(r.client) + ' → ' + endp(r.server) + ' (conversación ' + r.flow.id + (r.conns > 1 ? ', conexión ' + (r.k + 1) : '') + ', ' + S.file + ')', ''];
    for (const tu of r.turns) out.push('=== ' + (tu.dir ? 'Servidor' : 'Cliente') + ', paquete ' + tu.i + ', ' + new Date(tu.t * 1000).toISOString() + ', ' + tu.len + ' bytes' + (tu.gap ? ' NO CAPTURADOS ===' : ' ===') + (tu.gap ? '' : '\n' + Engine.printable(r.dirs[tu.dir].bytes, tu.off, tu.off + tu.len)));
    return out.join('\n') + '\n';
  }
  function renderFollow() {
    const el = $('#p-flujo'); if (!S.M || !S.follow) { el.innerHTML = ''; return; }
    const r = Engine.followTcp(S.M, S.follow.fid, S.follow.k);
    if (!r) { el.innerHTML = '<div class="empty-note">Esa conversación no es TCP.</div>'; return; }
    if (!r.conns) { el.innerHTML = '<div class="empty-note">Los paquetes de esta conversación están fuera de los primeros ' + fmtN(Engine.MAX_PKTS) + ' de la captura y no se pueden reconstruir.</div>'; return; }
    const f = r.flow, [dc, ds] = r.dirs, total = dc.bytes.length + ds.bytes.length;
    const open = dc.syn ? 'empezó con SYN' : 'empezó antes de la captura (no se vio el SYN)';
    const close = dc.rst || ds.rst ? 'terminó con RST' : dc.fin && ds.fin ? 'se cerró con FIN' : dc.fin || ds.fin ? 'se cerró solo por un lado' : 'seguía abierta al final de la captura';
    const warn = [];
    if (dc.missing + ds.missing) warn.push(fmtB(dc.missing + ds.missing) + ' sin capturar');
    if (dc.retrans + ds.retrans) warn.push(fmtN(dc.retrans + ds.retrans) + ' segmentos retransmitidos o solapados');
    if (dc.truncated || ds.truncated) warn.push('flujo recortado por tamaño o por un salto de secuencia');
    el.innerHTML = `
      <div class="box">
        <div class="box-head"><h2>Flujo TCP <span class="mono">${esc(endp(r.client))} → ${esc(endp(r.server))}</span><small>conversación ${f.id}${r.conns > 1 ? ', conexión ' + (r.k + 1) + ' de ' + r.conns : ''}</small></h2>
          <button class="btn small ghost" data-goto="conversaciones">Volver a conversaciones</button></div>
        <p class="hint" style="margin:0 0 10px">${fmtN(r.pkts)} paquetes desde ${relT(r.first)} durante ${esc(fmtDur(r.last - r.first))}. La conexión ${open} y ${close}. El cliente envió ${esc(fmtB(dc.bytes.length))} y el servidor ${esc(fmtB(ds.bytes.length))}.${warn.length ? ' <span class="warn">' + esc(warn.join('; ')) + '.</span>' : ''}</p>
        <div class="toolbar">
          ${r.conns > 1 ? '<label class="hint" for="followConn">Conexión</label><select id="followConn" class="btn small">' + Array.from({length: r.conns}, (_, i) => '<option value="' + i + '"' + (i === r.k ? ' selected' : '') + '>' + (i + 1) + ' de ' + r.conns + '</option>').join('') + '</select>' : ''}
          <label class="hint" for="followDir">Mostrar</label>
          <select id="followDir" class="btn small"><option value="ambos">Toda la conversación (${esc(fmtB(total))})</option><option value="0">Solo cliente → servidor (${esc(fmtB(dc.bytes.length))})</option><option value="1">Solo servidor → cliente (${esc(fmtB(ds.bytes.length))})</option></select>
          <label class="hint" for="followFmt">Formato</label>
          <select id="followFmt" class="btn small"><option value="ascii">ASCII</option><option value="utf8">UTF-8</option><option value="hex">Hexadecimal</option></select>
        </div>
        <div class="legend" style="margin:0 0 8px"><span><i style="background:var(--s6)"></i>Cliente ${esc(endp(r.client))}</span><span><i style="background:var(--s1)"></i>Servidor ${esc(endp(r.server))}</span></div>
        <div class="stream" id="stream">${followTurnsHtml(r)}</div>
        <div class="row-actions" style="margin-top:10px">
          <button class="btn small" id="dlCli"${dc.bytes.length ? '' : ' disabled'}>Descargar cliente → servidor</button>
          <button class="btn small" id="dlSrv"${ds.bytes.length ? '' : ' disabled'}>Descargar servidor → cliente</button>
          <button class="btn small" id="dlTxt"${total ? '' : ' disabled'}>Descargar diálogo (.txt)</button>
          <button class="btn small ghost" id="followPkts">Ver paquetes</button>
          <button class="btn small ghost" id="followAsk">Preguntar al agente</button>
        </div>
      </div>
      <div class="box"><div class="box-head"><h2>Archivos extraídos de esta conexión</h2></div>
        ${r.files.length ? '<div class="file-list">' + r.files.map(fileItem).join('') + '</div>' : '<p class="muted" style="margin:0">No se extrajeron archivos de esta conexión.</p>'}</div>`;
    $('#followDir').value = S.followDir; $('#followFmt').value = S.followFmt;
    const redraw = () => { $('#stream').innerHTML = followTurnsHtml(r); };
    $('#followDir').addEventListener('change', e => { S.followDir = e.target.value; redraw(); });
    $('#followFmt').addEventListener('change', e => { S.followFmt = e.target.value; redraw(); });
    const fc = $('#followConn'); if (fc) fc.addEventListener('change', e => { S.follow.k = +e.target.value; renderFollow(); });
    const base = 'flujo-' + f.id + (r.conns > 1 ? '-' + (r.k + 1) : '');
    $('#dlCli').addEventListener('click', () => saveBinary(base + '-cliente.bin', [dc.bytes]));
    $('#dlSrv').addEventListener('click', () => saveBinary(base + '-servidor.bin', [ds.bytes]));
    $('#dlTxt').addEventListener('click', () => saveFile(base + '.txt', dialogText(r)));
    $('#followPkts').addEventListener('click', () => { S.pktFilter = 'ip:' + r.client.ip + ' ip:' + r.server.ip + ' puerto:' + r.client.port + ' puerto:' + r.server.port; renderPackets(); setTab('paquetes'); });
    $('#followAsk').addEventListener('click', () => askAgent('Sigue el flujo TCP de la conversación ' + f.id + (r.conns > 1 ? ' (conexión ' + (r.k + 1) + ')' : '') + ' entre ' + endp(r.client) + ' y ' + endp(r.server) + ' y explícame qué se dijeron y si hay algo sospechoso.'));
  }

  // ---------- Extracted files ----------
  const DIR_LABEL = {descarga: 'Descarga', subida: 'Subida'};
  const sumsText = F => F.map(f => f.sha256 + '  ' + f.saveAs).join('\n') + '\n';
  function fileItem(f) {
    const st = [f.complete ? '<span class="ok">Completo</span>' : '<span class="warn">Incompleto</span>'];
    if (f.kind === 'exe') st.push('<span class="bad">' + (f.disguised ? 'Ejecutable con extensión engañosa' : 'Ejecutable') + '</span>');
    return `<div class="file-item${f.kind === 'exe' ? ' exe' : ''}">
      <div class="fi-head"><span class="proto-tag">${esc(f.proto)}</span><strong class="fi-name">${esc(f.name)}</strong><span class="muted">${esc(f.type)}, ${esc(fmtB(f.size))}</span>${st.join('')}</div>
      <div class="fi-path mono" title="${esc(f.path)}">${esc(f.path)}</div>
      <div class="fi-hash"><span class="muted">SHA-256</span><code class="hash">${f.sha256}</code><button class="btn small ghost" data-hash="${f.n}">Copiar</button></div>
      <div class="fi-meta">${DIR_LABEL[f.dir] || ''} de <span class="mono">${esc(f.src)}:${f.sport}</span> a <span class="mono">${esc(f.dst)}:${f.dport}</span>, en ${relT(f.t)}${f.mime ? ', declarado como ' + esc(f.mime) : ''}</div>
      ${f.notes.length ? '<ul class="fi-notes">' + f.notes.map(n => '<li>' + esc(n) + '</li>').join('') + '</ul>' : ''}
      <div class="row-actions"><button class="btn small" data-dl="${f.n}">Descargar</button><button class="btn small ghost" data-follow="${f.fid}:${f.conn}">Ver conversación</button><button class="btn small ghost" data-ask-file="${f.n}">Preguntar al agente</button></div>
    </div>`;
  }
  function renderFiles() {
    const el = $('#p-archivos'); if (!S.M) { el.innerHTML = ''; return; }
    const F = S.M.files, notes = S.M.fileNotes;
    const notesHtml = notes.length ? '<details class="box"><summary>Avisos de la extracción (' + notes.length + ')</summary><ul class="fi-notes">' + notes.map(n => '<li>' + esc(n) + '</li>').join('') + '</ul></details>' : '';
    if (!F.length) { el.innerHTML = '<div class="empty-note">No se encontraron archivos transferidos en claro por HTTP, FTP o SMB2.<br>El tráfico cifrado (HTTPS, FTPS, SMB3 cifrado) no se puede reconstruir sin las claves.</div>' + notesHtml; return; }
    const by = {}; F.forEach(f => by[f.proto] = (by[f.proto] || 0) + 1);
    const exe = F.filter(f => f.kind === 'exe').length;
    el.innerHTML = `
      <div class="toolbar"><label class="sr" for="fileFilter">Filtrar archivos</label>
        <input type="search" id="fileFilter" placeholder="Filtrar por nombre, hash, IP, protocolo o tipo" value="${esc(S.fileFilter)}">
        <button class="btn small" id="btnZip">Descargar todo (.zip)</button><button class="btn small" id="btnSums">Exportar SHA256SUMS</button></div>
      <p class="hint" style="margin:-4px 0 6px">${F.length} archivo(s) reconstruidos: ${Object.entries(by).map(([k, v]) => v + ' por ' + k).join(', ')}${exe ? ', <span class="bad">' + exe + ' ejecutable(s)</span>' : ''}. El SHA-256 se calcula sobre el contenido final, sin cabeceras HTTP y con chunked y gzip ya decodificados. Para verificarlos después: <span class="mono">sha256sum -c SHA256SUMS.txt</span> (Linux), <span class="mono">shasum -a 256 -c SHA256SUMS.txt</span> (macOS) o <span class="mono">Get-FileHash -Algorithm SHA256</span> (PowerShell).</p>
      <p class="warn" style="margin:0 0 12px;font-size:13px">Pueden contener malware: ábrelos solo en una máquina aislada.</p>
      <div class="file-list" id="fileList"></div>${notesHtml}`;
    let tmr; $('#fileFilter').addEventListener('input', e => { clearTimeout(tmr); tmr = setTimeout(() => { S.fileFilter = e.target.value; fillFiles(); }, 180); });
    $('#btnZip').addEventListener('click', () => saveBinary('archivos-' + S.file.replace(/\.[^.]+$/, '') + '.zip', zipParts([...F.map(f => ({name: f.saveAs, data: f.data})), {name: 'SHA256SUMS.txt', data: new TextEncoder().encode(sumsText(F))}])));
    $('#btnSums').addEventListener('click', () => saveFile('SHA256SUMS.txt', sumsText(F)));
    fillFiles();
  }
  function fillFiles() {
    const q = S.fileFilter.trim().toLowerCase();
    const list = S.M.files.filter(f => !q || [f.name, f.path, f.sha256, f.proto, f.type, f.src, f.dst, f.mime].join(' ').toLowerCase().includes(q));
    $('#fileList').innerHTML = list.length ? list.slice(0, 500).map(fileItem).join('') + (list.length > 500 ? '<p class="muted">Se muestran 500 de ' + fmtN(list.length) + '. Usa el filtro o descarga el ZIP.</p>' : '') : '<p class="muted">Ningún archivo coincide con el filtro.</p>';
  }
  $('#content').addEventListener('click', async e => {
    const file = n => S.M && S.M.files.find(f => f.n === +n);
    const dl = e.target.closest('[data-dl]'), hs = e.target.closest('[data-hash]'), ak = e.target.closest('[data-ask-file]');
    if (dl) { const f = file(dl.dataset.dl); if (f) saveBinary(f.saveAs, [f.data]); }
    else if (hs) { const f = file(hs.dataset.hash); if (f) toast(await copyText(f.sha256) ? 'SHA-256 copiado' : 'No se pudo copiar'); }
    else if (ak) { const f = file(ak.dataset.askFile); if (f) askAgent('Analiza el archivo n.º ' + f.n + ' "' + f.name + '" (' + f.proto + ', SHA-256 ' + f.sha256 + '): de dónde viene, qué es según su contenido, si parece peligroso y qué debería hacer con él.'); }
  });

  // ---------- Incident timeline (phases + MITRE ATT&CK) ----------
  const phaseLabel = id => (Engine.PHASES.find(p => p.id === id) || {label: id}).label;
  const techChip = m => '<a class="tech" href="' + esc(m.url) + '" target="_blank" rel="noopener noreferrer" title="' + esc(m.name + ' (táctica: ' + m.tactic + ')') + '"><b>' + esc(m.id) + '</b> ' + esc(m.name) + '</a>';
  const techChips = list => '<span class="techs">' + list.map(techChip).join('') + '</span>';
  function renderIncident() {
    const el = $('#p-incidente'); if (!S.M) { el.innerHTML = ''; return; }
    const M = S.M, I = Engine.incident(M), rel = t => relShort(t - M.start);
    if (!M.findings.length) { el.innerHTML = '<div class="empty-note">No hay hallazgos, así que no hay un incidente que ordenar por fases.</div>'; return; }
    const active = I.phases.filter(p => p.findings.length), first = Math.min(...active.map(p => p.start)), last = Math.max(...active.map(p => p.end));
    const orderNote = I.inOrder ? 'Las fases aparecen en el orden habitual de un ataque.'
      : 'Las fases no siguen el orden habitual (' + I.order.map(phaseLabel).join(' → ') + '): puede haber varias actividades independientes, o un equipo comprometido antes de que empezara la captura.';
    el.innerHTML = `
      <div class="box hero">
        <div class="box-head"><h2>Línea de tiempo del incidente<small>${M.findings.length} hallazgos en ${active.length} fase(s), de ${rel(first)} a ${rel(last)}</small></h2>
          <div class="row-actions"><button class="btn small" id="btnNavigator">Exportar capa ATT&amp;CK Navigator</button><button class="btn small" id="btnAskIncident">Preguntar al agente</button></div></div>
        <p class="hint" style="margin:0 0 8px">${esc(orderNote)} Cada barra va del primer al último evento del hallazgo; haz clic para ver el detalle.</p>
        <div class="gantt" id="gantt"></div>
        <div class="legend"><span><i style="background:var(--alta)"></i>Severidad alta</span><span><i style="background:var(--media)"></i>Media</span><span><i class="hollow"></i>Baja (solo contorno)</span></div>
        <div class="readout" id="ganttReadout">Pasa el cursor sobre una barra para ver el hallazgo y sus técnicas.</div>
      </div>
      ${I.links.length ? '<div class="box"><div class="box-head"><h2>Equipos que conectan las fases<small>aparecen en hallazgos de más de una fase</small></h2></div><ul class="links">' +
        I.links.map(l => '<li><span class="mono">' + esc(l.ip) + '</span> <span class="muted">' + (l.internal ? 'interno' : 'externo') + (l.name ? ', ' + esc(l.name) : '') + '</span>: ' + l.phases.map(phaseLabel).join(' → ') + '</li>').join('') + '</ul></div>' : ''}
      ${I.phases.filter(p => p.findings.length || p.id !== 'impacto').map(p => `
        <section class="box phase${p.findings.length ? '' : ' empty'}">
          <div class="box-head"><h2>${esc(p.label)}<small>${p.findings.length ? p.findings.length + ' hallazgo(s), de ' + rel(p.start) + ' a ' + rel(p.end) : 'sin actividad detectada'}</small></h2></div>
          <p class="hint" style="margin:0 0 8px">${esc(p.desc)}</p>
          ${p.techniques.length ? '<div style="margin-bottom:8px">' + techChips(p.techniques) + '</div>' : ''}
          ${p.findings.length ? '<ol class="events">' + p.findings.map(f => '<li><span class="mono ev-t">' + rel(f.t) + (f.tEnd - f.t >= 1 ? '–' + rel(f.tEnd) : '') + '</span><span class="sev ' + f.sev + '"><i class="dot ' + f.sev + '"></i> ' + SEV_LABEL[f.sev] + '</span><div class="ev-body"><button class="linkish" data-finding="' + f.id + '">' + esc(f.title) + '</button><div class="muted ev-ips mono">' + esc([...new Set(f.ips)].slice(0, 5).join(', ')) + '</div>' + techChips(f.mitre) + '</div></li>').join('') + '</ol>' : ''}
        </section>`).join('')}`;
    $('#btnNavigator').addEventListener('click', () => saveFile('attack-navigator-' + S.file.replace(/\.[^.]+$/, '') + '.json', navigatorLayer()));
    $('#btnAskIncident').addEventListener('click', () => askAgent('Reconstruye la historia de este incidente fase por fase (reconocimiento, acceso, comando y control, exfiltración) usando la línea de tiempo y las técnicas MITRE ATT&CK. Indica qué hallazgos parecen relacionados entre sí y cuáles son independientes.'));
    requestAnimationFrame(drawIncident);
  }
  // Gantt chart: one lane per phase, one bar per finding (start to last event), rows packed so bars never overlap.
  function drawIncident() {
    const M = S.M, wrap = document.getElementById('gantt'); if (!M || !wrap || !wrap.clientWidth) return;
    const lanes = Engine.incident(M).phases.filter(p => p.findings.length || p.id !== 'impacto');
    // Narrow screens put the phase name above its lane instead of in a left column.
    const W = wrap.clientWidth, narrow = W < 520, L = narrow ? 4 : Math.min(150, Math.max(110, W * 0.18)), R = 12, T = 6, B = 24, ROW = 16, BAR = 10, PAD = 7, HEAD = narrow ? 18 : 0;
    const pw = W - L - R, dur = M.duration || 1, X = t => L + (t - M.start) / dur * pw;
    let y = T, body = '';
    for (const ln of lanes) {
      const rows = [], placed = [];
      for (const f of ln.findings) {
        const x0 = X(f.t), x1 = Math.max(x0 + 8, X(f.tEnd));
        let r = rows.findIndex(end => end + 3 <= x0); if (r < 0) { r = rows.length; rows.push(0); }
        rows[r] = x1; placed.push({f, x0, x1, r});
      }
      const h = Math.max(narrow ? 0 : 38, HEAD + Math.max(1, rows.length) * ROW + PAD * 2), top = y + HEAD + PAD, n = ln.findings.length ? ln.findings.length + ' hallazgo(s)' : 'sin actividad';
      body += '<line class="grid" x1="0" x2="' + W + '" y1="' + (y + h).toFixed(1) + '" y2="' + (y + h).toFixed(1) + '"/>';
      body += narrow ? '<text class="lane' + (ln.findings.length ? '' : ' off') + '" x="0" y="' + (y + 15) + '">' + esc(ln.label) + ' <tspan class="axis">' + n + '</tspan></text>'
        : '<text class="lane' + (ln.findings.length ? '' : ' off') + '" x="0" y="' + (y + PAD + 11) + '">' + esc(ln.label) + '</text><text class="axis" x="0" y="' + (y + PAD + 24) + '">' + n + '</text>';
      for (const b of placed) {
        const by = top + b.r * ROW + (ROW - BAR) / 2, w = b.x1 - b.x0, f = b.f;
        body += f.sev === 'baja'
          ? '<rect x="' + (b.x0 + 0.75).toFixed(1) + '" y="' + (by + 0.75).toFixed(1) + '" width="' + Math.max(1, w - 1.5).toFixed(1) + '" height="' + (BAR - 1.5) + '" rx="3" fill="var(--surface)" stroke="var(--baja)" stroke-width="1.5" pointer-events="none"/>'
          : '<rect x="' + b.x0.toFixed(1) + '" y="' + by.toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + BAR + '" rx="3" fill="var(--' + f.sev + ')" pointer-events="none"/>';
        body += '<rect class="hit" data-finding="' + f.id + '" x="' + (b.x0 - 3).toFixed(1) + '" y="' + (top + b.r * ROW).toFixed(1) + '" width="' + (w + 6).toFixed(1) + '" height="' + ROW + '"/>';
      }
      y += h;
    }
    const H = y + B, ticks = Math.max(2, Math.min(7, Math.floor(pw / 110)));
    let axis = '';
    for (let t = 0; t <= ticks; t++) { const x = L + pw * t / ticks; axis += '<line class="grid" x1="' + x.toFixed(1) + '" x2="' + x.toFixed(1) + '" y1="' + T + '" y2="' + y + '" stroke-dasharray="2 4"/><text class="axis" x="' + x.toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + (t === 0 ? 'start' : t === ticks ? 'end' : 'middle') + '">' + relShort(M.duration * t / ticks) + '</text>'; }
    wrap.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" height="' + H + '" role="img" aria-label="Línea de tiempo de los hallazgos por fase del incidente">' + axis + body + '</svg>';
    const ro = $('#ganttReadout');
    wrap.querySelectorAll('.hit').forEach(r => {
      r.addEventListener('mouseenter', () => {
        const f = M.findings.find(x => x.id === r.dataset.finding);
        ro.innerHTML = '<b>' + esc(f.title) + '</b> (' + SEV_LABEL[f.sev].toLowerCase() + ', ' + esc(phaseLabel(f.phase)) + ') de ' + relShort(f.t - M.start) + ' a ' + relShort(f.tEnd - M.start) + '. ' + esc(f.mitre.map(m => m.id + ' ' + m.name).join(', ')) + '.';
      });
    });
    wrap.querySelector('svg').addEventListener('mouseleave', () => { ro.textContent = 'Pasa el cursor sobre una barra para ver el hallazgo y sus técnicas.'; });
  }
  // Layer for the MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/): one entry per technique, colored by worst severity.
  function navigatorLayer() {
    const rank = {alta: 3, media: 2, baja: 1}, color = {3: '#ff6666', 2: '#ffb84d', 1: '#ffe766'}, by = new Map();
    for (const f of S.M.findings) for (const m of f.mitre) { const e = by.get(m.id) || {score: 0, titles: []}; e.score = Math.max(e.score, rank[f.sev]); e.titles.push(f.title); by.set(m.id, e); }
    const techniques = [...by].map(([id, e]) => ({techniqueID: id, score: e.score, color: color[e.score], comment: e.titles.join('; '), enabled: true, showSubtechniques: false}));
    for (const id of by.keys()) {
      if (!id.includes('.')) continue;
      const pid = id.split('.')[0], parent = techniques.find(t => t.techniqueID === pid);
      if (parent) parent.showSubtechniques = true; else techniques.push({techniqueID: pid, enabled: true, showSubtechniques: true});
    }
    return JSON.stringify({name: 'Sonda: ' + S.file, versions: {layer: '4.5', navigator: '5.1.0'}, domain: 'enterprise-attack',
      description: 'Técnicas observadas por Sonda en ' + S.file + ' (' + new Date().toLocaleString('es-ES') + '). Color según la severidad más alta del hallazgo.',
      sorting: 3, hideDisabled: false, techniques, legendItems: [{label: 'Severidad alta', color: color[3]}, {label: 'Severidad media', color: color[2]}, {label: 'Severidad baja', color: color[1]}],
      showTacticRowBackground: false, selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false}, null, 2);
  }

  // ---------- Findings ----------
  const ruleAdded = text => S.rules.some(r => r.text.trim() === text.trim());
  function renderFindings() {
    const el = $('#p-hallazgos'); if (!S.M) { el.innerHTML = ''; return; }
    const F = S.M.findings, sev = sevCounts();
    if (!F.length) { el.innerHTML = '<div class="empty-note">No se detectaron patrones sospechosos con las heurísticas actuales.<br>Pregúntale al agente si quieres una revisión manual de algo concreto.</div>'; return; }
    el.innerHTML = '<div class="toolbar"><span class="hint" style="flex:1">' + F.length + ' hallazgos: ' + sev.alta + ' de severidad alta, ' + sev.media + ' media y ' + sev.baja + ' baja. Son heurísticas: confírmalos antes de actuar.</span><button class="btn small" id="addAllRules">Añadir todas las reglas sugeridas</button></div>' +
      F.map(f => `<article class="finding ${f.sev}" id="f-${f.id}">
        <header><h3 tabindex="-1">${esc(f.title)}</h3><span class="sev ${f.sev}">${SEV_LABEL[f.sev]}</span><span class="meta">${esc(f.cat)}, desde ${relShort(f.t - S.M.start)}</span></header>
        <div class="f-attack"><button class="linkish" data-goto="incidente">Fase: ${esc(phaseLabel(f.phase))}</button>${techChips(f.mitre)}</div>
        <p>${esc(f.desc)}</p>
        <ul>${f.evidence.map(e => '<li>' + esc(e) + '</li>').join('')}</ul>
        ${f.rules.map((r, i) => '<pre class="rule">' + esc(r) + '</pre><div class="row-actions" style="margin-bottom:8px">' + (ruleAdded(r) ? '<span class="ok" style="font-size:13px">Añadida a tus reglas</span>' : '<button class="btn small" data-add-rule="' + f.id + ':' + i + '">Añadir a mis reglas</button>') + '</div>').join('')}
        <div class="row-actions"><button class="btn small ghost" data-ask="${f.id}">Preguntar al agente</button><button class="btn small ghost" data-pkts="${f.id}">Ver paquetes implicados</button></div>
      </article>`).join('');
    $('#addAllRules').addEventListener('click', () => { let n = 0; F.forEach(f => f.rules.forEach(r => { if (addRule(r, 'hallazgo', f.title).rule) n++; })); toast(n ? n + ' reglas añadidas' : 'Ya estaban todas añadidas'); renderFindings(); });
    el.querySelectorAll('[data-add-rule]').forEach(b => b.addEventListener('click', () => {
      const [fid, i] = b.dataset.addRule.split(':'); const f = F.find(x => x.id === fid); const res = addRule(f.rules[+i], 'hallazgo', f.title);
      toast(res.rule ? 'Regla añadida' : res.error || 'Esa regla ya estaba añadida'); renderFindings();
    }));
    el.querySelectorAll('[data-ask]').forEach(b => b.addEventListener('click', () => { const f = F.find(x => x.id === b.dataset.ask); askAgent('Explícame el hallazgo "' + f.title + '": qué significa, cómo confirmarlo en la captura y qué debería hacer.'); }));
    el.querySelectorAll('[data-pkts]').forEach(b => b.addEventListener('click', () => {
      const f = F.find(x => x.id === b.dataset.pkts); const ips = [...new Set(f.ips)].slice(0, 2);
      S.pktFilter = ips.map(ip => 'ip:' + ip).join(' '); renderPackets(); setTab('paquetes');
    }));
  }

  // ---------- Rules ----------
  function nextSid() { let m = S.M ? S.M.nextSid - 1 : 1000000; for (const r of S.rules) if (r.test && r.test.sid) m = Math.max(m, r.test.sid); return Math.max(m + 1, 1000001); }
  function storeHits(r) { if (r.test && r.test.sid && r.test.sample) S.hits[String(r.test.sid)] = r.test.sample; }
  function addRule(text, source, note) {
    text = String(text || '').trim();
    if (!text) return {error: 'La regla está vacía'};
    if (ruleAdded(text)) return {dup: true, error: 'Esa regla ya está en tu lista'};
    const test = Engine.testRule(text, S.M);
    if (test.errors && test.errors.length) return {error: 'La regla tiene errores: ' + test.errors.join(' '), test};
    if (test.sid && S.rules.some(r => r.test && r.test.sid === test.sid)) return {error: 'Ya existe una regla con sid ' + test.sid + '. Usa sid:' + nextSid() + '.', test};
    const r = {id: ++S.ruleSeq, text, source, note: note || '', test};
    S.rules.push(r); storeHits(r); renderRules(); updateCounts();
    return {rule: r};
  }
  const SRC_LABEL = {hallazgo: 'Sugerida por un hallazgo', agente: 'Creada por el agente', ia: 'Generada con IA', manual: 'Escrita a mano'};
  function ruleStatusHtml(r) {
    const t = r.test || {};
    if (t.comment) return '<span class="muted">Configuración o comentario; no es una regla de detección, se exporta tal cual.</span>';
    if (t.errors && t.errors.length) return '<span class="bad">Error: ' + esc(t.errors.join(' ')) + '</span>';
    let h = '<span class="ok">Sintaxis válida</span>';
    if (t.hits === null || t.hits === undefined) h += '<span class="muted">Carga una captura para probarla</span>';
    else h += t.hits ? '<span><b>' + fmtN(t.hits) + '</b> alertas en esta captura</span><button class="btn small ghost" data-see="' + t.sid + '">Ver paquetes</button>' : '<span class="muted">0 alertas en esta captura</span>';
    if (t.warnings && t.warnings.length) h += '<span class="warn">' + esc(t.warnings.join(' ')) + '</span>';
    if (t.ignored && t.ignored.length) h += '<span class="muted">No evaluado en la prueba: ' + esc(t.ignored.join(', ')) + '</span>';
    return h;
  }
  function renderRules() {
    const el = $('#p-reglas');
    const real = S.rules.filter(r => !r.test || !r.test.comment).length;
    el.innerHTML = `
      <div class="box">
        <div class="box-head"><h2>Crear regla con el agente</h2></div>
        <div class="composer">
          <label class="sr" for="aiRuleDesc">Describe lo que quieres detectar</label>
          <textarea id="aiRuleDesc" placeholder="Describe lo que quieres detectar. Ej.: alertar cuando un equipo interno haga más de 50 consultas DNS en un minuto"></textarea>
          <div class="row-actions"><button class="btn primary" id="btnAiRule">Generar regla</button><span class="hint">El agente la escribe, Sonda valida la sintaxis y la prueba contra la captura antes de que la añadas.</span></div>
          <div id="aiRuleOut"></div>
        </div>
      </div>
      <div class="box">
        <div class="box-head"><h2>Mis reglas<small>${real} regla${real === 1 ? '' : 's'}, compatibles con Snort 2.9 y Snort 3</small></h2>
          <div class="row-actions"><button class="btn small" id="btnExport" ${S.rules.length ? '' : 'disabled'}>Exportar local.rules</button><button class="btn small" id="btnCopyRules" ${S.rules.length ? '' : 'disabled'}>Copiar todo</button></div></div>
        <div id="ruleList">${S.rules.length ? S.rules.map(r => `
          <div class="rule-item" data-id="${r.id}">
            <div class="rule-src">${esc(SRC_LABEL[r.source] || '')}${r.note ? ': ' + esc(r.note) : ''}</div>
            <label class="sr" for="rt${r.id}">Texto de la regla</label>
            <textarea id="rt${r.id}" spellcheck="false" rows="${Math.min(6, Math.max(2, r.text.split('\n').reduce((a, l) => a + Math.max(1, Math.ceil(l.length / 100)), 0)))}">${esc(r.text)}</textarea>
            <div class="rule-status">${ruleStatusHtml(r)}<span style="flex:1"></span><button class="btn small ghost" data-del="${r.id}">Eliminar</button></div>
          </div>`).join('') : '<p class="muted" style="margin:0">Todavía no tienes reglas. Añádelas desde la pestaña Hallazgos, pídeselas al agente o escríbelas abajo.</p>'}</div>
      </div>
      <details class="box"><summary>Escribir una regla a mano</summary>
        <div class="composer">
          <label class="sr" for="manualRule">Regla Snort</label>
          <textarea id="manualRule" class="mono" spellcheck="false">alert tcp any any -> $HOME_NET 22 (msg:"SONDA Conexion SSH entrante"; flags:S; classtype:policy-violation; sid:${nextSid()}; rev:1;)</textarea>
          <div class="row-actions"><button class="btn" id="btnTestManual">Probar</button><button class="btn primary" id="btnAddManual">Añadir regla</button><span class="hint" id="manualOut"></span></div>
        </div>
      </details>`;
    $('#btnAiRule').addEventListener('click', generateRule);
    if (S.aiRuleDraft) showDraft();
    $('#btnExport').addEventListener('click', () => saveFile('sonda-local.rules.txt', buildRulesFile()));
    $('#btnCopyRules').addEventListener('click', async () => toast(await copyText(buildRulesFile()) ? 'Reglas copiadas' : 'No se pudo copiar'));
    $('#btnTestManual').addEventListener('click', () => { const t = Engine.testRule($('#manualRule').value, S.M); $('#manualOut').innerHTML = t.errors.length ? '<span class="bad">' + esc(t.errors.join(' ')) + '</span>' : '<span class="ok">Válida.</span> ' + (t.hits === null ? '' : fmtN(t.hits) + ' alertas en la captura.'); });
    $('#btnAddManual').addEventListener('click', () => { const res = addRule($('#manualRule').value, 'manual'); toast(res.rule ? 'Regla añadida' : res.error); });
    el.querySelectorAll('.rule-item textarea').forEach(ta => ta.addEventListener('change', () => {
      const r = S.rules.find(x => x.id === +ta.closest('.rule-item').dataset.id); if (!r) return;
      r.text = ta.value.trim(); r.test = Engine.testRule(r.text, S.M); storeHits(r);
      ta.closest('.rule-item').querySelector('.rule-status').innerHTML = ruleStatusHtml(r) + '<span style="flex:1"></span><button class="btn small ghost" data-del="' + r.id + '">Eliminar</button>';
      updateCounts();
    }));
  }
  function ruleListClick(e) {
    const del = e.target.closest('[data-del]');
    if (del) { S.rules = S.rules.filter(r => r.id !== +del.dataset.del); renderRules(); updateCounts(); if (S.M) renderFindings(); return; }
    const see = e.target.closest('[data-see]');
    if (see) { S.pktFilter = 'regla:' + see.dataset.see; renderPackets(); setTab('paquetes'); }
  }
  function buildRulesFile() {
    const head = ['# local.rules generado por Sonda el ' + new Date().toLocaleString('es-ES'), S.file ? '# Captura analizada: ' + S.file : '', '# Antes de usarlas, define $HOME_NET y $EXTERNAL_NET en snort.lua (Snort 3) o snort.conf (Snort 2).', '# Guarda este archivo como local.rules e inclúyelo en tu configuración.', ''].filter((l, i) => l || i === 4);
    return head.join('\n') + '\n' + S.rules.map(r => (r.note ? '# ' + r.note.replace(/\n/g, ' ') + '\n' : '') + r.text).join('\n\n') + '\n';
  }
  async function generateRule() {
    const desc = $('#aiRuleDesc').value.trim(), out = $('#aiRuleOut');
    if (!desc) { out.innerHTML = '<p class="bad">Describe primero qué quieres detectar.</p>'; return; }
    if (!S.sample) { out.innerHTML = '<p class="bad">' + esc(aiUnavailableText()) + '</p>'; return; }
    const btn = $('#btnAiRule'); btn.disabled = true; out.innerHTML = '<p class="thinking">Escribiendo la regla…</p>';
    const ctx = S.M ? Engine.summary(S.M, S.file) : null;
    if (ctx) { delete ctx.hallazgos.lista; }
    const prompt = 'Eres experto en Snort. Escribe UNA regla Snort compatible con Snort 2.9 y Snort 3 para esta necesidad: "' + desc + '".\n' +
      'Requisitos: usa sid:' + nextSid() + '; rev:1; msg sin tildes que empiece por "SONDA "; classtype adecuado; $HOME_NET/$EXTERNAL_NET cuando tenga sentido; detection_filter para umbrales; flow:to_server,established para contenido de aplicación TCP; escapa ; " y \\ dentro de content con |3B| |22| |5C|. Una sola línea.\n' +
      (ctx ? 'Contexto de la captura cargada (úsalo para elegir IPs o puertos si la descripción lo pide): ' + JSON.stringify(ctx) + '\n' : '') +
      'Responde solo con JSON: {"regla": "alert ...", "explicacion": "2-3 frases en español: qué detecta, cómo funciona y posibles falsos positivos"}';
    try {
      const res = await S.sample.json(prompt);
      if (!res || typeof res.regla !== 'string') throw {code: 'invalid_json'};
      S.aiRuleDraft = {text: res.regla.trim(), explanation: String(res.explicacion || ''), desc};
      showDraft();
    } catch (e) { out.innerHTML = '<p class="bad">' + esc(aiErrorText(e)) + '</p>'; }
    finally { btn.disabled = false; }
  }
  function showDraft() {
    const d = S.aiRuleDraft, out = $('#aiRuleOut'); if (!d || !out) return;
    const t = Engine.testRule(d.text, S.M);
    out.innerHTML = '<pre class="rule">' + esc(d.text) + '</pre><p style="margin:0 0 8px">' + esc(d.explanation) + '</p><div class="rule-status" style="margin:0 0 10px">' + ruleStatusHtml({test: t}).replace(/<button[^>]*data-see[^>]*>.*?<\/button>/, '') + '</div>' +
      '<div class="row-actions">' + (t.errors.length ? '' : '<button class="btn primary small" id="draftAdd">Añadir a mis reglas</button>') + '<button class="btn small" id="draftDiscard">Descartar</button></div>';
    const add = $('#draftAdd'); if (add) add.addEventListener('click', () => { const res = addRule(d.text, 'ia', d.desc); if (res.rule) { S.aiRuleDraft = null; renderRules(); toast('Regla añadida'); } else toast(res.error); });
    $('#draftDiscard').addEventListener('click', () => { S.aiRuleDraft = null; out.innerHTML = ''; });
  }

  // ---------- Report (PDF, Markdown, IoC and delivery package; see report.js) ----------
  const REPORT_KEY = 'sonda.informe', dlg = $('#reportDlg');
  const reportFields = {title: '#rTitle', caseId: '#rCase', org: '#rOrg', analyst: '#rAnalyst', tlp: '#rTlp'};
  $('#rTlp').innerHTML = Report.TLP.map(t => '<option>' + t + '</option>').join('');
  $('#btnReport').addEventListener('click', () => {
    let saved = {}; try { saved = JSON.parse(localStorage.getItem(REPORT_KEY) || '{}') || {}; } catch (e) {}
    for (const [k, sel] of Object.entries(reportFields)) $(sel).value = saved[k] || (k === 'tlp' ? 'TLP:AMBER' : '');
    $('#rInterp').disabled = !S.interp; $('#rInterp').checked = !!S.interp;
    $('#rInterpHint').textContent = S.interp ? '' : 'Para incluirla, pulsa antes "Interpretar captura" en el Resumen.';
    $('#rStatus').textContent = '';
    dlg.showModal();
  });
  function reportData() {
    const meta = {}; for (const [k, sel] of Object.entries(reportFields)) meta[k] = $(sel).value.trim();
    try { localStorage.setItem(REPORT_KEY, JSON.stringify(meta)); } catch (e) {}
    const rules = S.rules.filter(r => r.test && !r.test.comment && !(r.test.errors || []).length).map(r => ({text: r.text, note: r.note || SRC_LABEL[r.source] || '', hits: r.test.hits, sid: r.test.sid}));
    return Report.build(S.M, {file: S.file, meta, rules, interp: $('#rInterp').checked ? S.interp : ''});
  }
  const reportBase = D => ((D.meta.caseId ? D.meta.caseId + '-' : '') + S.file.replace(/\.[^.]+$/, '')).replace(/[^\w.-]+/g, '_').slice(0, 80);
  const textBytes = s => new TextEncoder().encode(s);
  function deliveryZip(D) {
    const base = reportBase(D), files = [
      {name: 'informe-' + base + '.pdf', data: Report.pdf(D)},
      {name: 'informe-' + base + '.md', data: textBytes(Report.markdown(D))},
      {name: 'iocs-' + base + '.csv', data: textBytes(Report.iocCsv(D))},
      {name: 'iocs-' + base + '.stix.json', data: textBytes(Report.stix(D))},
      {name: 'local.rules', data: textBytes(Report.rulesFile(D))}];
    if (S.M.files.length) files.push({name: 'archivos-extraidos-SHA256SUMS.txt', data: textBytes(sumsText(S.M.files))});
    files.push({name: 'LEEME.txt', data: textBytes([
      (D.meta.title || 'Informe de análisis de tráfico de red') + (D.meta.caseId ? ' (' + D.meta.caseId + ')' : ''), 'Clasificación: ' + D.meta.tlp, 'Captura: ' + S.file + (D.capture.sha256 ? ' (SHA-256 ' + D.capture.sha256 + ')' : ''), '',
      'informe-*.pdf               Informe completo para entregar.', 'informe-*.md                El mismo informe en Markdown, para editarlo o pegarlo en un ticket.', 'iocs-*.csv                  Indicadores de compromiso para hojas de cálculo y SIEM.',
      'iocs-*.stix.json            Los mismos indicadores en STIX 2.1 (MISP, OpenCTI y plataformas de inteligencia).', 'local.rules                 Reglas Snort, una por línea.',
      ...(S.M.files.length ? ['archivos-extraidos-SHA256SUMS  Hashes de los archivos extraídos. Los archivos no se incluyen porque pueden ser malware; se descargan desde la pestaña Archivos.'] : []),
      'SHA256SUMS.txt              Hashes de este paquete. Compruébalos con: sha256sum -c SHA256SUMS.txt', ''].join('\r\n'))});
    files.push({name: 'SHA256SUMS.txt', data: textBytes(files.map(f => Engine.sha256(f.data) + '  ' + f.name).join('\n') + '\n')});
    return zipParts(files);
  }
  $('#reportForm').addEventListener('submit', e => {
    const kind = e.submitter && e.submitter.value;
    if (kind === 'cancel' || !S.M) return;
    e.preventDefault();
    const st = $('#rStatus'), btns = dlg.querySelectorAll('button');
    st.textContent = 'Generando…'; btns.forEach(b => b.disabled = true);
    setTimeout(async () => {
      try {
        const D = reportData(), base = reportBase(D);
        if (kind === 'pdf') await saveBinary('informe-' + base + '.pdf', [Report.pdf(D)], 'application/pdf');
        else if (kind === 'zip') await saveBinary('entrega-' + base + '.zip', deliveryZip(D), 'application/zip');
        else if (kind === 'md') await saveFile('informe-' + base + '.md', Report.markdown(D));
        else if (kind === 'csv') await saveBinary('iocs-' + base + '.csv', [textBytes(Report.iocCsv(D))], 'text/csv');
        else if (kind === 'stix') await saveBinary('iocs-' + base + '.stix.json', [textBytes(Report.stix(D))], 'application/json');
        st.textContent = 'Listo. ' + D.iocs.length + ' indicadores y ' + D.findings.length + ' hallazgos en el informe.';
      } catch (err) { st.textContent = 'No se pudo generar: ' + ((err && err.message) || err); }
      finally { btns.forEach(b => b.disabled = false); }
    }, 30);
  });

  // ---------- Markdown ----------
  function inline(s) {
    return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:!?]|$)/g, '$1<em>$2</em>');
  }
  function md(src) {
    const lines = String(src || '').replace(/\r/g, '').split('\n'); let html = '', i = 0, list = null;
    const close = () => { if (list) { html += '</' + list + '>'; list = null; } };
    while (i < lines.length) {
      const l = lines[i]; let m;
      if (/^\s*```/.test(l)) {
        close(); const lang = l.replace(/^\s*```/, '').trim(), buf = []; i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
        i++; html += '<pre data-lang="' + esc(lang) + '"><code>' + esc(buf.join('\n')) + '</code></pre>'; continue;
      }
      if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
        close(); const cells = r => r.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
        html += '<div class="scroll-x"><table><thead><tr>' + cells(l).map(c => '<th>' + inline(c) + '</th>').join('') + '</tr></thead><tbody>'; i += 2;
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) html += '<tr>' + cells(lines[i++]).map(c => '<td>' + inline(c) + '</td>').join('') + '</tr>';
        html += '</tbody></table></div>'; continue;
      }
      if ((m = l.match(/^(#{1,6})\s+(.*)/))) { close(); const t = m[1].length <= 3 ? 'h3' : 'h4'; html += '<' + t + '>' + inline(m[2]) + '</' + t + '>'; i++; continue; }
      if ((m = l.match(/^\s*[-*•]\s+(.*)/))) { if (list !== 'ul') { close(); html += '<ul>'; list = 'ul'; } html += '<li>' + inline(m[1]) + '</li>'; i++; continue; }
      if ((m = l.match(/^\s*\d+[.)]\s+(.*)/))) { if (list !== 'ol') { close(); html += '<ol>'; list = 'ol'; } html += '<li>' + inline(m[1]) + '</li>'; i++; continue; }
      if (!l.trim()) { close(); i++; continue; }
      close(); const para = [l]; i++;
      while (i < lines.length && lines[i].trim() && !/^(\s*```|#{1,6}\s|\s*[-*•]\s|\s*\d+[.)]\s|\s*\|)/.test(lines[i])) para.push(lines[i++]);
      html += '<p>' + para.map(inline).join('<br>') + '</p>';
    }
    close(); return html;
  }
  const RULE_LINE = /^\s*(alert|drop|reject|log|pass|sdrop|block)\s+\w+\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s*\(.*\)\s*$/;
  function enhanceCode(root) {
    root.querySelectorAll('pre').forEach((pre, idx) => {
      if (pre.nextElementSibling && pre.nextElementSibling.classList.contains('code-actions')) return;
      const code = pre.textContent, rules = code.split('\n').filter(l => RULE_LINE.test(l));
      const bar = document.createElement('div'); bar.className = 'code-actions';
      bar.innerHTML = '<button class="btn small" data-copy>Copiar</button>' + (rules.length ? '<button class="btn small" data-addrules>Añadir ' + (rules.length > 1 ? rules.length + ' reglas' : 'regla') + ' a mis reglas</button>' : '');
      bar.querySelector('[data-copy]').addEventListener('click', async () => toast(await copyText(code) ? 'Copiado' : 'No se pudo copiar'));
      const ab = bar.querySelector('[data-addrules]');
      if (ab) ab.addEventListener('click', () => {
        const res = rules.map(r => addRule(r, 'agente'));
        const ok = res.filter(r => r.rule).length, err = res.find(r => r.error && !r.dup);
        toast(ok ? ok + ' regla(s) añadidas' : err ? err.error : 'Ya estaban en tu lista');
        if (ok) { ab.disabled = true; ab.textContent = 'Añadida'; if (S.M) renderFindings(); }
      });
      pre.after(bar);
    });
  }

  // ---------- Agent tools ----------
  function need() { if (!S.M) throw new Error('No hay ninguna captura cargada. Pide al usuario que abra un archivo pcap o use la captura de ejemplo.'); return S.M; }
  const pktRow = p => ({n: p.i, t: +(p.t - S.M.start).toFixed(3), origen: p.src + (p.sport ? ':' + p.sport : ''), destino: p.dst + (p.dport ? ':' + p.dport : ''), protocolo: p.label, bytes: p.len, info: p.info.slice(0, 180)});
  const flowRow = f => ({id: f.id, protocolo: f.proto, aplicacion: f.app, a: f.a + (f.ap ? ':' + f.ap : ''), b: f.b + (f.bp ? ':' + f.bp : ''), paquetes: f.pkts, bytes: f.bytes, bytes_a_a_b: f.ab, bytes_b_a_a: f.ba, inicio_t: +(f.first - S.M.start).toFixed(2), duracion_s: +(f.last - f.first).toFixed(2), syn: f.syn, syn_ack: f.synack, rst: f.rst});
  const lim = (v, d, max) => Math.max(1, Math.min(max, parseInt(v, 10) || d));
  const TOOL_LABEL = {resumen_captura: 'Leyendo el resumen de la captura', buscar_paquetes: 'Buscando paquetes', conversaciones: 'Revisando conversaciones', detalle_host: 'Analizando un host', consultas_dns: 'Revisando consultas DNS', trafico_web: 'Revisando tráfico web', listar_hallazgos: 'Leyendo los hallazgos', listar_reglas: 'Leyendo tus reglas', probar_regla_snort: 'Probando una regla contra la captura', crear_regla_snort: 'Guardando una regla', seguir_flujo_tcp: 'Reconstruyendo un flujo TCP', linea_de_tiempo_incidente: 'Ordenando el incidente por fases', archivos_transferidos: 'Revisando archivos transferidos'};
  // What the agent reads of a stream goes to the API: hide passwords as the rest of the tools do.
  const maskSecrets = s => s.replace(/^(\s*PASS\s+)\S.*$/gim, '$1(oculta)').replace(/(Authorization:\s*\w+\s+)\S+/gi, '$1(oculto)').replace(/((?:^|[&?\s])(?:pass(?:word)?|pwd|passwd|clave|contrasena)=)[^&\s]*/gi, '$1(oculta)');
  const isBinary = b => { let bad = 0; for (const c of b) if (c < 9 || (c > 13 && c < 32) || c > 126) bad++; return b.length > 0 && bad / b.length > 0.1; };
  const fileRow = f => ({n: f.n, nombre: f.name, ruta: f.path, protocolo: f.proto, sentido: f.dir, tipo_real: f.type, ejecutable: f.kind === 'exe', extension_enganosa: f.disguised, tipo_declarado: f.mime || undefined, bytes: f.size, sha256: f.sha256, completo: f.complete,
    origen: f.src + ':' + f.sport, destino: f.dst + ':' + f.dport, t: +(f.t - S.M.start).toFixed(3), conversacion: f.fid, conexion: f.conn + 1, notas: f.notes.length ? f.notes : undefined});
  function toolNote(name, input) {
    const b = S.curBot; if (!b) return;
    const bits = input ? Object.entries(input).filter(([k, v]) => v !== undefined && v !== '' && k !== 'regla' && k !== 'nota').map(([k, v]) => k + ' ' + v).join(', ') : '';
    const s = document.createElement('span'); s.textContent = (TOOL_LABEL[name] || name) + (bits ? ' (' + bits + ')' : ''); b.tools.append(s); scrollMsgs();
  }
  const T = (name, description, properties, fn) => ({name, description, inputSchema: {type: 'object', properties}, execute: async input => { input = input || {}; toolNote(name, input); return fn(input); }});
  const TOOLS = [
    T('resumen_captura', 'Resumen general de la captura cargada: volumen, duración, protocolos, hosts y puertos principales, dominios DNS, SNI TLS, hosts HTTP y lista de hallazgos.', {}, () => Engine.summary(need(), S.file)),
    T('buscar_paquetes', 'Busca paquetes por IP, puerto, protocolo (etiqueta como DNS, HTTP, TLS, TCP, ICMP, ARP...), texto en el resumen del paquete o rango de tiempo relativo en segundos. Devuelve como máximo 60.',
      {ip: {type: 'string'}, puerto: {type: 'integer'}, protocolo: {type: 'string'}, texto: {type: 'string', description: 'Texto a buscar en la información del paquete'}, desde_s: {type: 'number'}, hasta_s: {type: 'number'}, limite: {type: 'integer', description: 'Por defecto 25, máximo 60'}},
      i => {
        const M = need(), out = [], L = lim(i.limite, 25, 60); let total = 0;
        const proto = i.protocolo ? String(i.protocolo).toLowerCase() : null, txt = i.texto ? String(i.texto).toLowerCase() : null;
        for (const p of M.pkts) {
          if (i.ip && p.src !== i.ip && p.dst !== i.ip) continue;
          if (i.puerto && p.sport !== +i.puerto && p.dport !== +i.puerto) continue;
          if (proto && p.label.toLowerCase() !== proto && p.proto.toLowerCase() !== proto) continue;
          const r = p.t - M.start; if (i.desde_s !== undefined && r < +i.desde_s) continue; if (i.hasta_s !== undefined && r > +i.hasta_s) continue;
          if (txt && !p.info.toLowerCase().includes(txt)) continue;
          total++; if (out.length < L) out.push(pktRow(p));
        }
        return {coincidencias: total, mostrados: out.length, paquetes: out};
      }),
    T('conversaciones', 'Lista conversaciones (flujos TCP/UDP/ICMP) con bytes en cada sentido, banderas SYN/SYN-ACK/RST y duración. Se puede filtrar por IP, puerto o protocolo y ordenar.',
      {ip: {type: 'string'}, puerto: {type: 'integer'}, protocolo: {type: 'string'}, orden: {type: 'string', enum: ['bytes', 'paquetes', 'duracion', 'inicio']}, limite: {type: 'integer'}},
      i => {
        const M = need(); let l = M.flows;
        if (i.ip) l = l.filter(f => f.a === i.ip || f.b === i.ip);
        if (i.puerto) l = l.filter(f => f.ap === +i.puerto || f.bp === +i.puerto);
        if (i.protocolo) { const p = String(i.protocolo).toLowerCase(); l = l.filter(f => f.proto.toLowerCase() === p || f.app.toLowerCase() === p); }
        const o = i.orden; l = l.slice().sort((x, y) => o === 'paquetes' ? y.pkts - x.pkts : o === 'duracion' ? (y.last - y.first) - (x.last - x.first) : o === 'inicio' ? x.first - y.first : y.bytes - x.bytes);
        return {total: l.length, conversaciones: l.slice(0, lim(i.limite, 15, 40)).map(flowRow)};
      }),
    T('detalle_host', 'Perfil de una IP: tráfico enviado y recibido, con quién habla, servicios que ofrece y usa, consultas DNS, peticiones HTTP, SNI TLS y hallazgos relacionados.', {ip: {type: 'string'}},
      i => {
        const M = need(), h = M.hosts.get(i.ip);
        if (!h) return {error: 'La IP ' + i.ip + ' no aparece en la captura.'};
        const fl = M.flows.filter(f => f.a === i.ip || f.b === i.ip), peers = new Map(), served = new Map(), used = new Map();
        for (const f of fl) {
          const other = f.a === i.ip ? f.b : f.a, e = peers.get(other) || {ip: other, bytes: 0, conversaciones: 0}; e.bytes += f.bytes; e.conversaciones++; peers.set(other, e);
          if (f.b === i.ip && f.synack) served.set(f.proto + '/' + f.bp, (served.get(f.proto + '/' + f.bp) || 0) + 1);
          if (f.a === i.ip) used.set(f.proto + '/' + f.svc, (used.get(f.proto + '/' + f.svc) || 0) + 1);
        }
        const dns = new Map(); M.dns.filter(q => q.src === i.ip).forEach(q => dns.set(q.name, (dns.get(q.name) || 0) + 1));
        const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
        return {ip: i.ip, interno: Engine.isInternal(i.ip), mac: h.mac || undefined, nombre_dns: M.ipNames.get(i.ip), enviado: fmtB(h.bytesOut), recibido: fmtB(h.bytesIn), paquetes_enviados: h.pktsOut, paquetes_recibidos: h.pktsIn,
          contactos: [...peers.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 12).map(p => ({...p, nombre: M.ipNames.get(p.ip)})),
          servicios_ofrecidos: top(served, 10).map(([k, v]) => k + ' (' + v + ')'), servicios_usados: top(used, 12).map(([k, v]) => k + ' (' + v + ')'),
          consultas_dns: top(dns, 12).map(([k, v]) => k + ' (' + v + ')'),
          http: M.http.filter(r => r.src === i.ip || r.dst === i.ip).slice(0, 10).map(r => ({t: +(r.t - M.start).toFixed(2), origen: r.src, metodo: r.method, host: r.host, uri: r.uri.slice(0, 150), user_agent: r.ua.slice(0, 100)})),
          tls_sni: [...new Set(M.tls.filter(r => r.src === i.ip).map(r => r.sni))].slice(0, 15),
          hallazgos: M.findings.filter(f => f.ips.includes(i.ip)).map(f => f.sev + ': ' + f.title)};
      }),
    T('consultas_dns', 'Consultas DNS de la captura. Filtra por dominio (contiene) o por IP que consulta. Devuelve conteo por dominio y una muestra de consultas.', {dominio: {type: 'string'}, ip: {type: 'string'}, limite: {type: 'integer'}},
      i => {
        const M = need(); let l = M.dns;
        if (i.dominio) { const d = String(i.dominio).toLowerCase(); l = l.filter(q => q.name.includes(d)); }
        if (i.ip) l = l.filter(q => q.src === i.ip);
        const c = new Map(); l.forEach(q => c.set(q.name, (c.get(q.name) || 0) + 1));
        return {total: l.length, dominios_distintos: c.size, por_dominio: [...c.entries()].sort((a, b) => b[1] - a[1]).slice(0, lim(i.limite, 20, 50)).map(([k, v]) => ({dominio: k.length > 120 ? k.slice(0, 120) + '…' : k, consultas: v})),
          muestra: l.slice(0, 10).map(q => ({t: +(q.t - M.start).toFixed(2), origen: q.src, servidor: q.dst, tipo: q.qt, nombre: q.name.slice(0, 120)})),
          respuestas_nxdomain: [...M.nx.values()].map(n => ({ip: n.ip, veces: n.count}))};
      }),
    T('trafico_web', 'Peticiones HTTP (método, host, URI, User-Agent) y nombres de servidor TLS (SNI). Filtra por host (contiene) o IP.', {host: {type: 'string'}, ip: {type: 'string'}, limite: {type: 'integer'}},
      i => {
        const M = need(), h = i.host ? String(i.host).toLowerCase() : null, L = lim(i.limite, 20, 50);
        const http = M.http.filter(r => (!h || r.host.toLowerCase().includes(h)) && (!i.ip || r.src === i.ip || r.dst === i.ip));
        const tls = M.tls.filter(r => (!h || r.sni.toLowerCase().includes(h)) && (!i.ip || r.src === i.ip || r.dst === i.ip));
        return {peticiones_http: http.length, http: http.slice(0, L).map(r => ({t: +(r.t - M.start).toFixed(2), origen: r.src, destino: r.dst + ':' + r.dport, metodo: r.method, host: r.host, uri: r.uri.slice(0, 200), user_agent: r.ua.slice(0, 120)})),
          saludos_tls: tls.length, tls: tls.slice(0, L).map(r => ({t: +(r.t - M.start).toFixed(2), origen: r.src, destino: r.dst + ':' + r.dport, sni: r.sni})),
          credenciales_en_claro: M.creds.map(c => ({protocolo: c.proto, origen: c.src, destino: c.where, usuario: c.user, contrasena: c.secret}))};
      }),
    T('seguir_flujo_tcp', 'Reconstruye una conversación TCP como "Seguir flujo TCP" de Wireshark: devuelve el diálogo en orden (lo que envía el cliente y lo que responde el servidor), bytes perdidos, retransmisiones y archivos extraídos. Identifícala con el id de la herramienta conversaciones o de archivos_transferidos, o con IP y puerto. Los datos binarios se resumen y las contraseñas se enmascaran.',
      {conversacion: {type: 'integer', description: 'id de la conversación'}, ip: {type: 'string'}, puerto: {type: 'integer'}, conexion: {type: 'integer', description: 'Si la misma pareja IP:puerto se reutilizó, número de conexión empezando en 1'}, max_caracteres: {type: 'integer', description: 'Texto máximo del diálogo. Por defecto 6000, máximo 20000'}},
      i => {
        const M = need();
        const f = i.conversacion ? M.flowById.get(+i.conversacion) : (i.ip || i.puerto) ? M.flows.find(x => x.proto === 'TCP' && (!i.ip || x.a === i.ip || x.b === i.ip) && (!i.puerto || x.ap === +i.puerto || x.bp === +i.puerto)) : null;
        if (!f) return {error: 'No encontré esa conversación TCP. Usa la herramienta conversaciones para ver los id.'};
        const r = Engine.followTcp(M, f.id, (+i.conexion || 1) - 1);
        if (!r) return {error: 'La conversación ' + f.id + ' no es TCP.'};
        if (!r.conns) return {error: 'Los paquetes de esa conversación quedan fuera de los primeros ' + Engine.MAX_PKTS + ' de la captura.'};
        const max = lim(i.max_caracteres, 6000, 20000), dialogo = []; let used = 0, omitidos = 0;
        for (const tu of r.turns) {
          if (used >= max) { omitidos++; continue; }
          const de = tu.dir ? 'servidor' : 'cliente', t = +(tu.t - M.start).toFixed(3);
          if (tu.gap) { dialogo.push({de, t, bytes_no_capturados: tu.len}); continue; }
          const b = r.dirs[tu.dir].bytes.subarray(tu.off, tu.off + Math.min(tu.len, max - used)), bin = isBinary(b.subarray(0, 512));
          const full = bin ? '[binario] ' + Array.from(b.subarray(0, 24), x => x.toString(16).padStart(2, '0')).join(' ') : maskSecrets(Engine.printable(b));
          const texto = full.slice(0, max - used); used += texto.length;
          dialogo.push({de, paquete: tu.i, t, bytes: tu.len, texto, recortado: !bin && (b.length < tu.len || texto.length < full.length) || undefined});
        }
        const [dc, ds] = r.dirs;
        return {conversacion: f.id, conexion: r.k + 1, conexiones_en_esta_pareja: r.conns, cliente: endp(r.client), servidor: endp(r.server), paquetes: r.pkts, inicio_t: +(r.first - M.start).toFixed(3), duracion_s: +(r.last - r.first).toFixed(3),
          bytes_cliente: dc.bytes.length, bytes_servidor: ds.bytes.length, bytes_no_capturados: dc.missing + ds.missing, retransmisiones: dc.retrans + ds.retrans, apertura_con_syn: dc.syn, cierre: dc.rst || ds.rst ? 'RST' : dc.fin || ds.fin ? 'FIN' : 'abierta',
          turnos: r.turns.length, turnos_omitidos: omitidos || undefined, dialogo, archivos: r.files.map(fileRow)};
      }),
    T('archivos_transferidos', 'Archivos reconstruidos de transferencias HTTP, FTP y SMB2 en claro: nombre, ruta o URL, tipo real según su contenido (detecta ejecutables y extensiones engañosas), tamaño, SHA-256, origen y destino, si están completos y de qué conversación salen.',
      {protocolo: {type: 'string', enum: ['HTTP', 'FTP', 'SMB']}, ip: {type: 'string'}, texto: {type: 'string', description: 'Busca en nombre, ruta, hash o tipo'}, solo_ejecutables: {type: 'boolean'}, limite: {type: 'integer'}},
      i => {
        const M = need(), q = i.texto ? String(i.texto).toLowerCase() : null;
        const l = M.files.filter(f => (!i.protocolo || f.proto === String(i.protocolo).toUpperCase()) && (!i.ip || f.src === i.ip || f.dst === i.ip) && (!i.solo_ejecutables || f.kind === 'exe') && (!q || [f.name, f.path, f.sha256, f.type].join(' ').toLowerCase().includes(q)));
        return {total: l.length, archivos: l.slice(0, lim(i.limite, 20, 60)).map(fileRow), avisos: M.fileNotes.length ? M.fileNotes.slice(0, 15) : undefined};
      }),
    T('linea_de_tiempo_incidente', 'Línea de tiempo del incidente por fases (reconocimiento, acceso, comando y control, exfiltración, impacto): hallazgos de cada fase en orden con inicio y fin, técnicas MITRE ATT&CK, equipos que aparecen en varias fases y si el orden de las fases es el habitual de un ataque.', {},
      () => {
        const M = need(), I = Engine.incident(M), rel = t => t === null ? null : +(t - M.start).toFixed(2);
        return {fases: I.phases.map(p => ({fase: p.label, hallazgos: p.findings.length, desde_t: rel(p.start), hasta_t: rel(p.end), tecnicas: p.techniques.map(m => m.id + ' ' + m.name),
            eventos: p.findings.map(f => ({id: f.id, t: rel(f.t), fin_t: rel(f.tEnd), severidad: f.sev, titulo: f.title, mitre: f.mitre.map(m => m.id), ips: [...new Set(f.ips)].slice(0, 6)}))})),
          orden_observado: I.order.map(phaseLabel), sigue_orden_habitual: I.inOrder, equipos_en_varias_fases: I.links.map(l => ({ip: l.ip, interno: l.internal, fases: l.phases.map(phaseLabel)}))};
      }),
    T('listar_hallazgos', 'Hallazgos de la detección automática con severidad, fase del incidente, técnicas MITRE ATT&CK, descripción, evidencia y reglas Snort sugeridas.', {severidad: {type: 'string', enum: ['alta', 'media', 'baja']}},
      i => need().findings.filter(f => !i.severidad || f.sev === i.severidad).map(f => ({id: f.id, severidad: f.sev, categoria: f.cat, titulo: f.title, inicio_t: +(f.t - S.M.start).toFixed(2), fase: phaseLabel(f.phase), mitre: f.mitre.map(m => m.id + ' ' + m.name + ' (' + m.tactic + ')'), fin_t: +(f.tEnd - S.M.start).toFixed(2), tramas_de_referencia: f.frames, indicadores: f.ioc.slice(0, 10).map(i => i.type + ' ' + i.value), descripcion: f.desc, evidencia: f.evidence, reglas_sugeridas: f.rules, regla_ya_añadida: f.rules.some(ruleAdded)}))),
    T('listar_reglas', 'Reglas Snort que el usuario tiene en su lista, con validez y alertas generadas en la captura, más el siguiente sid libre.', {},
      () => ({siguiente_sid: nextSid(), reglas: S.rules.map(r => ({sid: r.test && r.test.sid, regla: r.text, origen: r.source, valida: !(r.test && r.test.errors && r.test.errors.length), alertas_en_captura: r.test ? r.test.hits : null}))})),
    T('probar_regla_snort', 'Valida la sintaxis de una regla Snort y la ejecuta contra los paquetes de la captura sin guardarla. Devuelve errores, avisos, opciones no evaluadas, número de alertas y paquetes de ejemplo.', {regla: {type: 'string'}},
      i => { const t = Engine.testRule(String(i.regla || ''), S.M); return {valida: !t.errors.length, errores: t.errors, avisos: t.warnings, opciones_no_evaluadas: t.ignored, alertas: t.hits, ejemplos: S.M && t.sample ? t.sample.slice(0, 6).map(n => pktRow(S.M.pkts[n - 1])) : []}; }),
    T('crear_regla_snort', 'Guarda una regla Snort en la lista del usuario (solo cuando el usuario pida crear o añadir reglas). La valida y prueba contra la captura. Devuelve el resultado o los errores para corregirla.', {regla: {type: 'string'}, nota: {type: 'string', description: 'Qué detecta, en pocas palabras'}},
      i => {
        const res = addRule(String(i.regla || ''), 'agente', i.nota ? String(i.nota) : '');
        if (S.M) renderFindings();
        if (!res.rule) return {guardada: false, motivo: res.error, siguiente_sid: nextSid()};
        return {guardada: true, sid: res.rule.test.sid, alertas_en_captura: res.rule.test.hits, avisos: res.rule.test.warnings, opciones_no_evaluadas: res.rule.test.ignored};
      })
  ];

  // ---------- Chat ----------
  const msgs = $('#msgs'), input = $('#chatInput');
  function scrollMsgs() { msgs.scrollTop = msgs.scrollHeight; }
  function instructions() {
    let ctx;
    if (S.M) { const s = Engine.summary(S.M, S.file); ctx = 'Hay una captura cargada. Resumen inicial (consulta las herramientas para más detalle):\n' + JSON.stringify(s) + '\nSiguiente sid libre para reglas: ' + nextSid() + '.'; }
    else ctx = 'No hay ninguna captura cargada todavía. Puedes explicar conceptos (pcap, protocolos, Snort, análisis de tráfico) y sugerir abrir un archivo o usar la captura de ejemplo. Las herramientas de captura fallarán hasta entonces.';
    return 'Eres "Sonda", un agente analista de seguridad de redes (nivel SOC 2) integrado en una aplicación que analiza capturas pcap en el navegador del usuario. Tienes herramientas para consultar la captura y gestionar reglas Snort.\n\n' +
      'Cómo trabajar:\n- Responde siempre en español, claro y directo, en Markdown (párrafos cortos, listas, `código`). Las reglas Snort van en bloques ```snort, una por línea.\n' +
      '- Antes de afirmar cualquier dato concreto (IPs, conteos, dominios, tiempos) consúltalo con las herramientas. No inventes datos; si algo no está en la captura, dilo.\n' +
      '- Explica para alguien que está aprendiendo: qué ocurrió, por qué importa y qué hacer. Distingue hechos de hipótesis e indica tu nivel de confianza.\n' +
      '- Reglas Snort: compatibles con Snort 2.9 y 3; sid desde el siguiente libre; rev:1; msg sin tildes que empiece por "SONDA "; classtype adecuado; detection_filter para umbrales. Pruébalas con probar_regla_snort. Guárdalas con crear_regla_snort solo si el usuario pidió crear o añadir reglas, y di cuántas alertas generan en la captura.\n' +
      '- Para leer lo que se dijeron dos equipos usa seguir_flujo_tcp. Para archivos transferidos usa archivos_transferidos y cita el SHA-256 completo, el tipo real y si la extensión engaña; recomienda verificar el hash en un servicio de reputación sin afirmar que es malware si no hay pruebas.\n' +
      '- Cada hallazgo tiene una fase y técnicas MITRE ATT&CK. Para contar la historia del incidente usa linea_de_tiempo_incidente y cita los id de técnica (p. ej. T1046, T1071.004). El mapeo es heurístico: dilo si una técnica es dudosa.\n' +
      '- Los tiempos t son segundos desde el primer paquete. Las contraseñas aparecen enmascaradas: no intentes reconstruirlas.\n' +
      '- Sé conciso: normalmente menos de 250 palabras, salvo que pidan un informe.\n\nContexto actual:\n' + ctx;
  }
  function renderChatIntro() {
    if (S.chat.length) return;
    const f = S.M && S.M.findings[0];
    const sug = S.M ? ['¿Qué está pasando en esta captura?', f ? '¿Qué tan grave es "' + f.title + '" y qué hago?' : '¿Hay algo sospechoso en el tráfico?', '¿Qué hizo el host ' + ((S.M.findings.flatMap(x => x.ips).find(ip => !Engine.isInternal(ip))) || S.M.hostList[0].ip) + '?', ...(S.M.files.length ? ['¿Qué archivos se transfirieron y alguno es peligroso?'] : []), 'Crea reglas Snort para los ataques que encontraste']
      : ['¿Qué es un archivo pcap y cómo capturo uno?', '¿Cómo se estructura una regla de Snort?', '¿Qué diferencias hay entre Snort 2 y Snort 3?'];
    msgs.innerHTML = '<div class="chat-intro"><p>' + (S.M ? 'Puedo consultar la captura por ti, explicar lo que ves y escribir reglas Snort.' : 'Abre una captura para que pueda analizarla. Mientras tanto, pregúntame lo que quieras sobre análisis de tráfico o Snort.') + '</p><div class="chips">' + sug.map(s => '<button type="button">' + esc(s) + '</button>').join('') + '</div></div>';
    msgs.querySelectorAll('.chips button').forEach(b => b.addEventListener('click', () => send(b.textContent)));
  }
  function addUserMsg(text) { const intro = msgs.querySelector('.chat-intro'); if (intro) intro.remove(); const d = document.createElement('div'); d.className = 'msg user'; d.textContent = text; msgs.append(d); scrollMsgs(); }
  function addBotMsg() {
    const d = document.createElement('div'); d.className = 'msg bot';
    const tools = document.createElement('div'); tools.className = 'tools';
    const body = document.createElement('div'); body.className = 'md'; body.innerHTML = '<p class="thinking">Pensando…</p>';
    d.append(tools, body); msgs.append(d); scrollMsgs(); return {el: d, tools, body};
  }
  function setBusy(b) { S.busy = b; const btn = $('#btnSend'); btn.textContent = b ? 'Detener' : 'Enviar'; btn.classList.toggle('primary', !b); }
  function askAgent(text) { if (window.matchMedia('(max-width: 1099px)').matches) setTab('chat'); send(text); }
  async function send(text) {
    text = String(text || '').trim(); if (!text || S.busy) return;
    addUserMsg(text); input.value = ''; autosize();
    const bot = addBotMsg();
    if (!S.sample) { bot.body.innerHTML = '<p class="msg err">' + esc(aiUnavailableText()) + '</p>'; return; }
    S.chat.push({role: 'user', content: text});
    S.curBot = bot; setBusy(true); S.abort = new AbortController();
    const history = S.chat.slice(-18);
    const turns = [{role: 'user', content: instructions()}, ...history];
    const onText = ({text}) => { bot.body.innerHTML = md(text); scrollMsgs(); };
    let answer = null;
    try {
      try { answer = await S.sample(turns, {cache: false, signal: S.abort.signal, tools: TOOLS, onText}); }
      catch (e) {
        if (e && e.code === 'tools_unavailable') {
          const extra = S.M ? '\n\nHallazgos: ' + JSON.stringify(S.M.findings.map(f => ({sev: f.sev, titulo: f.title, desc: f.desc, evidencia: f.evidence, reglas: f.rules}))) : '';
          answer = await S.sample([{role: 'user', content: instructions() + extra + '\n(Las herramientas no están disponibles en este momento: responde con estos datos.)'}, ...history], {cache: false, signal: S.abort.signal, onText});
        } else throw e;
      }
      S.chat.push({role: 'assistant', content: answer.text});
      bot.body.innerHTML = md(answer.text); enhanceCode(bot.body);
      if (answer.truncated) bot.body.insertAdjacentHTML('beforeend', '<p class="muted">La respuesta se cortó por longitud. Pide que continúe.</p>');
    } catch (e) {
      if (e && e.text) { bot.body.innerHTML = md(e.text); enhanceCode(bot.body); S.chat.push({role: 'assistant', content: e.text}); }
      else if (e && e.code === 'cancelled') bot.body.innerHTML = '<p class="muted">Detenido.</p>';
      else bot.body.innerHTML = '';
      if (!e || e.code !== 'cancelled') bot.body.insertAdjacentHTML('beforeend', '<p class="msg err">' + esc(aiErrorText(e)) + '</p>');
    } finally {
      if (!bot.tools.children.length) bot.tools.remove();
      S.curBot = null; setBusy(false); scrollMsgs();
    }
  }
  $('#chatForm').addEventListener('submit', e => { e.preventDefault(); if (S.busy) { if (S.abort) S.abort.abort(); return; } send(input.value); });
  input.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); $('#chatForm').requestSubmit(); } });
  function autosize() { input.style.height = 'auto'; input.style.height = Math.min(160, input.scrollHeight) + 'px'; }
  input.addEventListener('input', autosize);
  $('#btnClear').addEventListener('click', () => { if (S.busy && S.abort) S.abort.abort(); S.chat = []; msgs.innerHTML = ''; renderChatIntro(); });

  $('#p-reglas').addEventListener('click', ruleListClick);
  renderRules(); updateCounts(); showPanels(); renderChatIntro();
})();
