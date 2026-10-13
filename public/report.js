/*
 * Informes de Sonda: arma los datos del informe (resumen ejecutivo, acciones, línea de
 * tiempo, evidencias, indicadores de compromiso, reglas) y los exporta a PDF, Markdown,
 * CSV y STIX 2.1. Sin DOM ni dependencias: es el global Report en el navegador y un
 * módulo en Node (scripts/analizar.js).
 *
 * El PDF se escribe a mano con las fuentes estándar (Helvetica y Courier) y la codificación
 * WinAnsi, que cubre el español (tildes, ñ, ¿, ¡). Los caracteres fuera de ella se sustituyen.
 */
const Report = (() => {
  'use strict';
  const E = typeof Engine !== 'undefined' ? Engine : require('./engine.js');
  const SEV = {alta: 'Alta', media: 'Media', baja: 'Baja'}, RANK = {alta: 0, media: 1, baja: 2};
  const TLP = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];
  const IOC_TYPES = {ip: 'Dirección IP', dominio: 'Dominio', url: 'URL', sha256: 'Hash SHA-256', 'user-agent': 'User-Agent', mac: 'Dirección MAC', puerto: 'Puerto'};
  const pad2 = n => String(n).padStart(2, '0');
  const utc = t => new Date(t * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  const uniq = a => [...new Set(a)];
  const listEs = a => a.length <= 1 ? a.join('') : a.slice(0, -1).join(', ') + ' y ' + a[a.length - 1];
  const phaseLabel = id => (E.PHASES.find(p => p.id === id) || {label: id}).label;
  function relT(M, t) { const r = Math.max(0, t - M.start), h = Math.floor(r / 3600), m = Math.floor(r % 3600 / 60), s = Math.floor(r % 60); return (h ? h + ':' + pad2(m) : m) + ':' + pad2(s); }
  function dur(s) { if (s < 1) return Math.round(s * 1000) + ' ms'; if (s < 60) return s.toFixed(1).replace('.', ',') + ' s'; const m = Math.floor(s / 60); return m < 60 ? m + ' min ' + Math.round(s % 60) + ' s' : Math.floor(m / 60) + ' h ' + (m % 60) + ' min'; }

  // ---------- Report data ----------
  // Fallback for models parsed without Engine.attachEvidence (normally the engine already did this in the worker).
  function evidence(M, f) {
    const frames = new Set(), rules = [];
    for (const r of f.rules) {
      if (r.startsWith('#')) continue;
      const t = E.testRule(r, M); rules.push({text: r, hits: t.hits, sid: t.sid});
      for (const n of t.sample || []) if (frames.size < 12) frames.add(n);
    }
    if (!frames.size) {
      const ips = new Set(f.ips);
      for (const p of M.pkts) { if (p.t > f.tEnd + 0.001) break; if (p.t >= f.t - 0.001 && (ips.has(p.src) || ips.has(p.dst))) { frames.add(p.i); if (frames.size >= 12) break; } }
    }
    return {frames: [...frames].sort((a, b) => a - b), rules};
  }
  function collectIocs(M) {
    const map = new Map();
    const add = (type, value, role, from) => {
      if (!value) return null;
      const k = type + '|' + String(value).toLowerCase(); let e = map.get(k);
      if (!e) { e = {type, value: String(value), roles: new Set(), findings: new Set(), mitre: new Set(), first: null}; map.set(k, e); }
      if (role) e.roles.add(role);
      if (from) { for (const id of from.findings) e.findings.add(id); for (const m of from.mitre) e.mitre.add(m); if (from.first !== null && (e.first === null || from.first < e.first)) e.first = from.first; }
      return e;
    };
    for (const f of M.findings) for (const i of f.ioc) add(i.type, i.value, i.role, {findings: [f.id], mitre: f.mitre.map(m => m.id), first: f.t});
    // Names seen for the IoC addresses: DNS answers, TLS SNI and HTTP Host.
    for (const e of [...map.values()].filter(x => x.type === 'ip')) {
      const names = new Set(), n = M.ipNames.get(e.value); if (n) names.add(n);
      for (const r of M.tls) if (r.dst === e.value) names.add(r.sni);
      for (const r of M.http) if (r.dst === e.value && r.host && !/^[\d.:[\]]+$/.test(r.host)) names.add(r.host.replace(/:\d+$/, ''));
      for (const d of names) add('dominio', d.toLowerCase(), 'Apunta a ' + e.value + ' (visto en DNS, TLS o HTTP)', e);
    }
    const order = Object.keys(IOC_TYPES);
    return [...map.values()].map(e => ({type: e.type, value: e.value, role: [...e.roles].join('; '), findings: [...e.findings], mitre: [...e.mitre], first: e.first}))
      .sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type) || (a.first || 0) - (b.first || 0));
  }
  function build(M, opts = {}) {
    const I = E.incident(M), F = M.findings.slice().sort((a, b) => RANK[a.sev] - RANK[b.sev] || a.t - b.t);
    const meta = Object.assign({title: '', caseId: '', org: '', analyst: '', tlp: 'TLP:AMBER'}, opts.meta || {});
    if (!TLP.includes(meta.tlp)) meta.tlp = 'TLP:AMBER';
    const sev = {alta: 0, media: 0, baja: 0}; F.forEach(f => sev[f.sev]++);
    const isInt = E.isInternal, intIps = list => uniq(list.flatMap(f => f.ips).filter(isInt)), extIps = list => uniq(list.flatMap(f => f.ips).filter(ip => !isInt(ip)));
    const byPhase = id => F.filter(f => f.phase === id).sort((a, b) => a.t - b.t);
    const c2 = byPhase('c2'), exf = byPhase('exfiltracion'), recon = byPhase('reconocimiento'), acc = byPhase('acceso');
    const compromised = c2.concat(exf).some(f => f.sev === 'alta');
    const iocs = collectIocs(M);
    const risk = !F.length ? {level: 'Sin hallazgos', color: 'baja', reason: 'Las detecciones automáticas no encontraron patrones de ataque en la captura.'}
      : compromised ? {level: 'Crítico', color: 'alta', reason: 'Hay indicios de al menos un equipo comprometido (comando y control o exfiltración de severidad alta).'}
      : sev.alta ? {level: 'Alto', color: 'alta', reason: 'Hay ataques o exposiciones de severidad alta, sin indicios claros de compromiso.'}
      : sev.media ? {level: 'Medio', color: 'media', reason: 'Hay actividad sospechosa de severidad media que conviene revisar.'}
      : {level: 'Bajo', color: 'baja', reason: 'Solo hay hallazgos de severidad baja.'};

    // Executive summary, in plain language.
    const summary = ['Se analizó la captura «' + (opts.file || 'captura') + '» (' + M.count.toLocaleString('es-ES') + ' paquetes, ' + E.fmtBytes(M.bytes) + '), tomada entre el ' + utc(M.start) + ' y el ' + utc(M.end) + ' (' + dur(M.duration) + ').'];
    if (F.length) summary.push('El análisis identificó ' + F.length + ' hallazgos (' + sev.alta + ' de severidad alta, ' + sev.media + ' media y ' + sev.baja + ' baja) en ' + I.active.length + ' fases del incidente: ' + listEs(I.active.map(phaseLabel).map(s => s.toLowerCase())) + '.');
    else summary.push('No se identificaron patrones de ataque con las detecciones automáticas.');
    if (c2.length || exf.length) {
      const hosts = intIps(c2.concat(exf)), ext = extIps(c2.concat(exf));
      summary.push((compromised ? 'Hay indicios de compromiso: ' : 'Hay actividad compatible con un compromiso: ') + (hosts.length ? listEs(hosts) : 'equipos de la red') + (hosts.length > 1 ? ' se comunican' : ' se comunica') + (ext.length ? ' con ' + listEs(ext) : ' con destinos externos') +
        ' de forma propia de un canal de comando y control' + (exf.length ? ', y hay salida de datos de la red (' + listEs(exf.map(f => f.title.charAt(0).toLowerCase() + f.title.slice(1))) + ')' : '') + '.');
    }
    if (recon.length || acc.length) {
      const atk = extIps(recon.concat(acc)), tgt = intIps(recon.concat(acc).filter(f => f.cat !== 'Credenciales expuestas'));
      if (atk.length) summary.push('Desde ' + listEs(atk) + ' se ' + (recon.length ? 'exploró la red' : '') + (recon.length && acc.length ? ' y se ' : '') + (acc.length ? 'intentó el acceso' : '') + (tgt.length ? ' contra ' + listEs(tgt.slice(0, 6)) : '') + '.');
    }
    if (M.creds.length) summary.push('Se transmitieron ' + M.creds.length + ' credencial(es) sin cifrar (' + uniq(M.creds.map(c => c.proto)).join(', ') + '); deben considerarse comprometidas.');
    if (M.files.length) { const ex = M.files.filter(f => f.kind === 'exe'), dis = ex.filter(f => f.disguised); summary.push('Se reconstruyeron ' + M.files.length + ' archivo(s) transferidos en claro' + (ex.length ? '; ' + (ex.length === 1 ? '1 es un ejecutable' : ex.length + ' son ejecutables') + (dis.length ? ' (' + dis.length + ' con extensión engañosa)' : '') : '') + '.'); }
    if (F.length && !I.inOrder) summary.push('Las fases no aparecen en el orden habitual de un ataque (' + I.order.map(phaseLabel).join(' -> ') + '): puede tratarse de actividades independientes o de un compromiso anterior al inicio de la captura.');

    // Recommended actions, most urgent first.
    const recs = [], rec = (prio, text, why) => recs.push({prio, text, why});
    const titles = list => listEs(uniq(list.map(f => f.title)).slice(0, 3));
    if (c2.length || exf.length) { const h = intIps(c2.concat(exf)); if (h.length) rec('Inmediata', 'Aislar de la red ' + listEs(h) + ' y preservar su disco y su memoria para el análisis forense antes de limpiarlos.', titles(c2.concat(exf))); }
    if (iocs.length) { const n = t => iocs.filter(i => i.type === t).length; rec('Inmediata', 'Bloquear en cortafuegos, proxy y DNS los indicadores de compromiso de la sección 4 (' + [n('ip') && n('ip') + ' IP', n('dominio') && n('dominio') + (n('dominio') === 1 ? ' dominio' : ' dominios'), n('url') && n('url') + ' URL', n('sha256') && n('sha256') + (n('sha256') === 1 ? ' hash' : ' hashes')].filter(Boolean).join(', ') + ').', 'Cortan el contacto con los orígenes del ataque y con la infraestructura de control.'); }
    if (exf.length) rec('Inmediata', 'Determinar qué información salió hacia ' + (listEs(extIps(exf)) || 'el exterior') + ' y valorar las obligaciones de notificación de la brecha.', titles(exf));
    const ex = M.files.filter(f => f.kind === 'exe');
    if (ex.length) rec('Alta', 'Buscar en los equipos los ejecutables descargados por su SHA-256 (sección 4) y analizarlos en un entorno aislado.', listEs(uniq(ex.map(f => f.name)).slice(0, 3)));
    if (M.creds.length) rec('Alta', 'Cambiar las contraseñas expuestas (usuarios: ' + listEs(uniq(M.creds.map(c => c.user)).slice(0, 6)) + ') y sustituir ' + listEs(uniq(M.creds.map(c => c.proto.replace('Formulario ', '')))) + ' por protocolos cifrados (SFTP, HTTPS).', 'Las credenciales viajaron en texto claro.');
    const web = F.filter(f => f.mitre.some(m => m.id === 'T1190'));
    if (web.length) rec('Alta', 'Revisar los registros de ' + (listEs(intIps(web)) || 'los servidores web afectados') + ' para confirmar si las peticiones maliciosas tuvieron éxito, y aplicar parches o un WAF.', titles(web));
    const brute = F.filter(f => f.mitre.some(m => m.id === 'T1110.001'));
    if (brute.length) rec('Alta', 'Limitar los intentos de inicio de sesión y exigir clave pública o MFA en ' + (listEs(intIps(brute)) || 'los servicios atacados') + '.', titles(brute));
    const arp = F.filter(f => f.mitre.some(m => m.id === 'T1557.002'));
    if (arp.length) rec('Alta', 'Localizar en los switches el puerto con la MAC ' + listEs(uniq(arp.flatMap(f => f.ioc.map(i => i.value)))) + ' y activar Dynamic ARP Inspection.', titles(arp));
    const dos = byPhase('impacto');
    if (dos.length) rec('Alta', 'Activar SYN cookies y limitar las conexiones por origen en ' + (listEs(intIps(dos)) || 'los servicios afectados') + '.', titles(dos));
    if (recon.length && extIps(recon).length) rec('Media', 'Bloquear en el perímetro ' + listEs(extIps(recon)) + ' y revisar qué servicios quedan expuestos a Internet.', titles(recon));
    if (F.some(f => f.cat === 'Protocolo inseguro')) rec('Media', 'Sustituir Telnet por SSH.', 'Telnet transmite usuario, contraseña y comandos sin cifrar.');
    if (F.length) rec('Media', 'Desplegar las reglas Snort de la sección 5 en modo alerta, validarlas con tráfico real y después decidir si bloquean.', 'Detectan la repetición de estos patrones.');

    const ev = new Map(F.map(f => [f.id, f.ruleTests ? {frames: f.frames, rules: f.ruleTests} : evidence(M, f)]));
    const suggested = [], seenRule = new Set();
    for (const f of F) for (const r of ev.get(f.id).rules) if (!seenRule.has(r.text)) { seenRule.add(r.text); suggested.push({...r, note: f.title}); }
    const assets = new Map();
    for (const f of F) for (const ip of uniq(f.ips)) if (isInt(ip)) { const a = assets.get(ip) || {ip, name: M.ipNames.get(ip) || '', phases: new Set(), findings: 0, worst: 'baja'}; a.phases.add(f.phase); a.findings++; if (RANK[f.sev] < RANK[a.worst]) a.worst = f.sev; assets.set(ip, a); }

    return {meta, file: opts.file || 'captura', generated: new Date(), risk, summary, recs,
      capture: {format: M.format, size: M.fileSize, sha256: M.fileSha256, packets: M.count, bytes: M.bytes, start: M.start, end: M.end, duration: M.duration, hosts: M.hosts.size, flows: M.flows.length, truncated: M.truncated, pktsTruncated: M.pktsTruncated},
      incident: I, findings: F.map(f => ({...f, frames: ev.get(f.id).frames, ruleTests: ev.get(f.id).rules})), iocs,
      assets: [...assets.values()].sort((a, b) => RANK[a.worst] - RANK[b.worst] || b.findings - a.findings).map(a => ({...a, phases: [...a.phases].map(phaseLabel)})),
      files: M.files.slice().sort((a, b) => (b.kind === 'exe') - (a.kind === 'exe') || a.n - b.n).map(f => ({n: f.n, name: f.name, path: f.path, proto: f.proto, type: f.type, size: f.size, sha256: f.sha256, src: f.src, dst: f.dst, t: f.t, complete: f.complete, exe: f.kind === 'exe', disguised: f.disguised})),
      rules: {user: (opts.rules || []).filter(r => r.text && !r.comment), suggested},
      profile: {protocols: Object.entries(M.proto).sort((a, b) => b[1].pkts - a[1].pkts).slice(0, 10).map(([k, v]) => ({name: k, pkts: v.pkts, bytes: v.bytes})),
        hosts: M.hostList.slice(0, 10).map(h => ({ip: h.ip, internal: isInt(h.ip), name: M.ipNames.get(h.ip) || '', out: h.bytesOut, in: h.bytesIn, peers: h.peers.size}))}, interp: opts.interp || '', start: M.start,
      rel: t => relT(M, t)};
  }

  // ---------- PDF writer ----------
  const HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015,
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333,
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
  const HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975,
    722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333,
    556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584];
  const EXTRA = {'¿': [611, 611], '¡': [333, 333], '«': [556, 556], '»': [556, 556], 'º': [365, 365], 'ª': [370, 370], '°': [400, 400], '·': [278, 278], '–': [556, 556], '—': [1000, 1000], '…': [1000, 1000],
    '‘': [222, 278], '’': [222, 278], '“': [333, 500], '”': [333, 500], '•': [350, 350], '€': [556, 556], '×': [584, 584], '©': [737, 737], '®': [737, 737], '±': [584, 584], 'ß': [611, 611], ' ': [278, 278]};
  const WIN = {'€': 128, '‚': 130, 'ƒ': 131, '„': 132, '…': 133, '†': 134, '‡': 135, 'ˆ': 136, '‰': 137, 'Š': 138, '‹': 139, 'Œ': 140, 'Ž': 142, '‘': 145, '’': 146, '“': 147, '”': 148, '•': 149, '–': 150, '—': 151, '˜': 152, '™': 153, 'š': 154, '›': 155, 'œ': 156, 'ž': 158, 'Ÿ': 159};
  const SUBST = {'→': '->', '←': '<-', '↔': '<->', '≥': '>=', '≤': '<=', '≠': '!=', '✓': 'v', '\t': '    '};
  // Keeps only what WinAnsi can show; the rest loses its accent or becomes "?".
  function clean(s) {
    let out = '';
    for (const ch of String(s ?? '')) {
      const c = ch.codePointAt(0);
      if ((c >= 32 && c <= 126) || (c >= 160 && c <= 255) || WIN[ch]) out += ch;
      else if (SUBST[ch] !== undefined) out += SUBST[ch];
      else if (c === 10) out += '\n';
      else if (c < 32 || (c >= 127 && c < 160) || (c >= 0x200b && c <= 0x200f)) continue;
      else { const b = ch.normalize('NFD').replace(/[̀-ͯ]/g, ''); out += b.length === 1 && b.charCodeAt(0) < 256 ? b : '?'; }
    }
    return out;
  }
  function charW(ch, font) {
    if (font === 'F3') return 600;
    const c = ch.charCodeAt(0), b = font === 'F2' ? 1 : 0;
    if (c >= 32 && c <= 126) return (b ? HELVB : HELV)[c - 32];
    if (EXTRA[ch]) return EXTRA[ch][b];
    const base = ch.normalize('NFD').charAt(0), bc = base.charCodeAt(0);
    return bc >= 32 && bc <= 126 ? (b ? HELVB : HELV)[bc - 32] : 556;
  }
  const textW = (s, font, size) => { let w = 0; for (const ch of s) w += charW(ch, font); return w * size / 1000; };
  function pdfStr(s) {
    let out = '(';
    for (const ch of s) {
      const c = WIN[ch] || ch.charCodeAt(0);
      if (c === 40 || c === 41 || c === 92) out += '\\' + ch;
      else if (c < 32 || c > 126) out += '\\' + c.toString(8).padStart(3, '0');
      else out += ch;
    }
    return out + ')';
  }
  const utf16 = s => '<FEFF' + Array.from(String(s), ch => { const c = ch.codePointAt(0); if (c > 0xffff) { const v = c - 0x10000; return ((0xd800 + (v >> 10)).toString(16) + (0xdc00 + (v & 0x3ff)).toString(16)).toUpperCase(); } return c.toString(16).padStart(4, '0').toUpperCase(); }).join('') + '>';
  const num = n => (Math.round(n * 100) / 100).toString();
  const rgb = hex => { const v = parseInt(hex.slice(1), 16); return num((v >> 16) / 255) + ' ' + num(((v >> 8) & 255) / 255) + ' ' + num((v & 255) / 255); };
  const C = {ink: '#17212C', muted: '#566472', accent: '#1D5C8A', line: '#C7D0D8', soft: '#EEF2F5', head: '#E2E9EF', white: '#FFFFFF', alta: '#B0303F', media: '#A86A12', baja: '#4C7757'};

  function writer() {
    const PW = 595.28, PH = 841.89, ML = 50, MR = 50, MT = 64, MB = 58, CW = PW - ML - MR;
    const pages = [], outline = [];
    let pg = null, y = 0;
    const w = {CW, ML, PW, PH, pages, get y() { return y; }, set y(v) { y = v; }};
    const op = s => pg.ops.push(s);
    w.newPage = () => { pg = {ops: [], links: []}; pages.push(pg); y = MT; };
    w.room = () => PH - MB - y;
    w.ensure = h => { if (!pg || h > w.room()) w.newPage(); };
    w.text = (x, top, s, font = 'F1', size = 10, color = C.ink) => { op('BT /' + font + ' ' + num(size) + ' Tf ' + rgb(color) + ' rg ' + num(x) + ' ' + num(PH - top - size * 0.86) + ' Td ' + pdfStr(clean(s)) + ' Tj ET'); };
    w.rect = (x, top, wd, h, fill, stroke, lw = 0.75) => { op('q ' + (fill ? rgb(fill) + ' rg ' : '') + (stroke ? rgb(stroke) + ' RG ' + num(lw) + ' w ' : '') + num(x) + ' ' + num(PH - top - h) + ' ' + num(wd) + ' ' + num(h) + ' re ' + (fill && stroke ? 'B' : fill ? 'f' : 'S') + ' Q'); };
    w.line = (x1, y1, x2, y2, color = C.line, lw = 0.75) => { op('q ' + rgb(color) + ' RG ' + num(lw) + ' w ' + num(x1) + ' ' + num(PH - y1) + ' m ' + num(x2) + ' ' + num(PH - y2) + ' l S Q'); };
    w.link = (x, top, wd, h, uri) => { pg.links.push([num(x), num(PH - top - h), num(x + wd), num(PH - top), uri]); };
    w.wrap = (s, font, size, width) => {
      const out = [];
      for (const para of clean(s).split('\n')) {
        let line = '';
        for (const word of para.match(/\S+\s*|\s+/g) || ['']) {
          if (textW(line + word, font, size) <= width) { line += word; continue; }
          if (line.trim()) out.push(line.trimEnd());
          line = '';
          let rest = word;
          while (textW(rest.trimEnd(), font, size) > width) { // hashes, URLs: cut by characters
            let k = 1; while (k < rest.length && textW(rest.slice(0, k + 1), font, size) <= width) k++;
            out.push(rest.slice(0, k)); rest = rest.slice(k);
          }
          line = rest;
        }
        out.push(line.trimEnd());
      }
      return out;
    };
    w.mark = (title, level) => outline.push({title, level, page: pages.length - 1, y});
    w.space = h => { y += h; };
    w.h1 = (s, mark = true) => {
      w.ensure(90); if (y > MT) y += 8;
      if (mark) w.mark(s, 1);
      w.text(ML, y, s, 'F2', 16, C.accent); y += 23;
      w.line(ML, y, ML + CW, y, C.accent, 1); y += 10;
    };
    w.h2 = (s, sevKey) => {
      w.ensure(70); y += 6;
      w.mark(s, 2);
      let x = ML;
      if (sevKey) { const lbl = SEV[sevKey].toUpperCase(), bw = textW(lbl, 'F2', 8) + 10; w.rect(x, y + 1, bw, 13, C[sevKey]); w.text(x + 5, y + 3.6, lbl, 'F2', 8, C.white); x += bw + 7; }
      for (const ln of w.wrap(s, 'F2', 12, ML + CW - x)) { w.text(x, y, ln, 'F2', 12, C.ink); y += 16; }
      y += 3;
    };
    w.p = (s, o = {}) => {
      const font = o.font || 'F1', size = o.size || 10, lh = size * 1.42, x = ML + (o.indent || 0);
      for (const ln of w.wrap(s, font, size, CW - (o.indent || 0))) { w.ensure(lh); w.text(x, y, ln, font, size, o.color || C.ink); y += lh; }
      y += o.after ?? 6;
    };
    w.bullets = (items, o = {}) => {
      const size = o.size || 10, lh = size * 1.42, ind = 13;
      for (const it of items) {
        const lines = w.wrap(it, o.font || 'F1', size, CW - ind);
        lines.forEach((ln, k) => { w.ensure(lh); if (!k) w.text(ML + 2, y, '•', 'F1', size, C.muted); w.text(ML + ind, y, ln, o.font || 'F1', size, C.ink); y += lh; });
        y += 2;
      }
      y += 4;
    };
    // Rows of label + value. A value can be {text, font, link}.
    w.kv = (rows, o = {}) => {
      const size = o.size || 9.5, lh = size * 1.42, lw = o.labelW || 135;
      for (const [label, v] of rows) {
        const val = typeof v === 'object' && v ? v : {text: String(v ?? '')}, font = val.font || 'F1', vs = font === 'F3' ? size - 0.5 : size;
        const lines = w.wrap(val.text, font, vs, CW - lw);
        w.ensure(lh * Math.min(lines.length, 3));
        w.text(ML, y, label, 'F2', size, C.muted);
        lines.forEach(ln => { w.ensure(lh); w.text(ML + lw, y, ln, font, vs, val.link ? C.accent : C.ink); if (val.link) w.link(ML + lw, y, textW(ln, font, vs), lh, val.link); y += lh; });
      }
      y += o.after ?? 6;
    };
    // cols: [{title, w (fraction of the width), font}]; cells: string or {text, font, color, link, fill}
    w.table = (cols, rows, o = {}) => {
      const size = o.size || 8.5, lh = size * 1.32, pad = 4, xs = []; let acc = ML;
      for (const c of cols) { xs.push(acc); acc += c.w * CW; }
      const header = () => {
        const lines = cols.map(c => w.wrap(c.title, 'F2', size, c.w * CW - pad * 2)), h = Math.max(...lines.map(l => l.length)) * lh + pad * 2;
        w.rect(ML, y, CW, h, C.head);
        cols.forEach((c, i) => lines[i].forEach((ln, k) => w.text(xs[i] + pad, y + pad + k * lh, ln, 'F2', size, C.ink)));
        y += h;
      };
      w.ensure(lh * 4 + pad * 4); header();
      rows.forEach((row, ri) => {
        const cells = row.map((v, i) => { const c = typeof v === 'object' && v ? v : {text: String(v ?? '')}, font = c.font || cols[i].font || 'F1', fs = font === 'F3' ? size - 0.5 : size; return {...c, font, fs, lines: w.wrap(c.text, font, fs, cols[i].w * CW - pad * 2)}; });
        let h = Math.max(...cells.map(c => c.lines.length)) * lh + pad * 2;
        const maxH = PH - MB - MT - 40; if (h > maxH) { cells.forEach(c => { c.lines = c.lines.slice(0, Math.floor((maxH - pad * 2) / lh)); }); h = maxH; }
        if (h > w.room()) { w.newPage(); header(); }
        if (ri % 2) w.rect(ML, y, CW, h, C.soft);
        cells.forEach((c, i) => {
          if (c.fill) w.rect(xs[i] + pad - 2, y + pad - 1, textW(c.lines[0] || '', c.font, c.fs) + 4, lh, c.fill);
          c.lines.forEach((ln, k) => { w.text(xs[i] + pad, y + pad + k * lh, ln, c.font, c.fs, c.color || (c.link ? C.accent : C.ink)); if (c.link && !k) w.link(xs[i] + pad, y + pad, textW(ln, c.font, c.fs), lh, c.link); });
        });
        y += h; w.line(ML, y, ML + CW, y, C.line, 0.5);
      });
      y += o.after ?? 10;
    };
    w.code = (s, o = {}) => {
      const size = o.size || 7.6, lh = size * 1.38, max = Math.floor((CW - 16) / (size * 0.6)), lines = [];
      // Break after a space when possible, so a rule copied from the PDF only gains line breaks between options.
      for (let ln of clean(s).split('\n')) {
        if (!ln.length) lines.push('');
        while (ln.length > max) { const cut = ln.lastIndexOf(' ', max); const at = cut > max * 0.5 ? cut + 1 : max; lines.push(ln.slice(0, at)); ln = ln.slice(at); }
        if (ln.length) lines.push(ln);
      }
      w.ensure(lh + 8); w.rect(ML, y, CW, 4, C.soft); y += 4;
      for (const ln of lines) { w.ensure(lh); w.rect(ML, y, CW, lh, C.soft); w.text(ML + 8, y + 1, ln, 'F3', size, C.ink); y += lh; }
      w.rect(ML, y, CW, 4, C.soft); y += 4 + (o.after ?? 8);
    };
    w.finish = (decorate, info) => {
      pages.forEach((p, i) => { pg = p; decorate(w, i, pages.length); });
      return serialize(pages, outline, info, PW, PH);
    };
    return w;
  }
  function serialize(pages, outline, info, PW, PH) {
    const objs = [], alloc = () => objs.push(null), set = (id, s) => { objs[id - 1] = s; };
    const catalog = alloc(), pagesId = alloc(), fonts = {F1: 'Helvetica', F2: 'Helvetica-Bold', F3: 'Courier', F4: 'Helvetica-Oblique'}, fontIds = {};
    for (const [k, name] of Object.entries(fonts)) { fontIds[k] = alloc(); set(fontIds[k], '<< /Type /Font /Subtype /Type1 /BaseFont /' + name + ' /Encoding /WinAnsiEncoding >>'); }
    const fontRes = '<< ' + Object.entries(fontIds).map(([k, id]) => '/' + k + ' ' + id + ' 0 R').join(' ') + ' >>';
    const pageIds = pages.map(() => alloc());
    pages.forEach((p, i) => {
      const content = p.ops.join('\n'), cid = alloc();
      set(cid, '<< /Length ' + content.length + ' >>\nstream\n' + content + '\nendstream');
      const annots = p.links.map(([x1, y1, x2, y2, uri]) => { const id = alloc(); set(id, '<< /Type /Annot /Subtype /Link /Rect [' + [x1, y1, x2, y2].join(' ') + '] /Border [0 0 0] /A << /S /URI /URI ' + pdfStr(clean(uri)) + ' >> >>'); return id + ' 0 R'; });
      set(pageIds[i], '<< /Type /Page /Parent ' + pagesId + ' 0 R /MediaBox [0 0 ' + PW + ' ' + PH + '] /Resources << /Font ' + fontRes + ' >> /Contents ' + cid + ' 0 R' + (annots.length ? ' /Annots [' + annots.join(' ') + ']' : '') + ' >>');
    });
    set(pagesId, '<< /Type /Pages /Kids [' + pageIds.map(id => id + ' 0 R').join(' ') + '] /Count ' + pages.length + ' >>');
    // Bookmarks: level-1 entries with their level-2 children (closed).
    let outlinesId = null;
    if (outline.length) {
      outlinesId = alloc();
      const tops = [];
      for (const o of outline) { if (o.level === 1 || !tops.length) tops.push({...o, kids: []}); else tops[tops.length - 1].kids.push(o); }
      const write = (items, parent) => {
        const ids = items.map(() => alloc());
        items.forEach((it, i) => {
          const kids = it.kids && it.kids.length ? write(it.kids, ids[i]) : null;
          set(ids[i], '<< /Title ' + utf16(it.title) + ' /Parent ' + parent + ' 0 R' + (i ? ' /Prev ' + ids[i - 1] + ' 0 R' : '') + (i < items.length - 1 ? ' /Next ' + ids[i + 1] + ' 0 R' : '') +
            ' /Dest [' + pageIds[it.page] + ' 0 R /XYZ 0 ' + num(PH - it.y + 12) + ' 0]' + (kids ? ' /First ' + kids[0] + ' 0 R /Last ' + kids[kids.length - 1] + ' 0 R /Count -' + kids.length : '') + ' >>');
        });
        return ids;
      };
      const top = write(tops, outlinesId);
      set(outlinesId, '<< /Type /Outlines /First ' + top[0] + ' 0 R /Last ' + top[top.length - 1] + ' 0 R /Count ' + top.length + ' >>');
    }
    set(catalog, '<< /Type /Catalog /Pages ' + pagesId + ' 0 R' + (outlinesId ? ' /Outlines ' + outlinesId + ' 0 R /PageMode /UseOutlines' : '') + ' /Lang (es-ES) >>');
    const infoId = alloc(), d = info.date;
    set(infoId, '<< /Title ' + utf16(info.title) + ' /Subject ' + utf16(info.subject) + (info.author ? ' /Author ' + utf16(info.author) : '') + ' /Creator (Sonda) /Producer (Sonda) /CreationDate (D:' + d.getUTCFullYear() + pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate()) + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + 'Z) >>');
    let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
    const offs = [];
    objs.forEach((s, i) => { offs.push(out.length); out += (i + 1) + ' 0 obj\n' + s + '\nendobj\n'; });
    const xref = out.length, docId = E.sha256(Uint8Array.from(info.title + d.toISOString() + objs.length, c => c.charCodeAt(0) & 255)).slice(0, 32);
    out += 'xref\n0 ' + (objs.length + 1) + '\n0000000000 65535 f \n' + offs.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('');
    out += 'trailer\n<< /Size ' + (objs.length + 1) + ' /Root ' + catalog + ' 0 R /Info ' + infoId + ' 0 R /ID [<' + docId + '> <' + docId + '>] >>\nstartxref\n' + xref + '\n%%EOF\n';
    const bytes = new Uint8Array(out.length);
    for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 255;
    return bytes;
  }

  // ---------- PDF report ----------
  const TLP_COLOR = {'TLP:CLEAR': '#FFFFFF', 'TLP:GREEN': '#33FF00', 'TLP:AMBER': '#FFC000', 'TLP:AMBER+STRICT': '#FFC000', 'TLP:RED': '#FF2B2B'};
  function tlpBadge(w, xRight, top, tlp) {
    const tw = textW(tlp, 'F2', 8), bw = tw + 10;
    w.rect(xRight - bw, top, bw, 13, '#000000'); w.text(xRight - bw + 5, top + 3, tlp, 'F2', 8, TLP_COLOR[tlp] || '#FFFFFF');
  }
  // Phase lanes with one bar per finding, as in the "Incidente" tab. Low severity is an outline so it does not rely on color alone.
  function ganttPdf(w, D) {
    const lanes = D.incident.phases.filter(p => p.findings.length || p.id !== 'impacto');
    const LW = 108, x0 = w.ML + LW, pw = w.CW - LW, span = Math.max(D.capture.duration, 1e-6), X = t => x0 + (t - D.start) / span * pw;
    const ROW = 10, BAR = 6.5, PADV = 5;
    const packed = lanes.map(ln => {
      const rows = [], bars = [];
      for (const f of ln.findings.slice().sort((a, b) => a.t - b.t)) {
        const a = X(f.t), b = Math.max(a + 4, X(f.tEnd)); let r = rows.findIndex(e => e + 2 <= a); if (r < 0) { r = rows.length; rows.push(0); } rows[r] = b; bars.push({f, a, b, r});
      }
      return {ln, bars, h: Math.max(26, Math.max(1, rows.length) * ROW + PADV * 2)};
    });
    const total = packed.reduce((s, l) => s + l.h, 0) + 34;
    w.ensure(total);
    let y = w.y; const top = y;
    for (const {ln, bars, h} of packed) {
      w.text(w.ML, y + PADV, ln.label, 'F2', 8.5, ln.findings.length ? C.ink : C.muted);
      w.text(w.ML, y + PADV + 11, ln.findings.length ? ln.findings.length + ' hallazgo(s)' : 'sin actividad', 'F1', 7, C.muted);
      for (const {f, a, b, r} of bars) {
        const by = y + PADV + r * ROW + (ROW - BAR) / 2;
        if (f.sev === 'baja') w.rect(a + 0.5, by + 0.5, b - a - 1, BAR - 1, C.white, C.baja, 1); else w.rect(a, by, b - a, BAR, C[f.sev]);
      }
      y += h; w.line(w.ML, y, w.ML + w.CW, y, C.line, 0.5);
    }
    for (let k = 0; k <= 6; k++) {
      const x = x0 + pw * k / 6, lbl = D.rel(D.start + span * k / 6);
      w.line(x, top, x, y, '#DDE3E8', 0.4);
      w.text(k === 0 ? x : k === 6 ? x - textW(lbl, 'F1', 7) : x - textW(lbl, 'F1', 7) / 2, y + 3, lbl, 'F1', 7, C.muted);
    }
    y += 14;
    let lx = w.ML;
    for (const [k, lbl] of [['alta', 'Severidad alta'], ['media', 'Severidad media'], ['baja', 'Severidad baja (contorno)']]) {
      if (k === 'baja') w.rect(lx, y + 1.5, 9, 6, C.white, C.baja, 1); else w.rect(lx, y + 1.5, 9, 6, C[k]);
      w.text(lx + 13, y, lbl, 'F1', 7.5, C.muted); lx += 13 + textW(lbl, 'F1', 7.5) + 16;
    }
    w.text(lx, y, 'Tiempo desde el inicio de la captura (' + utc(D.start) + ')', 'F1', 7.5, C.muted);
    w.y = y + 18;
  }
  function pdf(D) {
    const w = writer(), cap = D.capture, m = D.meta, title = m.title || 'Informe de análisis de tráfico de red';
    w.newPage();
    // Cover block
    w.text(w.ML, w.y, 'INFORME DE ANÁLISIS DE TRÁFICO DE RED', 'F2', 9, C.muted); w.y += 16;
    for (const ln of w.wrap(title, 'F2', 22, w.CW)) { w.text(w.ML, w.y, ln, 'F2', 22, C.ink); w.y += 28; }
    w.y += 6;
    w.kv([
      ['Caso', m.caseId || '-'], ['Organización', m.org || '-'], ['Analista', m.analyst || '-'],
      ['Fecha del informe', utc(D.generated.getTime() / 1000)], ['Clasificación', m.tlp],
      ['Captura analizada', D.file], ['Tamaño y formato', (cap.size ? E.fmtBytes(cap.size) + ', ' : '') + cap.format],
      ['SHA-256 de la captura', {text: cap.sha256 || 'no disponible', font: 'F3'}],
      ['Periodo (UTC)', utc(cap.start) + ' a ' + utc(cap.end) + ' (' + dur(cap.duration) + ')'],
      ['Volumen', cap.packets.toLocaleString('es-ES') + ' paquetes, ' + E.fmtBytes(cap.bytes) + ', ' + cap.hosts + ' hosts, ' + cap.flows + ' conversaciones']
    ], {labelW: 140});
    // Risk banner
    w.ensure(52); w.y += 4;
    const lvl = 'Nivel de riesgo: ' + D.risk.level.toUpperCase(), rl = w.wrap(D.risk.reason, 'F1', 9.5, w.CW - 28), bh = 30 + rl.length * 13;
    w.rect(w.ML, w.y, w.CW, bh, C.soft); w.rect(w.ML, w.y, 5, bh, C[D.risk.color]);
    w.text(w.ML + 16, w.y + 9, lvl, 'F2', 13, C[D.risk.color]);
    rl.forEach((ln, i) => w.text(w.ML + 16, w.y + 28 + i * 13, ln, 'F1', 9.5, C.ink));
    w.y += bh + 10;

    w.h1('1. Resumen ejecutivo');
    D.summary.forEach(s => w.p(s));
    if (D.findings.length) {
      w.p('Hallazgos principales', {font: 'F2', size: 10.5, after: 3});
      w.bullets(D.findings.slice(0, 5).map(f => '[' + SEV[f.sev] + '] ' + f.title + ' (' + phaseLabel(f.phase) + '; ' + f.mitre.map(x => x.id).join(', ') + ')'));
    }
    if (D.recs.length) {
      w.p('Acciones recomendadas', {font: 'F2', size: 10.5, after: 4});
      w.table([{title: 'Prioridad', w: 0.13}, {title: 'Acción', w: 0.55}, {title: 'Motivo', w: 0.32}],
        D.recs.map(r => [{text: r.prio, font: 'F2', color: r.prio === 'Inmediata' ? C.alta : r.prio === 'Alta' ? C.media : C.ink}, r.text, {text: r.why, color: C.muted}]), {size: 8.8});
    }
    if (D.interp) { w.p('Valoración del agente de IA', {font: 'F2', size: 10.5, after: 3}); mdToPdf(w, D.interp); w.p('Generada por un modelo de lenguaje a partir de los datos del análisis; revisada por el analista antes de su entrega.', {size: 8, color: C.muted}); }

    w.h1('2. Línea de tiempo del incidente');
    if (!D.findings.length) w.p('Sin hallazgos que ordenar.');
    else {
      w.p('Cada barra va del primer al último evento de un hallazgo; los carriles son las fases del incidente. Los tiempos son relativos al inicio de la captura.', {size: 9, color: C.muted});
      ganttPdf(w, D);
      if (!D.incident.inOrder) w.p('Orden observado: ' + D.incident.order.map(phaseLabel).join(' -> ') + '. No es el orden habitual de un ataque: puede haber actividades independientes o un compromiso anterior a la captura.', {size: 9});
      for (const ph of D.incident.phases.filter(p => p.findings.length)) {
        w.p(ph.label + ' (' + D.rel(ph.start) + ' a ' + D.rel(ph.end) + ')', {font: 'F2', size: 10.5, after: 3});
        w.table([{title: 'Inicio (UTC)', w: 0.2}, {title: 'Duración', w: 0.12}, {title: 'Sev.', w: 0.08}, {title: 'Hallazgo', w: 0.39}, {title: 'MITRE ATT&CK', w: 0.21}],
          ph.findings.map(f => [utc(f.t).replace(' UTC', ''), dur(f.tEnd - f.t), {text: SEV[f.sev], color: C[f.sev], font: 'F2'}, f.title, {text: f.mitre.map(x => x.id).join(', '), font: 'F3', link: f.mitre[0].url}]), {size: 8.2});
      }
      if (D.incident.links.length) { w.p('Equipos que conectan fases', {font: 'F2', size: 10.5, after: 3}); w.bullets(D.incident.links.map(l => l.ip + ' (' + (l.internal ? 'interno' : 'externo') + '): ' + l.phases.map(phaseLabel).join(' -> ')), {size: 9.5}); }
    }

    w.h1('3. Hallazgos y evidencias');
    w.p('Ordenados por severidad. Las tramas de referencia son números de paquete de la captura original (en Wireshark: frame.number == N). Las contraseñas se muestran enmascaradas.', {size: 9, color: C.muted});
    for (const f of D.findings) {
      w.h2(f.title, f.sev);
      w.kv([
        ['Fase y categoría', phaseLabel(f.phase) + ' / ' + f.cat],
        ...f.mitre.map((x, i) => [i ? '' : 'MITRE ATT&CK', {text: x.id + ' ' + x.name + ' (' + x.tactic + ')', link: x.url}]),
        ['Periodo (UTC)', utc(f.t) + (f.tEnd - f.t >= 1 ? ' a ' + utc(f.tEnd) + ' (' + dur(f.tEnd - f.t) + ')' : '')],
        ['Equipos implicados', uniq(f.ips).slice(0, 12).join(', ') + (uniq(f.ips).length > 12 ? ' y ' + (uniq(f.ips).length - 12) + ' más' : '')],
        ['Tramas de referencia', f.frames.length ? f.frames.join(', ') : 'sin tramas almacenadas']
      ], {size: 9, labelW: 125, after: 4});
      w.p(f.desc, {size: 9.5});
      if (f.evidence.length) { w.p('Evidencias', {font: 'F2', size: 9.5, after: 2}); w.bullets(f.evidence, {size: 8.8}); }
    }

    w.h1('4. Indicadores de compromiso (IoC)');
    if (!D.iocs.length) w.p('No se extrajeron indicadores externos de los hallazgos.');
    else {
      w.p('Indicadores observados en la captura, listos para cargarlos en cortafuegos, proxy, DNS, EDR o SIEM. También se pueden exportar en CSV y en STIX 2.1 desde Sonda. Verifíquelos antes de bloquear: un IoC compartido (CDN, nube) puede afectar a servicios legítimos.', {size: 9, color: C.muted});
      w.table([{title: 'Tipo', w: 0.13}, {title: 'Valor', w: 0.36, font: 'F3'}, {title: 'Contexto', w: 0.3}, {title: 'Primera vez (UTC)', w: 0.21}],
        D.iocs.map(i => [IOC_TYPES[i.type] || i.type, i.value, i.role + (i.mitre.length ? ' [' + i.mitre.join(', ') + ']' : ''), i.first === null ? '-' : utc(i.first).replace(' UTC', '')]), {size: 8});
    }
    if (D.assets.length) {
      w.p('Activos internos afectados', {font: 'F2', size: 10.5, after: 3});
      w.table([{title: 'Equipo', w: 0.22, font: 'F3'}, {title: 'Peor severidad', w: 0.16}, {title: 'Hallazgos', w: 0.12}, {title: 'Fases', w: 0.5}],
        D.assets.map(a => [a.ip + (a.name ? ' (' + a.name + ')' : ''), {text: SEV[a.worst], color: C[a.worst], font: 'F2'}, String(a.findings), a.phases.join(', ')]), {size: 8.5});
    }

    w.h1('5. Reglas de detección (Snort)');
    w.p('Compatibles con Snort 2.9 y Snort 3. Cada regla ocupa una sola línea: cópielas del archivo local.rules que acompaña al informe, no de este PDF, donde se muestran partidas. Antes de usarlas, defina $HOME_NET y $EXTERNAL_NET e incluya el archivo local.rules en la configuración. "Alertas" es el número de paquetes de esta captura que dispararían la regla en el probador de Sonda; valídelas siempre en Snort.', {size: 9, color: C.muted});
    const ruleBlock = (r, note) => { w.p((r.sid ? 'sid ' + r.sid + ' · ' : '') + (r.hits === null || r.hits === undefined ? '' : r.hits + (r.hits === 1 ? ' alerta' : ' alertas') + ' en la captura · ') + note, {size: 8.5, color: C.muted, after: 2}); w.code(r.text); };
    if (D.rules.user.length) { w.p('Reglas seleccionadas por el analista', {font: 'F2', size: 10.5, after: 3}); D.rules.user.forEach(r => ruleBlock(r, r.note || 'regla del analista')); }
    if (D.rules.suggested.length) { w.p('Reglas sugeridas por los hallazgos', {font: 'F2', size: 10.5, after: 3}); D.rules.suggested.forEach(r => ruleBlock(r, r.note)); }
    if (!D.rules.user.length && !D.rules.suggested.length) w.p('No hay reglas que entregar.');

    let sec = 6;
    if (D.files.length) {
      w.h1(sec++ + '. Archivos extraídos');
      w.p('Reconstruidos de flujos TCP en claro (HTTP, FTP, SMB2). El SHA-256 se calculó sobre el contenido final, sin cabeceras. Los archivos se entregan por separado.' + (D.files.length > 300 ? ' Se listan los ejecutables y los primeros archivos (300 de ' + D.files.length + '); la lista completa está en archivos-extraidos-SHA256SUMS.txt del paquete de entrega.' : ''), {size: 9, color: C.muted});
      w.table([{title: 'N.º', w: 0.05}, {title: 'Archivo', w: 0.25}, {title: 'Tipo real', w: 0.18}, {title: 'Tamaño', w: 0.09}, {title: 'SHA-256', w: 0.43, font: 'F3'}],
        D.files.slice(0, 300).map(f => [String(f.n), f.name + ' (' + f.proto + (f.complete ? '' : ', incompleto') + ')', {text: f.type + (f.disguised ? ' - extensión engañosa' : ''), color: f.exe ? C.alta : C.ink}, E.fmtBytes(f.size), f.sha256]), {size: 7.8});
    }

    w.h1(sec++ + '. Perfil del tráfico');
    w.table([{title: 'Protocolo', w: 0.4}, {title: 'Paquetes', w: 0.3}, {title: 'Bytes', w: 0.3}], D.profile.protocols.map(p => [p.name, p.pkts.toLocaleString('es-ES'), E.fmtBytes(p.bytes)]), {size: 8.5});
    w.table([{title: 'Host', w: 0.3, font: 'F3'}, {title: 'Tipo', w: 0.12}, {title: 'Enviado', w: 0.16}, {title: 'Recibido', w: 0.16}, {title: 'Contactos', w: 0.26}],
      D.profile.hosts.map(h => [h.ip + (h.name ? ' (' + h.name + ')' : ''), h.internal ? 'interno' : 'externo', E.fmtBytes(h.out), E.fmtBytes(h.in), String(h.peers)]), {size: 8.5});
    w.h1(sec++ + '. Metodología y limitaciones');
    w.bullets([
      'Análisis realizado con Sonda sobre la captura indicada, sin modificarla. Su SHA-256 figura en la portada para comprobar la integridad del archivo entregado.',
      'Las detecciones son heurísticas sobre el tráfico: indican patrones compatibles con un ataque, no lo prueban. El mapeo a MITRE ATT&CK asigna la técnica más probable para cada patrón.',
      'Solo se inspecciona contenido en claro. El tráfico cifrado (TLS, SSH, SMB3 cifrado) se valora por sus metadatos (direcciones, volúmenes, tiempos, SNI).',
      'Los tiempos se expresan en UTC según las marcas de la captura; dependen del reloj del equipo que la tomó.',
      cap.pktsTruncated ? 'La captura supera ' + E.MAX_PKTS.toLocaleString('es-ES') + ' paquetes: las estadísticas cubren todo, pero las evidencias, la extracción de archivos y la prueba de reglas usan los primeros ' + E.MAX_PKTS.toLocaleString('es-ES') + '.' : 'Se analizaron todos los paquetes de la captura.',
      cap.truncated ? 'El archivo parece truncado: se analizó hasta el último paquete legible.' : 'El archivo se leyó completo.'
    ], {size: 9});

    return w.finish((w, i, n) => {
      tlpBadge(w, w.ML + w.CW, 24, m.tlp);
      if (i) { w.text(w.ML, 26, (m.caseId ? m.caseId + ' · ' : '') + title, 'F1', 7.5, C.muted); w.line(w.ML, 42, w.ML + w.CW, 42, C.line, 0.5); }
      w.line(w.ML, w.PH - 44, w.ML + w.CW, w.PH - 44, C.line, 0.5);
      const foot = D.file + (cap.sha256 ? ' · SHA-256 ' + cap.sha256.slice(0, 16) + '…' : '') + ' · ' + m.tlp, pn = 'Página ' + (i + 1) + ' de ' + n;
      w.text(w.ML, w.PH - 38, clean(foot).slice(0, 110), 'F1', 7.5, C.muted);
      w.text(w.ML + w.CW - textW(pn, 'F1', 7.5), w.PH - 38, pn, 'F1', 7.5, C.muted);
    }, {title, subject: 'Análisis de ' + D.file + ' (' + m.tlp + ')', author: [m.analyst, m.org].filter(Boolean).join(', '), date: D.generated});
  }
  // The agent's Markdown, reduced to paragraphs and bullets.
  function mdToPdf(w, md) {
    const strip = s => s.replace(/\*\*([^*]+)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1').replace(/(^|\s)\*([^*\s][^*]*)\*/g, '$1$2');
    let list = [];
    const flush = () => { if (list.length) { w.bullets(list, {size: 9.5}); list = []; } };
    for (const raw of String(md).replace(/\r/g, '').split('\n')) {
      const l = raw.trim(); let m;
      if (!l || /^```/.test(l) || /^\|?[\s:|-]+\|?$/.test(l)) { flush(); continue; }
      if ((m = l.match(/^#{1,6}\s+(.*)/))) { flush(); w.p(strip(m[1]), {font: 'F2', size: 10, after: 2}); }
      else if ((m = l.match(/^(?:[-*•]|\d+[.)])\s+(.*)/))) list.push(strip(m[1]));
      else { flush(); w.p(strip(l.replace(/^\||\|$/g, '').replace(/\s*\|\s*/g, ' · ')), {size: 9.5}); }
    }
    flush();
  }

  // ---------- Markdown, CSV and STIX ----------
  function markdown(D) {
    const m = D.meta, cell = s => String(s).replace(/\|/g, '/').replace(/\n/g, ' ');
    let r = '# ' + (m.title || 'Informe de análisis de tráfico de red') + '\n\n' +
      '| | |\n|---|---|\n' + [['Caso', m.caseId || '-'], ['Organización', m.org || '-'], ['Analista', m.analyst || '-'], ['Fecha del informe', utc(D.generated.getTime() / 1000)], ['Clasificación', m.tlp], ['Captura', D.file], ['SHA-256 de la captura', '`' + (D.capture.sha256 || '-') + '`'], ['Periodo (UTC)', utc(D.capture.start) + ' a ' + utc(D.capture.end)], ['Volumen', D.capture.packets + ' paquetes, ' + E.fmtBytes(D.capture.bytes)]].map(([k, v]) => '| ' + k + ' | ' + cell(v) + ' |').join('\n') +
      '\n\n**Nivel de riesgo: ' + D.risk.level + '.** ' + D.risk.reason + '\n\n## 1. Resumen ejecutivo\n\n' + D.summary.join('\n\n') + '\n\n';
    if (D.recs.length) r += '### Acciones recomendadas\n\n| Prioridad | Acción | Motivo |\n|---|---|---|\n' + D.recs.map(x => '| ' + x.prio + ' | ' + cell(x.text) + ' | ' + cell(x.why) + ' |').join('\n') + '\n\n';
    if (D.interp) r += '### Valoración del agente de IA\n\n' + D.interp + '\n\n';
    r += '## 2. Línea de tiempo del incidente\n\n' + (D.incident.inOrder || !D.findings.length ? '' : 'Orden observado: ' + D.incident.order.map(phaseLabel).join(' → ') + ' (no es el habitual).\n\n');
    for (const ph of D.incident.phases.filter(p => p.findings.length)) r += '### ' + ph.label + '\n\n| Inicio (UTC) | Severidad | Hallazgo | ATT&CK |\n|---|---|---|---|\n' + ph.findings.map(f => '| ' + utc(f.t) + ' | ' + SEV[f.sev] + ' | ' + cell(f.title) + ' | ' + f.mitre.map(x => '[' + x.id + '](' + x.url + ')').join(', ') + ' |').join('\n') + '\n\n';
    r += '## 3. Hallazgos y evidencias\n\n' + (D.findings.length ? D.findings.map(f => '### [' + SEV[f.sev] + '] ' + f.title + '\n\n- Fase: ' + phaseLabel(f.phase) + '\n- MITRE ATT&CK: ' + f.mitre.map(x => '[' + x.id + ' ' + x.name + '](' + x.url + ')').join(', ') + '\n- Periodo (UTC): ' + utc(f.t) + ' a ' + utc(f.tEnd) + '\n- Tramas de referencia: ' + (f.frames.join(', ') || '-') + '\n\n' + f.desc + '\n\n' + f.evidence.map(e => '- ' + e).join('\n') + '\n').join('\n') : 'Sin hallazgos.\n');
    r += '\n## 4. Indicadores de compromiso\n\n' + (D.iocs.length ? '| Tipo | Valor | Contexto | Primera vez (UTC) |\n|---|---|---|---|\n' + D.iocs.map(i => '| ' + (IOC_TYPES[i.type] || i.type) + ' | `' + cell(i.value) + '` | ' + cell(i.role) + ' | ' + (i.first === null ? '-' : utc(i.first)) + ' |').join('\n') + '\n' : 'Sin indicadores.\n');
    const rules = D.rules.user.concat(D.rules.suggested);
    r += '\n## 5. Reglas Snort\n\n' + (rules.length ? '```\n' + rules.map(x => '# ' + (x.note || '').replace(/\n/g, ' ') + '\n' + x.text).join('\n\n') + '\n```\n' : 'Sin reglas.\n');
    r += '\n## Perfil del tráfico\n\n| Protocolo | Paquetes | Bytes |\n|---|---:|---:|\n' + D.profile.protocols.map(p => '| ' + p.name + ' | ' + p.pkts + ' | ' + E.fmtBytes(p.bytes) + ' |').join('\n') + '\n\n| Host | Tipo | Enviado | Recibido |\n|---|---|---:|---:|\n' + D.profile.hosts.map(h => '| ' + h.ip + (h.name ? ' (' + h.name + ')' : '') + ' | ' + (h.internal ? 'interno' : 'externo') + ' | ' + E.fmtBytes(h.out) + ' | ' + E.fmtBytes(h.in) + ' |').join('\n') + '\n';
    if (D.files.length) r += '\n## Archivos extraídos\n\n| N.º | Archivo | Protocolo | Tipo real | Tamaño | SHA-256 |\n|---:|---|---|---|---:|---|\n' + D.files.map(f => '| ' + f.n + ' | ' + cell(f.name) + ' | ' + f.proto + ' | ' + f.type + (f.disguised ? ' (extensión engañosa)' : '') + ' | ' + E.fmtBytes(f.size) + ' | `' + f.sha256 + '` |').join('\n') + '\n';
    return r;
  }
  // CSV for spreadsheets and SIEM. Values that start like a formula are prefixed with ' (the user agent comes from the attacker).
  function iocCsv(D) {
    const q = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    return ['tipo,valor,contexto,primera_vez_utc,hallazgos,mitre_attack,clasificacion'].concat(D.iocs.map(i => [i.type, i.value, i.role, i.first === null ? '' : new Date(i.first * 1000).toISOString(), i.findings.map(id => (D.findings.find(f => f.id === id) || {}).title).filter(Boolean).join(' | '), i.mitre.join(' '), D.meta.tlp].map(q).join(','))).join('\r\n') + '\r\n';
  }
  const TLP_STIX = {'TLP:CLEAR': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', 'TLP:GREEN': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'TLP:AMBER': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', 'TLP:AMBER+STRICT': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', 'TLP:RED': 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'};
  function uuid4() {
    const b = new Uint8Array(16), c = typeof globalThis !== 'undefined' && globalThis.crypto;
    if (c && c.getRandomValues) c.getRandomValues(b); else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }
  function stixPattern(i) {
    const s = v => "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
    switch (i.type) {
      case 'ip': return '[' + (i.value.includes(':') ? 'ipv6-addr' : 'ipv4-addr') + ':value = ' + s(i.value) + ']';
      case 'dominio': return '[domain-name:value = ' + s(i.value) + ']';
      case 'url': return '[url:value = ' + s(i.value) + ']';
      case 'sha256': return "[file:hashes.'SHA-256' = " + s(i.value) + ']';
      case 'mac': return '[mac-addr:value = ' + s(i.value.toLowerCase()) + ']';
      case 'user-agent': return "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = " + s(i.value) + ']';
      case 'puerto': { const [p, proto] = i.value.split('/'); return '[network-traffic:dst_port = ' + (+p) + (proto ? ' AND network-traffic:protocols[*] = ' + s(proto) : '') + ']'; }
    }
    return null;
  }
  function stix(D) {
    const now = D.generated.toISOString(), marks = [TLP_STIX[D.meta.tlp]], base = {spec_version: '2.1', created: now, modified: now, object_marking_refs: marks};
    const identity = {type: 'identity', id: 'identity--' + uuid4(), ...base, name: D.meta.org || 'Sonda', identity_class: D.meta.org ? 'organization' : 'system'};
    const objects = [identity], aps = new Map();
    for (const f of D.findings) for (const x of f.mitre) if (!aps.has(x.id)) aps.set(x.id, {type: 'attack-pattern', id: 'attack-pattern--' + uuid4(), ...base, created_by_ref: identity.id, name: x.name, external_references: [{source_name: 'mitre-attack', external_id: x.id, url: x.url}]});
    objects.push(...aps.values());
    for (const i of D.iocs) {
      const pattern = stixPattern(i); if (!pattern) continue;
      const ind = {type: 'indicator', id: 'indicator--' + uuid4(), ...base, created_by_ref: identity.id, name: (IOC_TYPES[i.type] || i.type) + ': ' + i.value, description: i.role, indicator_types: ['malicious-activity'],
        pattern, pattern_type: 'stix', valid_from: i.first === null ? now : new Date(i.first * 1000).toISOString()};
      objects.push(ind);
      for (const id of i.mitre) if (aps.has(id)) objects.push({type: 'relationship', id: 'relationship--' + uuid4(), ...base, created_by_ref: identity.id, relationship_type: 'indicates', source_ref: ind.id, target_ref: aps.get(id).id});
    }
    objects.push({type: 'report', id: 'report--' + uuid4(), ...base, created_by_ref: identity.id, name: D.meta.title || 'Análisis de ' + D.file, description: D.summary.join(' '), report_types: ['threat-report'], published: now, object_refs: objects.map(o => o.id)});
    return JSON.stringify({type: 'bundle', id: 'bundle--' + uuid4(), objects}, null, 2);
  }

  function rulesFile(D) {
    const all = D.rules.user.concat(D.rules.suggested);
    return ['# local.rules entregado con el informe "' + (D.meta.title || 'Análisis de ' + D.file) + '"' + (D.meta.caseId ? ' (' + D.meta.caseId + ')' : ''), '# Captura: ' + D.file + (D.capture.sha256 ? ' (SHA-256 ' + D.capture.sha256 + ')' : ''), '# Clasificación: ' + D.meta.tlp + '. Generado por Sonda el ' + utc(D.generated.getTime() / 1000) + '.',
      '# Define $HOME_NET y $EXTERNAL_NET en snort.lua (Snort 3) o snort.conf (Snort 2) e incluye este archivo.', ''].join('\n') + '\n' +
      all.map(r => '# ' + String(r.note || '').replace(/\n/g, ' ') + (r.hits === null || r.hits === undefined ? '' : ' (' + r.hits + ' alertas en la captura)') + '\n' + r.text).join('\n\n') + '\n';
  }

  return {build, pdf, markdown, iocCsv, stix, rulesFile, TLP, clean};
})();
if (typeof module !== 'undefined') module.exports = Report;
