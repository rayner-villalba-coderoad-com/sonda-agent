// Analiza un pcap desde la terminal, sin navegador ni IA.
// Uso: npm run analizar -- ruta/captura.pcap [--reglas salida.rules] [--archivos carpeta]
//        [--pdf informe.pdf] [--iocs iocs.csv] [--stix iocs.json] [--caso ID] [--org NOMBRE] [--analista NOMBRE] [--tlp TLP:AMBER]
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const Engine = require('../public/engine.js');
const Report = require('../public/report.js');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i < 0 ? null : (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : def); };
const FLAGS = ['--reglas', '--archivos', '--pdf', '--iocs', '--stix', '--caso', '--org', '--analista', '--tlp', '--titulo'];
const values = new Set(FLAGS.map(f => opt(f, null)));
const file = args.find(a => !a.startsWith('--') && !values.has(a));
if (!file) { console.error('Uso: npm run analizar -- captura.pcap [--reglas local.rules] [--archivos carpeta] [--pdf informe.pdf] [--iocs iocs.csv] [--stix iocs.json]\n       datos del informe: [--caso ID] [--org NOMBRE] [--analista NOMBRE] [--titulo TEXTO] [--tlp ' + Report.TLP.join('|') + ']'); process.exit(1); }
(async () => {
  const buf = fs.readFileSync(file);
  const M = await Engine.parse(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
  const s = Engine.summary(M, file);
  console.log(`\n${file}: ${s.paquetes} paquetes, ${s.volumen}, ${s.duracion_seg} s, ${s.hosts} hosts, ${s.conversaciones} conversaciones\n`);
  console.log('Protocolos:', s.protocolos.map(p => p.protocolo + ' ' + p.paquetes).join(', '));
  console.log(`\nHallazgos (${M.findings.length}):`);
  for (const f of M.findings) {
    console.log(`\n[${f.sev.toUpperCase()}] ${f.title}\n  ${f.desc}`);
    console.log('  ATT&CK: ' + f.mitre.map(m => `${m.id} ${m.name} (${m.tactic})`).join(', '));
    f.evidence.forEach(e => console.log('  - ' + e));
  }
  const I = Engine.incident(M), rel = t => { const r = Math.max(0, t - M.start); return Math.floor(r / 60) + ':' + String(Math.floor(r % 60)).padStart(2, '0'); };
  if (M.findings.length) {
    console.log('\nLínea de tiempo del incidente:' + (I.inOrder ? '' : ` (orden observado: ${I.order.map(id => Engine.PHASES.find(p => p.id === id).label).join(' → ')}; no es el habitual)`));
    for (const p of I.phases.filter(p => p.findings.length)) {
      console.log(`\n  ${p.label.toUpperCase()}  ${rel(p.start)} – ${rel(p.end)}`);
      for (const f of p.findings) console.log(`    ${rel(f.t).padStart(5)}  ${f.sev.padEnd(5)}  ${f.title}  [${f.mitre.map(m => m.id).join(', ')}]`);
    }
    I.links.forEach(l => console.log(`\n  ${l.ip} conecta: ${l.phases.map(id => Engine.PHASES.find(p => p.id === id).label).join(' → ')}`));
  }
  console.log(`\nArchivos transferidos (${M.files.length}):`);
  for (const f of M.files) {
    console.log(`\n  ${f.saveAs}  ${f.proto} ${f.dir}, ${Engine.fmtBytes(f.size)}, ${f.type}${f.complete ? '' : ', INCOMPLETO'}\n    ${f.path}\n    ${f.src}:${f.sport} → ${f.dst}:${f.dport}\n    SHA-256 ${f.sha256}`);
    f.notes.forEach(n => console.log('    ! ' + n));
  }
  M.fileNotes.forEach(n => console.log('  ! ' + n));
  const rulesOut = opt('--reglas', 'local.rules');
  if (rulesOut) {
    const rules = M.findings.flatMap(f => f.rules.map(r => '# ' + f.title + '\n' + r));
    fs.writeFileSync(rulesOut, '# Generado por Sonda\n\n' + rules.join('\n\n') + '\n');
    console.log(`\n${rules.length} reglas guardadas en ${rulesOut}`);
  }
  const pdfOut = opt('--pdf', 'informe.pdf'), csvOut = opt('--iocs', 'iocs.csv'), stixOut = opt('--stix', 'iocs.stix.json');
  if (pdfOut || csvOut || stixOut) {
    const tlp = (opt('--tlp', '') || 'TLP:AMBER').toUpperCase().replace(/^(?!TLP:)/, 'TLP:');
    if (!Report.TLP.includes(tlp)) { console.error('TLP no válido: ' + tlp + '. Usa ' + Report.TLP.join(', ')); process.exit(1); }
    const D = Report.build(M, {file: path.basename(file), meta: {title: opt('--titulo', '') || '', caseId: opt('--caso', '') || '', org: opt('--org', '') || '', analyst: opt('--analista', '') || '', tlp}});
    console.log(`\nNivel de riesgo: ${D.risk.level}. ${D.iocs.length} indicadores de compromiso.`);
    if (pdfOut) { fs.writeFileSync(pdfOut, Report.pdf(D)); console.log('Informe PDF guardado en ' + pdfOut); }
    if (csvOut) { fs.writeFileSync(csvOut, Report.iocCsv(D)); console.log('IoC en CSV guardados en ' + csvOut); }
    if (stixOut) { fs.writeFileSync(stixOut, Report.stix(D)); console.log('IoC en STIX 2.1 guardados en ' + stixOut); }
  }
  const dir = opt('--archivos', 'archivos-extraidos');
  if (dir) {
    // saveAs is already sanitized by the engine (no directories), so it cannot escape the folder.
    fs.mkdirSync(dir, {recursive: true});
    for (const f of M.files) fs.writeFileSync(path.join(dir, f.saveAs), f.data);
    fs.writeFileSync(path.join(dir, 'SHA256SUMS'), M.files.map(f => f.sha256 + '  ' + f.saveAs).join('\n') + '\n');
    console.log(`\n${M.files.length} archivos guardados en ${dir}. Verifícalos con: cd ${dir} && sha256sum -c SHA256SUMS`);
  }
})().catch(e => { console.error('Error:', e.message); process.exit(1); });
