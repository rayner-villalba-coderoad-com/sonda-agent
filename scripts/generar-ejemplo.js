// Genera ejemplo.pcap con tráfico normal y ataques simulados, para probar Sonda
// o abrirlo en Wireshark/Snort.  Uso: npm run ejemplo
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const Engine = require('../public/engine.js');
const out = path.join(__dirname, '..', 'ejemplo.pcap');
fs.writeFileSync(out, Buffer.from(Engine.sampleCapture()));
console.log('Captura de ejemplo guardada en', out);
