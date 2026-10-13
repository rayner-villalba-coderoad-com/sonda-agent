/*
 * Web Worker de Sonda: lee la captura, reconstruye flujos, extrae archivos,
 * detecta y prueba las reglas fuera del hilo de la interfaz.
 *
 * Mensajes al hilo principal, en este orden:
 *   {type: 'ready'}                             el worker cargó engine.js
 *   {type: 'progress', frac, n, stage}          mientras lee ('leer', 'archivos', 'reglas')
 *   {type: 'model', M, buf, tests, total}       modelo sin paquetes; buf y archivos se transfieren
 *   {type: 'pkts', batch}                       paquetes por lotes (ver Engine.addPackets)
 *   {type: 'end'}                               fin
 *   {type: 'error', message}                    la captura no se pudo leer
 */
'use strict';
importScripts('engine.js');
const BATCH = 20000;
self.postMessage({type: 'ready'});
self.onmessage = async e => {
  const {buf, rules} = e.data;
  try {
    const M = await Engine.parse(buf, (frac, n, stage) => self.postMessage({type: 'progress', frac, n, stage: stage || 'leer'}));
    if (rules && rules.length) self.postMessage({type: 'progress', frac: 1, n: M.count, stage: 'reglas'});
    const tests = (rules || []).map(text => Engine.testRule(text, M));
    const {pkts, transfer} = Engine.forTransfer(M, buf);
    self.postMessage({type: 'model', M, buf, tests, total: pkts.length}, transfer);
    for (let i = 0; i < pkts.length; i += BATCH) self.postMessage({type: 'pkts', batch: pkts.slice(i, i + BATCH)});
    self.postMessage({type: 'end'});
  } catch (err) {
    self.postMessage({type: 'error', message: (err && err.message) || String(err)});
  }
};
