/*
 * Servidor local de Sonda (Node.js 18 o superior, sin dependencias).
 *  - Sirve la aplicación desde ./public
 *  - GET  /api/health    indica si hay clave de API configurada
 *  - POST /api/messages  reenvía la conversación a la API de Anthropic
 *
 * La clave nunca llega al navegador. Por defecto escucha solo en 127.0.0.1
 * para que nadie más en tu red pueda gastar tu clave.
 */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

// Carga mínima de .env (CLAVE=valor), sin sobrescribir variables ya definidas.
(function loadEnv() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (!m || line.trim().startsWith('#')) continue;
    const val = m[2].replace(/^(['"])(.*)\1$/, '$2');
    if (process.env[m[1]] === undefined) process.env[m[1]] = val;
  }
})();

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const API_KEY = process.env.ANTHROPIC_API_KEY || '';
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const MAX_TOKENS = Math.min(Number(process.env.MAX_TOKENS) || 4096, 16000);
const API_URL = process.env.ANTHROPIC_API_URL || 'https://api.anthropic.com/v1/messages';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 4 * 1024 * 1024;

const MIME = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon'};

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body)});
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('Petición demasiado grande'), {status: 413})); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function proxyMessages(req, res) {
  if (!API_KEY) return sendJson(res, 401, {error: {message: 'Falta ANTHROPIC_API_KEY en el archivo .env'}});
  let payload;
  try { payload = JSON.parse(await readBody(req)); }
  catch (e) { return sendJson(res, e.status || 400, {error: {message: e.status ? e.message : 'JSON inválido'}}); }
  if (!Array.isArray(payload.messages) || !payload.messages.length) return sendJson(res, 400, {error: {message: 'Faltan mensajes'}});

  // Solo se reenvían los campos necesarios; el modelo y el límite los fija el servidor.
  const body = {model: MODEL, max_tokens: Math.min(Number(payload.max_tokens) || MAX_TOKENS, MAX_TOKENS), messages: payload.messages};
  if (Array.isArray(payload.tools) && payload.tools.length) body.tools = payload.tools;

  const ctl = new AbortController();
  req.on('close', () => { if (!res.writableEnded) ctl.abort(); });
  try {
    const r = await fetch(API_URL, {
      method: 'POST',
      headers: {'content-type': 'application/json', 'x-api-key': API_KEY, 'anthropic-version': '2023-06-01'},
      body: JSON.stringify(body),
      signal: ctl.signal
    });
    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch (e) { data = {error: {message: text.slice(0, 300)}}; }
    if (!r.ok) console.error('[api]', r.status, data && data.error && data.error.message);
    sendJson(res, r.status, data);
  } catch (e) {
    if (ctl.signal.aborted) return;
    console.error('[api] error de red:', e.message);
    sendJson(res, 502, {error: {message: 'No se pudo contactar con la API de Anthropic: ' + e.message}});
  }
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Prohibido'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, {'content-type': 'text/plain; charset=utf-8'}); return res.end('No encontrado'); }
    res.writeHead(200, {'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache'});
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/api/health' && req.method === 'GET') return sendJson(res, 200, {ok: true, hasKey: Boolean(API_KEY), model: MODEL});
  if (req.url === '/api/messages' && req.method === 'POST') return proxyMessages(req, res);
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res);
  res.writeHead(405); res.end();
});

server.listen(PORT, HOST, () => {
  console.log('Sonda escuchando en http://' + (HOST === '0.0.0.0' ? 'localhost' : HOST) + ':' + PORT);
  console.log(API_KEY ? 'Agente activo con el modelo ' + MODEL : 'Aviso: sin ANTHROPIC_API_KEY el análisis funciona, pero el agente y el chat no.');
});
