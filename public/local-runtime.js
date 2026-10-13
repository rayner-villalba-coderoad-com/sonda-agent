/*
 * Runtime local de Sonda.
 * Implementa la misma interfaz que usa app.js (window.claude.use('sample') y
 * window.claude.use('downloads')), pero hablando con el servidor local
 * (server.js), que reenvía las peticiones a la API de Anthropic.
 *
 * Las herramientas del agente se ejecutan aquí, en el navegador, contra la
 * captura ya cargada: el servidor nunca recibe el pcap, solo los mensajes.
 */
(function () {
  'use strict';
  const MAX_ROUNDS = 12;

  function apiError(code, message, text) { return {code, message, text: text || undefined}; }

  async function callApi(body, signal) {
    let res;
    try {
      res = await fetch('/api/messages', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body), signal});
    } catch (e) {
      if (e && e.name === 'AbortError') throw apiError('cancelled', 'Cancelado');
      throw apiError('upstream_error', 'No se pudo contactar con el servidor local: ' + (e && e.message));
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = (data && data.error && (data.error.message || data.error)) || ('HTTP ' + res.status);
      const code = res.status === 401 || res.status === 403 ? 'not_granted'
        : res.status === 429 || res.status === 529 ? 'rate_limited'
        : res.status === 413 ? 'prompt_too_large'
        : 'upstream_error';
      throw apiError(code, String(msg));
    }
    return data;
  }

  // Convierte la entrada de app.js (texto o turnos) en mensajes de la API,
  // fusionando turnos consecutivos del mismo rol.
  function toMessages(input) {
    if (typeof input === 'string') return [{role: 'user', content: input}];
    const out = [];
    for (const t of input) {
      if (!t || !t.content) continue;
      const last = out[out.length - 1];
      if (last && last.role === t.role) last.content += '\n\n' + t.content;
      else out.push({role: t.role, content: String(t.content)});
    }
    if (!out.length || out[0].role !== 'user') out.unshift({role: 'user', content: '(inicio de la conversación)'});
    return out;
  }

  async function sample(input, opts) {
    opts = opts || {};
    const messages = toMessages(input);
    const tools = Array.isArray(opts.tools) ? opts.tools : [];
    const apiTools = tools.map(t => ({name: t.name, description: t.description || '', input_schema: t.inputSchema || {type: 'object', properties: {}}}));
    let lastText = '';

    for (let round = 0; round < MAX_ROUNDS; round++) {
      if (opts.signal && opts.signal.aborted) throw apiError('cancelled', 'Cancelado', lastText);
      const body = {messages, max_tokens: 4096};
      if (apiTools.length) body.tools = apiTools;
      if (opts.onText && round === 0) opts.onText({text: '', delta: ''});

      let res;
      try { res = await callApi(body, opts.signal); }
      catch (e) { e.text = e.text || lastText || undefined; throw e; }

      const blocks = Array.isArray(res.content) ? res.content : [];
      const text = blocks.filter(b => b.type === 'text').map(b => b.text).join('');
      if (text) { lastText = text; if (opts.onText) opts.onText({text, delta: text}); }

      const uses = blocks.filter(b => b.type === 'tool_use');
      if (res.stop_reason !== 'tool_use' || !uses.length) {
        if (!text) throw apiError('empty_completion', 'La respuesta llegó vacía');
        return {text, truncated: res.stop_reason === 'max_tokens'};
      }

      messages.push({role: 'assistant', content: blocks});
      const results = [];
      for (const u of uses) {
        const tool = tools.find(t => t.name === u.name);
        let content, isError = false;
        try {
          if (!tool) throw new Error('Herramienta desconocida: ' + u.name);
          const out = await tool.execute(u.input || {});
          content = typeof out === 'string' ? out : JSON.stringify(out);
        } catch (e) {
          content = (e && e.message) || String(e);
          isError = true;
        }
        results.push({type: 'tool_result', tool_use_id: u.id, content: String(content).slice(0, 60000), is_error: isError});
      }
      messages.push({role: 'user', content: results});
    }
    throw apiError('upstream_error', 'El agente usó demasiadas herramientas seguidas sin responder', lastText);
  }

  function parseJsonLoose(text) {
    try { return JSON.parse(text); } catch (e) {}
    const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fence) { try { return JSON.parse(fence[1]); } catch (e) {} }
    const a = text.search(/[\[{]/), b = Math.max(text.lastIndexOf('}'), text.lastIndexOf(']'));
    if (a >= 0 && b > a) { try { return JSON.parse(text.slice(a, b + 1)); } catch (e) {} }
    throw apiError('invalid_json', 'La respuesta no contiene JSON válido', text);
  }

  sample.json = async function (input, opts) {
    const extra = '\n\nResponde únicamente con JSON válido, sin texto adicional.';
    const prompt = typeof input === 'string' ? input + extra : input.map((t, i) => i === input.length - 1 ? {role: t.role, content: t.content + extra} : t);
    const r = await sample(prompt, opts);
    if (r.truncated) throw apiError('invalid_json', 'La respuesta se cortó antes de completar el JSON', r.text);
    return parseJsonLoose(r.text);
  };
  sample.limits = async () => ({maxInputBytes: 262144});

  const downloads = {
    async save({filename, data}) {
      const blob = data instanceof Blob ? data : new Blob([data], {type: 'text/plain;charset=utf-8'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      return {status: 'saved'};
    }
  };

  let health = null;
  async function checkHealth() {
    if (!health) health = fetch('/api/health').then(r => r.json()).catch(() => ({ok: false}));
    return health;
  }

  window.claude = {
    async use(name) {
      if (name === 'downloads') return downloads;
      if (name === 'sample') { const h = await checkHealth(); return h && h.ok && h.hasKey ? sample : null; }
      return null;
    }
  };
})();
