const Engine = (() => {
  'use strict';
  const MAX_PKTS = 250000;
  const PORT_APP = {20:'FTP',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',69:'TFTP',80:'HTTP',88:'Kerberos',110:'POP3',123:'NTP',135:'RPC',137:'NetBIOS',138:'NetBIOS',139:'NetBIOS',143:'IMAP',161:'SNMP',162:'SNMP',389:'LDAP',443:'TLS',445:'SMB',465:'TLS',514:'Syslog',587:'SMTP',636:'TLS',853:'TLS',993:'TLS',995:'TLS',1433:'MSSQL',1900:'SSDP',3306:'MySQL',3389:'RDP',5060:'SIP',5353:'mDNS',5355:'LLMNR',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8000:'HTTP',8080:'HTTP',8443:'TLS',8888:'HTTP'};
  const SUS_PORTS = {4444:'puerto por defecto de Metasploit/Meterpreter',4445:'usado por shells reversas',1337:'asociado a backdoors',31337:'Back Orifice y otros backdoors',12345:'NetBus y otros backdoors',6666:'IRC, usado como canal C2',6667:'IRC, usado como canal C2',5555:'ADB de Android expuesto',9001:'Tor (ORPort)',9050:'proxy SOCKS de Tor',2323:'Telnet alternativo usado por botnets IoT'};
  const AUTH_PORTS = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',110:'POP3',143:'IMAP',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC'};
  const QT = {1:'A',2:'NS',5:'CNAME',6:'SOA',10:'NULL',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',65:'HTTPS',255:'ANY'};
  const RCODE = {0:'OK',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'};
  const FLAG_NAMES = ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'];
  const HTTP_METHODS = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) /;
  const UA_TOOLS = /sqlmap|nikto|nmap|masscan|zgrab|hydra|dirbuster|gobuster|wpscan|nuclei|acunetix|metasploit|python-requests|go-http-client|powershell|curl|wget/i;
  const UA_HIGH = /sqlmap|nikto|nmap|masscan|hydra|dirbuster|gobuster|wpscan|nuclei|acunetix|metasploit/i;
  const WEB_PATTERNS = [
    {id:'sqli', kind:'Inyección SQL', re:/union\s+(all\s+)?select|'\s*or\s+'?1'?\s*=\s*'?1|sleep\(\s*\d+\s*\)|information_schema/i, contents:['union','select']},
    {id:'trav', kind:'Path traversal', re:/\.\.[\/\\]/, contents:['../']},
    {id:'xss', kind:'Cross-site scripting', re:/<script|javascript:|onerror\s*=/i, contents:['<script']},
    {id:'lfi', kind:'Lectura de archivos del sistema', re:/\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini/i, contents:['/etc/passwd']},
    {id:'cmd', kind:'Inyección de comandos', re:/;\s*(wget|curl|nc|bash|sh)\s|\|\s*(nc|bash|sh)\b|\$\((wget|curl|id|whoami)/i, contents:['wget']},
    {id:'jndi', kind:'Log4Shell (JNDI)', re:/\$\{jndi:/i, contents:['${jndi:']}
  ];

  const r16 = (b, o) => (b[o] << 8) | b[o + 1];
  const r32 = (b, o) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
  const latin = (b, s, e) => { let out = ''; e = Math.min(e, b.length); for (let i = s; i < e; i++) out += String.fromCharCode(b[i]); return out; };
  const ip4 = (b, o) => b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
  const hex2 = n => n.toString(16).padStart(2, '0');
  const mac = (b, o) => { const a = []; for (let i = 0; i < 6; i++) a.push(hex2(b[o + i])); return a.join(':'); };
  function ip6(b, o) {
    const g = []; for (let i = 0; i < 8; i++) g.push(r16(b, o + i * 2));
    let bs = -1, bl = 0, cs = -1, cl = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) { if (cs < 0) { cs = i; cl = 1; } else cl++; if (cl > bl) { bl = cl; bs = cs; } } else cs = -1;
    }
    const h = g.map(x => x.toString(16));
    if (bl < 2) return h.join(':');
    return h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
  }
  function isInternal(ip) {
    if (!ip) return true;
    if (ip.includes(':')) { const l = ip.toLowerCase(); return l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff') || l === '::'; }
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] >= 224;
  }
  function flagStr(f) { const out = []; for (let i = 0; i < 8; i++) if (f & (1 << i)) out.push(FLAG_NAMES[i]); return out.join(', '); }
  function baseDomain(name) {
    const l = name.toLowerCase().replace(/\.$/, '').split('.');
    if (l.length <= 2) return l.join('.');
    const sld = l[l.length - 2];
    if (l[l.length - 1].length === 2 && /^(co|com|org|net|gov|edu|ac|gob|mil|nom)$/.test(sld)) return l.slice(-3).join('.');
    return l.slice(-2).join('.');
  }
  const mask = s => !s ? '(vacía)' : s.length <= 2 ? '**' : s[0] + '*'.repeat(Math.min(8, s.length - 2)) + s[s.length - 1];
  const decodeSafe = s => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } };
  const tick = () => new Promise(r => setTimeout(r, 0));

  // ---------- Decoders ----------
  function decodeLink(p, lt, d) {
    let o = 0, et = -1;
    switch (lt) {
      case 1:
        if (d.length < 14) return;
        p.dmac = mac(d, 0); p.smac = mac(d, 6); et = r16(d, 12); o = 14;
        while ((et === 0x8100 || et === 0x88a8) && o + 4 <= d.length) { p.vlan = r16(d, o) & 0xfff; et = r16(d, o + 2); o += 4; }
        if (et <= 1500) { p.info = 'Trama 802.3/LLC'; return; }
        break;
      case 113: if (d.length < 16) return; et = r16(d, 14); o = 16; break;
      case 276: if (d.length < 20) return; et = r16(d, 0); o = 20; break;
      case 0: case 108: {
        if (d.length < 4) return;
        const le = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24), be = r32(d, 0);
        const fam = (le > 0 && le < 256) ? le : be;
        et = fam === 2 ? 0x0800 : ([24, 28, 30].includes(fam) ? 0x86dd : -1); o = 4; break;
      }
      case 101: case 12: case 14: case 228: case 229: { const v = d[0] >> 4; et = v === 4 ? 0x0800 : v === 6 ? 0x86dd : -1; break; }
      default: p.info = 'Tipo de enlace ' + lt + ' no soportado'; return;
    }
    if (et === 0x0800) ipv4(p, d, o);
    else if (et === 0x86dd) ipv6(p, d, o);
    else if (et === 0x0806) arp(p, d, o);
    else if (et >= 0) p.info = 'EtherType 0x' + et.toString(16).padStart(4, '0');
  }
  function ipv4(p, d, o) {
    if (o + 20 > d.length) return;
    const ihl = (d[o] & 15) * 4, tot = r16(d, o + 2), proto = d[o + 9], frag = r16(d, o + 6) & 0x1fff;
    p.src = ip4(d, o + 12); p.dst = ip4(d, o + 16); p.ttl = d[o + 8]; p.ipv = 4; p.label = 'IPv4';
    const end = tot >= ihl ? Math.min(d.length, o + tot) : d.length;
    if (tot >= ihl && o + tot > d.length) p.trunc = true;
    l4(p, d, o + ihl, end, proto, frag !== 0, tot >= ihl ? o + tot : end);
  }
  function ipv6(p, d, o) {
    if (o + 40 > d.length) return;
    let nh = d[o + 6]; p.src = ip6(d, o + 8); p.dst = ip6(d, o + 24); p.ttl = d[o + 7]; p.ipv = 6; p.label = 'IPv6';
    const plen = r16(d, o + 4); let q = o + 40; const end = plen ? Math.min(d.length, q + plen) : d.length;
    if (plen && q + plen > d.length) p.trunc = true;
    let guard = 0, frag = false;
    while ([0, 43, 60, 51, 44].includes(nh) && q + 8 <= end && guard++ < 8) {
      const nn = d[q];
      if (nh === 44) { frag = (r16(d, q + 2) >> 3) !== 0; q += 8; }
      else q += nh === 51 ? (d[q + 1] + 2) * 4 : (d[q + 1] + 1) * 8;
      nh = nn;
    }
    l4(p, d, q, end, nh, frag, plen ? o + 40 + plen : end);
  }
  // dend is where the IP header says the packet ends; it differs from end when the capture cut the packet short.
  function l4(p, d, o, end, proto, frag, dend) {
    if (frag) { p.info = 'Fragmento IP'; return; }
    if (proto === 6) {
      p.proto = 'TCP'; p.label = 'TCP';
      if (o + 20 > end) return;
      p.sport = r16(d, o); p.dport = r16(d, o + 2); p.seq = r32(d, o + 4);
      const doff = (d[o + 12] >> 4) * 4; p.flags = d[o + 13];
      p.pl = d.subarray(Math.min(o + doff, end), end);
      if (p.trunc) p.seglen = Math.max(0, dend - (o + doff));
      tcpApp(p);
    } else if (proto === 17) {
      p.proto = 'UDP'; p.label = 'UDP';
      if (o + 8 > end) return;
      p.sport = r16(d, o); p.dport = r16(d, o + 2); p.pl = d.subarray(o + 8, end);
      udpApp(p);
    } else if (proto === 1 || proto === 58) {
      p.proto = proto === 1 ? 'ICMP' : 'ICMPv6'; p.label = p.proto;
      if (o + 4 > end) return;
      p.itype = d[o]; p.icode = d[o + 1]; p.pl = d.subarray(Math.min(o + 8, end), end);
      p.info = icmpInfo(p);
    } else if (proto === 2) { p.proto = p.label = 'IGMP'; p.info = 'IGMP'; }
    else if (proto === 47) { p.proto = p.label = 'GRE'; p.info = 'Túnel GRE'; }
    else if (proto === 50) { p.proto = p.label = 'ESP'; p.info = 'IPsec ESP'; }
    else { p.proto = 'IP/' + proto; p.info = 'Protocolo IP ' + proto; }
  }
  function icmpInfo(p) {
    if (p.proto === 'ICMP') {
      const m = {0:'Echo reply',3:'Destino inalcanzable',5:'Redirect',8:'Echo request (ping)',11:'Tiempo excedido'};
      return (m[p.itype] || ('Tipo ' + p.itype)) + (p.itype === 3 ? ' (código ' + p.icode + ')' : '');
    }
    const m6 = {1:'Destino inalcanzable',128:'Echo request',129:'Echo reply',133:'Router solicitation',134:'Router advertisement',135:'Neighbor solicitation',136:'Neighbor advertisement'};
    return m6[p.itype] || ('ICMPv6 tipo ' + p.itype);
  }
  function arp(p, d, o) {
    p.proto = p.label = 'ARP';
    if (o + 28 > d.length) return;
    const op = r16(d, o + 6);
    p.arpOp = op; p.sha = mac(d, o + 8); p.src = ip4(d, o + 14); p.dst = ip4(d, o + 24);
    p.info = op === 1 ? '¿Quién tiene ' + p.dst + '? Pregunta ' + p.src : op === 2 ? p.src + ' está en ' + p.sha : 'ARP op ' + op;
  }
  function portApp(p) { return PORT_APP[p.dport] || PORT_APP[p.sport] || null; }
  function tcpApp(p) {
    const pl = p.pl, n = pl.length;
    const base = p.sport + ' → ' + p.dport + ' [' + flagStr(p.flags) + ']' + (n ? ' Len=' + n : '');
    if (n === 0) { p.label = p.trunc ? (portApp(p) || 'TCP') : 'TCP'; p.info = base + (p.trunc ? ' (carga no capturada)' : ''); return; }
    if (pl[0] === 0x16 && pl[1] === 3 && n > 5) {
      p.label = 'TLS';
      if (pl[5] === 1) { const sni = parseSNI(pl); if (sni) p.sni = sni; p.info = 'Client Hello' + (sni ? ' (SNI: ' + sni + ')' : ''); }
      else if (pl[5] === 2) p.info = 'Server Hello';
      else p.info = 'Handshake TLS';
      return;
    }
    if ((pl[0] === 0x17 || pl[0] === 0x15 || pl[0] === 0x14) && pl[1] === 3 && pl[2] <= 4) { p.label = 'TLS'; p.info = pl[0] === 0x17 ? 'Datos de aplicación cifrados' : pl[0] === 0x15 ? 'Alerta TLS' : 'Change Cipher Spec'; return; }
    const head = latin(pl, 0, Math.min(n, 8));
    if (HTTP_METHODS.test(head)) { parseHTTP(p); return; }
    if (head.startsWith('HTTP/1.')) { const line = latin(pl, 0, Math.min(n, 120)).split('\r\n')[0]; p.label = 'HTTP'; p.http = {status: line}; p.info = line; return; }
    if (head.startsWith('SSH-')) { p.label = 'SSH'; p.info = 'Banner: ' + latin(pl, 0, Math.min(n, 80)).split(/\r?\n/)[0]; return; }
    if (p.dport === 21 || p.sport === 21) {
      p.label = 'FTP'; const line = latin(pl, 0, Math.min(n, 200)).split(/\r?\n/)[0];
      if (p.dport === 21) { let m; if ((m = line.match(/^USER\s+(.+)/i))) p.ftp = {user: m[1].trim()}; else if ((m = line.match(/^PASS\s*(.*)/i))) p.ftp = {pass: m[1].trim()}; }
      p.info = p.ftp && p.ftp.pass !== undefined ? 'PASS ' + mask(p.ftp.pass) : line.slice(0, 100); return;
    }
    if (p.dport === 53 || p.sport === 53) { parseDNS(p, pl.subarray(2)); if (p.dns) return; }
    p.label = portApp(p) || 'TCP'; p.info = base;
  }
  function udpApp(p) {
    const pl = p.pl;
    if ([53, 5353, 5355].includes(p.dport) || [53, 5353, 5355].includes(p.sport)) { parseDNS(p, pl); if (p.dns) { if (p.dport === 5353 || p.sport === 5353) p.label = 'mDNS'; else if (p.dport === 5355 || p.sport === 5355) p.label = 'LLMNR'; return; } }
    if (p.dport === 443 || p.sport === 443) { p.label = 'QUIC'; p.info = 'QUIC ' + p.sport + ' → ' + p.dport + ' Len=' + pl.length; return; }
    p.label = portApp(p) || 'UDP';
    p.info = p.sport + ' → ' + p.dport + ' Len=' + pl.length;
  }
  function readName(b, o) {
    const labels = []; let jumped = false, next = o, guard = 0;
    while (guard++ < 128) {
      if (o >= b.length) return null;
      const l = b[o];
      if (l === 0) { if (!jumped) next = o + 1; break; }
      if ((l & 0xC0) === 0xC0) { if (o + 1 >= b.length) return null; if (!jumped) next = o + 2; o = ((l & 0x3f) << 8) | b[o + 1]; jumped = true; continue; }
      if (l > 63 || o + 1 + l > b.length) return null;
      labels.push(latin(b, o + 1, o + 1 + l)); o += 1 + l;
    }
    return {name: labels.join('.') || '.', next};
  }
  function parseDNS(p, b) {
    if (b.length < 12) return;
    const fl = r16(b, 2), qd = r16(b, 4), an = r16(b, 6), qr = fl >> 15, rcode = fl & 15;
    if (qd === 0 || qd > 10) return;
    let o = 12; const qs = [];
    for (let i = 0; i < qd && i < 4; i++) { const r = readName(b, o); if (!r) return; o = r.next; if (o + 4 > b.length) return; qs.push({name: r.name, qt: r16(b, o)}); o += 4; }
    const ans = [];
    if (qr) for (let i = 0; i < an && i < 20; i++) {
      const r = readName(b, o); if (!r) break; o = r.next; if (o + 10 > b.length) break;
      const t = r16(b, o), rdl = r16(b, o + 8); o += 10; if (o + rdl > b.length) break;
      if (t === 1 && rdl === 4) ans.push(ip4(b, o)); else if (t === 28 && rdl === 16) ans.push(ip6(b, o)); else if (t === 5) { const c = readName(b, o); if (c) ans.push('CNAME ' + c.name); } else if (t === 16) ans.push('TXT');
      o += rdl;
    }
    p.dns = {id: r16(b, 0), qr, rcode, qs, ans}; p.label = 'DNS';
    const q = qs[0];
    p.info = qr ? 'Respuesta ' + (rcode ? RCODE[rcode] || ('rcode ' + rcode) + ' ' : '') + (QT[q.qt] || q.qt) + ' ' + q.name + (ans.length ? ' → ' + ans.slice(0, 3).join(', ') : '')
      : 'Consulta ' + (QT[q.qt] || q.qt) + ' ' + q.name;
  }
  function parseSNI(pl) {
    try {
      let o = 5; if (pl[o] !== 1) return null; o += 4; o += 2 + 32; if (o >= pl.length) return null;
      o += 1 + pl[o]; o += 2 + r16(pl, o); o += 1 + pl[o];
      const extEnd = Math.min(pl.length, o + 2 + r16(pl, o)); o += 2;
      while (o + 4 <= extEnd) {
        const t = r16(pl, o), l = r16(pl, o + 2); o += 4;
        if (t === 0) { const q = o + 2; if (pl[q] === 0) { const nl = r16(pl, q + 1); return latin(pl, q + 3, q + 3 + nl); } }
        o += l;
      }
    } catch (e) {}
    return null;
  }
  function parseHTTP(p) {
    const txt = latin(p.pl, 0, Math.min(p.pl.length, 6000));
    const sep = txt.indexOf('\r\n\r\n');
    const headPart = sep >= 0 ? txt.slice(0, sep) : txt;
    const lines = headPart.split('\r\n');
    const [method, uri] = lines[0].split(' ');
    const h = {method, uri: uri || '/', host: '', ua: '', auth: '', ctype: '', body: sep >= 0 ? txt.slice(sep + 4, sep + 4 + 600) : ''};
    for (const ln of lines.slice(1)) {
      const i = ln.indexOf(':'); if (i < 0) continue;
      const k = ln.slice(0, i).trim().toLowerCase(), v = ln.slice(i + 1).trim();
      if (k === 'host') h.host = v; else if (k === 'user-agent') h.ua = v; else if (k === 'authorization') h.auth = v; else if (k === 'content-type') h.ctype = v;
    }
    p.http = h; p.label = 'HTTP'; p.info = method + ' ' + (h.host ? h.host : '') + h.uri.slice(0, 140);
  }

  // ---------- Model and accounting ----------
  function newModel() {
    return {count:0, bytes:0, start:Infinity, end:-Infinity, times:[], labels:[], lens:[], pkts:[], pktsTruncated:false, truncated:false, format:'', linktypes:{}, proto:{}, hosts:new Map(), flowMap:new Map(), dns:[], dnsCount:new Map(), nx:new Map(), ipNames:new Map(), http:[], tls:[], sniCount:new Map(), httpHostCount:new Map(), creds:[], ftpUser:new Map(), arp:new Map(), files:[], fileNotes:[], tcpIdx:null,
      acc:{scan:new Map(), sweep:new Map(), brute:new Map(), flood:new Map(), synack:new Map(), beacon:new Map(), sus:new Map(), tun:new Map(), ua:[], web:[], icmpBig:new Map()}};
  }
  function handle(M, ts, lt, d, orig) {
    if (!isFinite(ts)) ts = M.end > -Infinity ? M.end : 0;
    const p = {i: M.count + 1, t: ts, len: orig || d.length, cap: d.length, proto: 'Otro', label: 'Otro', src: '', dst: '', sport: 0, dport: 0, flags: 0, info: '', pl: null};
    M.linktypes[lt] = (M.linktypes[lt] || 0) + 1;
    try { decodeLink(p, lt, d); } catch (e) { p.info = p.info || 'Paquete mal formado'; }
    if (!p.info) p.info = p.proto === 'UDP' || p.proto === 'TCP' ? p.sport + ' → ' + p.dport : (p.label || 'Paquete');
    account(M, p);
  }
  function account(M, p) {
    const ts = p.t, len = p.len;
    M.count++; M.bytes += len; if (ts < M.start) M.start = ts; if (ts > M.end) M.end = ts;
    M.times.push(ts); M.labels.push(p.label); M.lens.push(len);
    const pr = M.proto[p.label] || (M.proto[p.label] = {pkts: 0, bytes: 0}); pr.pkts++; pr.bytes += len;
    if (M.pkts.length < MAX_PKTS) M.pkts.push(p); else M.pktsTruncated = true;
    if (p.proto === 'ARP') {
      if (p.src && p.sha && p.src !== '0.0.0.0') { let s = M.arp.get(p.src); if (!s) { s = {ip: p.src, macs: [], first: ts, conflictT: null, count: 0}; M.arp.set(p.src, s); } if (!s.macs.includes(p.sha)) { s.macs.push(p.sha); if (s.macs.length === 2) s.conflictT = ts; } s.count++; s.last = ts; }
      return;
    }
    if (!p.src) return;
    hostAcc(M, p.src, true, len, p.dst, p.smac); hostAcc(M, p.dst, false, len, p.src, p.dmac);
    if (p.proto === 'TCP' || p.proto === 'UDP' || p.proto === 'ICMP' || p.proto === 'ICMPv6') flowAcc(M, p);
    detAcc(M, p);
  }
  function hostAcc(M, ip, out, len, peer, mc) {
    let h = M.hosts.get(ip);
    if (!h) { h = {ip, pktsOut: 0, pktsIn: 0, bytesOut: 0, bytesIn: 0, peers: new Set(), mac: ''}; M.hosts.set(ip, h); }
    if (out) { h.pktsOut++; h.bytesOut += len; } else { h.pktsIn++; h.bytesIn += len; }
    if (h.peers.size < 5000) h.peers.add(peer);
    if (mc && !h.mac && isInternal(ip)) h.mac = mc;
  }
  function flowAcc(M, p) {
    const k1 = p.proto + '|' + p.src + '|' + p.sport + '|' + p.dst + '|' + p.dport;
    const k2 = p.proto + '|' + p.dst + '|' + p.dport + '|' + p.src + '|' + p.sport;
    let f = M.flowMap.get(k1), dir = 0;
    if (!f) { f = M.flowMap.get(k2); dir = 1; }
    if (!f) { f = {id: M.flowMap.size + 1, proto: p.proto, app: p.label, a: p.src, ap: p.sport, b: p.dst, bp: p.dport, pkts: 0, bytes: 0, ab: 0, ba: 0, first: p.t, last: p.t, syn: 0, synack: 0, rst: 0, fin: 0}; M.flowMap.set(k1, f); dir = 0; }
    p.fid = f.id;
    f.pkts++; f.bytes += p.len; if (dir) f.ba += p.len; else f.ab += p.len; f.last = p.t;
    if (!['TCP', 'UDP'].includes(p.label)) f.app = p.label;
    const fl = p.flags;
    if (p.proto === 'TCP') { if ((fl & 0x12) === 0x02) f.syn++; if ((fl & 0x12) === 0x12) f.synack++; if (fl & 4) f.rst++; if (fl & 1) f.fin++; }
  }
  function getOr(map, k, mk) { let v = map.get(k); if (!v) { v = mk(); map.set(k, v); } return v; }
  function detAcc(M, p) {
    const A = M.acc, f = p.flags, t = p.t;
    if (p.proto === 'TCP') {
      if ((f & 0x12) === 0x02 && !(f & 0x10)) {
        const ks = p.src + '|' + p.dst;
        const s = getOr(A.scan, ks, () => ({src: p.src, dst: p.dst, ports: new Set(), open: new Set(), count: 0, first: t, last: t, lastNew: t}));
        if (s.ports.size < 5000 && !s.ports.has(p.dport)) { s.ports.add(p.dport); s.lastNew = t; } s.count++; s.last = t;
        sweepAdd(A, p.src, p.dst, t, 'tcp');
        if (AUTH_PORTS[p.dport]) { const b = getOr(A.brute, ks + '|' + p.dport, () => ({src: p.src, dst: p.dst, port: p.dport, count: 0, first: t, last: t})); b.count++; b.last = t; }
        const fl = getOr(A.flood, p.dst + '|' + p.dport, () => ({dst: p.dst, port: p.dport, syn: 0, srcs: new Set(), first: t, last: t}));
        fl.syn++; fl.last = t; if (fl.srcs.size < 5000) fl.srcs.add(p.src);
        const bc = getOr(A.beacon, ks + '|' + p.dport, () => ({src: p.src, dst: p.dst, port: p.dport, times: []}));
        if (bc.times.length < 500) bc.times.push(t);
        if (SUS_PORTS[p.dport]) susAdd(A, p, 'tcp');
      } else if ((f & 0x12) === 0x12) {
        A.synack.set(p.src + '|' + p.sport, (A.synack.get(p.src + '|' + p.sport) || 0) + 1);
        const s = A.scan.get(p.dst + '|' + p.src); if (s && s.open.size < 5000) s.open.add(p.sport);
      }
    } else if (p.proto === 'UDP') {
      if (SUS_PORTS[p.dport]) susAdd(A, p, 'udp');
    } else if (p.proto === 'ICMP' && p.itype === 8) {
      sweepAdd(A, p.src, p.dst, t, 'icmp');
      if (p.pl && p.pl.length >= 600) { const ib = getOr(A.icmpBig, p.src + '|' + p.dst, () => ({src: p.src, dst: p.dst, count: 0, max: 0, first: t, last: t})); ib.count++; ib.last = t; ib.max = Math.max(ib.max, p.pl.length); }
    }
    if (p.dns) dnsAcc(M, p);
    if (p.http && p.http.method) httpAcc(M, p);
    if (p.sni) { if (M.tls.length < 20000) M.tls.push({t, src: p.src, dst: p.dst, dport: p.dport, sni: p.sni}); M.sniCount.set(p.sni, (M.sniCount.get(p.sni) || 0) + 1); }
    if (p.ftp) {
      const k = p.src + '|' + p.dst;
      if (p.ftp.user !== undefined) M.ftpUser.set(k, p.ftp.user);
      if (p.ftp.pass !== undefined) M.creds.push({t, proto: 'FTP', src: p.src, dst: p.dst, port: p.dport, user: M.ftpUser.get(k) || '?', secret: mask(p.ftp.pass), where: 'ftp://' + p.dst});
    }
  }
  function sweepAdd(A, src, dst, t, kind) { const s = getOr(A.sweep, src + '|' + kind, () => ({src, kind, dsts: new Set(), first: t, last: t})); if (s.dsts.size < 5000) s.dsts.add(dst); s.last = t; }
  function susAdd(A, p, proto) { const s = getOr(A.sus, p.src + '|' + p.dst + '|' + p.dport + '|' + proto, () => ({src: p.src, dst: p.dst, port: p.dport, proto, count: 0, first: p.t, last: p.t})); s.count++; s.last = p.t; }
  function dnsAcc(M, p) {
    const d = p.dns, q = d.qs[0]; if (!q) return;
    const A = M.acc, name = q.name.toLowerCase();
    if (!d.qr) {
      if (M.dns.length < 50000) M.dns.push({t: p.t, src: p.src, dst: p.dst, name, qt: QT[q.qt] || String(q.qt)});
      M.dnsCount.set(name, (M.dnsCount.get(name) || 0) + 1);
      if (p.label !== 'DNS') return;
      const base = baseDomain(name), sub = name.length > base.length ? name.slice(0, name.length - base.length - 1) : '';
      const tu = getOr(A.tun, base, () => ({base, subs: new Set(), count: 0, maxLabel: 0, longest: '', txt: 0, srcs: new Set(), first: p.t, last: p.t, subLen: 0}));
      tu.count++; tu.last = p.t;
      if (sub) { if (tu.subs.size < 5000) tu.subs.add(sub); tu.subLen += sub.length; }
      for (const lab of name.split('.')) if (lab.length > tu.maxLabel) tu.maxLabel = lab.length;
      if (name.length > tu.longest.length) tu.longest = name;
      if (q.qt === 16 || q.qt === 10 || q.qt === 255) tu.txt++;
      if (tu.srcs.size < 50) tu.srcs.add(p.src);
    } else {
      for (const a of d.ans) if (!a.startsWith('CNAME') && a !== 'TXT') M.ipNames.set(a, name);
      if (d.rcode === 3) { const n = getOr(M.nx, p.dst, () => ({ip: p.dst, count: 0, names: new Set(), first: p.t, last: p.t})); n.count++; n.last = p.t; if (n.names.size < 25) n.names.add(name); }
    }
  }
  function httpAcc(M, p) {
    const h = p.http, A = M.acc;
    const host = h.host || p.dst;
    if (M.http.length < 20000) M.http.push({t: p.t, src: p.src, dst: p.dst, dport: p.dport, method: h.method, host, uri: h.uri, ua: h.ua});
    M.httpHostCount.set(host, (M.httpHostCount.get(host) || 0) + 1);
    if (h.auth && /^basic\s+/i.test(h.auth)) {
      let dec = ''; try { dec = atob(h.auth.replace(/^basic\s+/i, '').trim()); } catch (e) {}
      const i = dec.indexOf(':');
      M.creds.push({t: p.t, proto: 'HTTP Basic', src: p.src, dst: p.dst, port: p.dport, user: i >= 0 ? dec.slice(0, i) : (dec || '?'), secret: mask(i >= 0 ? dec.slice(i + 1) : ''), where: host + h.uri});
    }
    if (h.method === 'POST' && h.body && /(^|&)(pass(word)?|pwd|passwd|clave|contrasena)=/i.test(h.body)) {
      const um = h.body.match(/(?:^|&)(?:user(?:name)?|login|email|usuario)=([^&]*)/i), pm = h.body.match(/(?:^|&)(?:pass(?:word)?|pwd|passwd|clave|contrasena)=([^&]*)/i);
      M.creds.push({t: p.t, proto: 'Formulario HTTP', src: p.src, dst: p.dst, port: p.dport, user: um ? decodeSafe(um[1]) : '?', secret: mask(pm ? decodeSafe(pm[1]) : ''), where: host + h.uri});
    }
    if (h.ua) { const m = h.ua.match(UA_TOOLS); if (m) A.ua.push({t: p.t, src: p.src, dst: p.dst, port: p.dport, ua: h.ua, tool: m[0].toLowerCase()}); }
    const target = decodeSafe(h.uri) + ' ' + decodeSafe(h.body || '');
    for (const w of WEB_PATTERNS) if (w.re.test(target)) A.web.push({t: p.t, src: p.src, dst: p.dst, port: p.dport, uri: h.uri, host, id: w.id, kind: w.kind});
  }

  // ---------- Readers ----------
  async function readPcap(u8, dv, M, magic, onProgress) {
    const le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d, nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    M.format = 'pcap' + (nano ? ' (ns)' : '');
    const lt = dv.getUint32(20, le) & 0x0fffffff;
    let off = 24, n = 0;
    while (off + 16 <= u8.length) {
      const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le), incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
      off += 16;
      if (incl > 1048576 || off + incl > u8.length) { M.truncated = true; break; }
      handle(M, sec + frac / (nano ? 1e9 : 1e6), lt, u8.subarray(off, off + incl), orig);
      off += incl;
      if (++n % 15000 === 0) { if (onProgress) onProgress(off / u8.length, M.count); await tick(); }
    }
  }
  async function readPcapng(u8, dv, M, onProgress) {
    M.format = 'pcapng';
    let off = 0, le = true, n = 0, ifaces = [];
    while (off + 12 <= u8.length) {
      if (dv.getUint32(off, true) === 0x0A0D0D0A) { le = dv.getUint32(off + 8, true) === 0x1A2B3C4D; ifaces = []; }
      const type = dv.getUint32(off, le), blen = dv.getUint32(off + 4, le);
      if (blen < 12 || off + blen > u8.length) { M.truncated = true; break; }
      if (type === 1) {
        const ifc = {lt: dv.getUint16(off + 8, le), res: 1e-6};
        let o = off + 16;
        while (o + 4 <= off + blen - 4) {
          const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && l >= 1) { const v = u8[o + 4]; ifc.res = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); }
          o += 4 + ((l + 3) & ~3);
        }
        ifaces.push(ifc);
      } else if (type === 6 || type === 2) {
        const id = type === 6 ? dv.getUint32(off + 8, le) : dv.getUint16(off + 8, le);
        const hi = dv.getUint32(off + 12, le), lo = dv.getUint32(off + 16, le), cap = dv.getUint32(off + 20, le), orig = dv.getUint32(off + 24, le);
        const ifc = ifaces[id] || {lt: 1, res: 1e-6};
        handle(M, (hi * 4294967296 + lo) * ifc.res, ifc.lt, u8.subarray(off + 28, Math.min(off + 28 + cap, off + blen - 4)), orig);
        if (++n % 15000 === 0) { if (onProgress) onProgress(off / u8.length, M.count); await tick(); }
      } else if (type === 3) {
        const orig = dv.getUint32(off + 8, le), cap = Math.min(orig, blen - 16), ifc = ifaces[0] || {lt: 1};
        handle(M, NaN, ifc.lt, u8.subarray(off + 12, off + 12 + cap), orig);
        n++;
      }
      off += blen;
    }
  }
  async function parse(buf, onProgress) {
    if (buf.byteLength < 24) throw new Error('El archivo es demasiado pequeño para ser una captura.');
    const u8 = new Uint8Array(buf), dv = new DataView(buf), M = newModel();
    const magic = dv.getUint32(0, true);
    if (magic === 0x0A0D0D0A) await readPcapng(u8, dv, M, onProgress);
    else if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic)) await readPcap(u8, dv, M, magic, onProgress);
    else throw new Error('Formato no reconocido. Usa un archivo .pcap o .pcapng (en Wireshark: Archivo > Guardar como).');
    if (M.count === 0) throw new Error('La captura no contiene paquetes legibles.');
    finalize(M);
    if (onProgress) onProgress(1, M.count, 'archivos');
    try { await extractFiles(M); } catch (e) { M.files = []; M.fileNotes = ['No se pudieron extraer los archivos: ' + (e && e.message || e)]; }
    detect(M);
    if (onProgress) onProgress(1, M.count, 'evidencias');
    attachEvidence(M);
    // Hash of the whole file, for the chain of custody in reports.
    if (onProgress) onProgress(1, M.count, 'hash');
    M.fileSize = u8.length; M.fileSha256 = sha256(u8);
    return M;
  }
  // Evidence for reports: example frame numbers (as in Wireshark) and how many packets trigger each suggested rule.
  // It runs while parsing, in the worker, because testing every rule against every packet is the slow part.
  // Only the 60 most severe findings get rule tests; the rest take frames by time and address.
  function attachEvidence(M) {
    const rank = {alta: 0, media: 1, baja: 2};
    M.findings.slice().sort((a, b) => rank[a.sev] - rank[b.sev] || a.t - b.t).forEach((f, k) => {
      const frames = new Set(), tests = [];
      for (const r of f.rules) {
        if (r.startsWith('#')) continue;
        if (k >= 60) { const m = r.match(/sid:(\d+)/); tests.push({text: r, hits: null, sid: m ? +m[1] : undefined}); continue; }
        const t = testRule(r, M); tests.push({text: r, hits: t.hits, sid: t.sid});
        for (const n of t.sample || []) if (frames.size < 12) frames.add(n);
      }
      if (!frames.size) {
        const ips = new Set(f.ips);
        for (const p of M.pkts) { if (p.t > f.tEnd + 0.001) break; if (p.t >= f.t - 0.001 && (ips.has(p.src) || ips.has(p.dst))) { frames.add(p.i); if (frames.size >= 12) break; } }
      }
      f.frames = [...frames].sort((a, b) => a - b); f.ruleTests = tests;
    });
  }
  // Prepares a parsed model to be posted from a Web Worker. Drops what only the parser needs and takes
  // the packets out: they go in later batches, with each payload view replaced by its offset and length
  // in the capture buffer (views cannot be split across messages without copying the buffer each time).
  function forTransfer(M, buf) {
    for (const k of ['times', 'labels', 'lens', 'flowMap', 'acc', 'tcpIdx', 'ftpUser']) delete M[k];
    const pkts = M.pkts; M.pkts = [];
    for (const p of pkts) { if (p.pl) { p.plo = p.pl.byteOffset; p.pll = p.pl.length; } delete p.pl; }
    return {pkts, transfer: [...new Set([buf, ...M.files.map(f => f.data.buffer)])]};
  }
  function addPackets(M, buf, batch) {
    for (const p of batch) { p.pl = p.plo === undefined ? null : new Uint8Array(buf, p.plo, p.pll); delete p.plo; delete p.pll; M.pkts.push(p); }
  }

  // ---------- Finalize ----------
  function finalize(M) {
    M.duration = Math.max(0, M.end - M.start);
    const order = Object.entries(M.proto).sort((a, b) => b[1].pkts - a[1].pkts).map(e => e[0]);
    const top = order.slice(0, 7), topSet = new Set(top), keys = order.length > 7 ? top.concat(['Otros']) : top;
    const nb = M.duration > 0 ? 60 : 1, w = M.duration > 0 ? M.duration / nb : 1;
    const series = {}, bytesSeries = new Float64Array(nb);
    keys.forEach(k => series[k] = new Array(nb).fill(0));
    for (let i = 0; i < M.times.length; i++) {
      const b = Math.min(nb - 1, Math.floor((M.times[i] - M.start) / w));
      series[topSet.has(M.labels[i]) ? M.labels[i] : 'Otros'][b]++;
      bytesSeries[b] += M.lens[i];
    }
    M.timeline = {nb, width: w, keys, series, bytes: Array.from(bytesSeries)};
    M.flows = [...M.flowMap.values()];
    M.flowById = new Map(M.flows.map(f => [f.id, f]));
    for (const f of M.flows) {
      f.svc = f.syn > 0 ? f.bp : (PORT_APP[f.bp] ? f.bp : PORT_APP[f.ap] ? f.ap : Math.min(f.ap, f.bp));
    }
    M.flows.sort((a, b) => b.bytes - a.bytes);
    M.hostList = [...M.hosts.values()].sort((a, b) => (b.bytesIn + b.bytesOut) - (a.bytesIn + a.bytesOut));
    const ports = new Map();
    for (const f of M.flows) {
      if (f.proto !== 'TCP' && f.proto !== 'UDP') continue;
      if (f.proto === 'TCP' && !(f.synack > 0 || (f.syn === 0 && f.pkts > 2))) continue;
      const k = f.proto + '/' + f.svc; const e = getOr(ports, k, () => ({port: f.svc, proto: f.proto, app: PORT_APP[f.svc] || '', flows: 0, bytes: 0}));
      e.flows++; e.bytes += f.bytes;
    }
    M.portList = [...ports.values()].sort((a, b) => b.flows - a.flows);
  }

  // ---------- TCP reassembly ----------
  // Works over M.pkts (the first MAX_PKTS packets). Payloads are views into the capture buffer.
  const EMPTY = new Uint8Array(0);
  const MAX_STREAM = 256 * 1048576, MAX_GAP = 16 * 1048576;
  function tcpIndex(M) {
    if (M.tcpIdx) return M.tcpIdx;
    const idx = new Map();
    for (const p of M.pkts) if (p.fid && p.proto === 'TCP') { let a = idx.get(p.fid); if (!a) { a = []; idx.set(p.fid, a); } a.push(p); }
    return (M.tcpIdx = idx);
  }
  // Splits a flow into connections: the same 4-tuple can be reused, and a SYN with a new ISN starts a new one.
  function tcpConnections(M, fid) {
    const out = []; let cur = null;
    for (const p of tcpIndex(M).get(fid) || []) {
      const syn = (p.flags & 0x12) === 0x02;
      if (!cur || (syn && (cur.isn === null ? cur.data > 0 : cur.isn !== p.seq))) { cur = {pkts: [], isn: null, data: 0}; out.push(cur); }
      if (syn && cur.isn === null) cur.isn = p.seq;
      cur.pkts.push(p); if (p.pl && p.pl.length) cur.data++;
    }
    return out.map((c, k) => ({k, pkts: c.pkts, first: c.pkts[0].t, last: c.pkts[c.pkts.length - 1].t}));
  }
  // One direction of a connection: orders segments by sequence number, drops retransmitted bytes
  // and leaves zeros where bytes are missing (recorded in gaps), so offsets stay true to the stream.
  function tcpSide(list) {
    const d = {bytes: EMPTY, chunks: [], gaps: [], missing: 0, retrans: 0, syn: false, fin: false, rst: false, pkts: list.length, truncated: false};
    let base = null; const segs = [];
    for (const p of list) {
      if ((p.flags & 2) && !d.syn) { d.syn = true; base = (p.seq + 1) >>> 0; }
      if (p.flags & 1) d.fin = true;
      if (p.flags & 4) d.rst = true;
      const len = p.seglen !== undefined ? p.seglen : (p.pl ? p.pl.length : 0);
      if (len > 0) segs.push({p, len, off: 0});
    }
    if (!segs.length) return d;
    const fromData = () => { const s0 = segs[0].p.seq; let min = 0; for (const s of segs) { const r = (s.p.seq - s0) | 0; if (r < min) min = r; } return (s0 + min) >>> 0; };
    if (base === null) base = fromData();
    for (const s of segs) s.off = (s.p.seq - base) | 0;
    if (d.syn && segs.every(s => s.off + s.len <= 0 || s.off > MAX_GAP)) { base = fromData(); for (const s of segs) s.off = (s.p.seq - base) | 0; }
    segs.sort((a, b) => a.off - b.off || a.p.i - b.p.i);
    let end = 0;
    for (let k = 0; k < segs.length; k++) {
      const s = segs[k];
      if (s.off > end + MAX_GAP) { segs.length = k; d.truncated = true; break; }
      if (s.off + s.len > end) end = s.off + s.len;
    }
    if (end > MAX_STREAM) { end = MAX_STREAM; d.truncated = true; }
    const buf = new Uint8Array(end); let next = 0;
    for (const s of segs) {
      const off = s.off, data = s.p.pl || EMPTY;
      if (off >= end) break;
      if (off + s.len <= next) { d.retrans++; continue; }
      if (off > next) { d.gaps.push({off: next, len: off - next, t: s.p.t, i: s.p.i}); d.missing += off - next; next = off; }
      const skip = next - off;
      if (skip > 0) d.retrans++;
      const avail = Math.max(0, Math.min(data.length, end - off) - skip);
      if (avail > 0) { buf.set(data.subarray(skip, skip + avail), next); d.chunks.push({off: next, len: avail, t: s.p.t, i: s.p.i}); }
      const stop = Math.min(off + s.len, end);
      if (next + avail < stop) { d.gaps.push({off: next + avail, len: stop - next - avail, t: s.p.t, i: s.p.i}); d.missing += stop - next - avail; }
      next = stop;
    }
    d.bytes = buf;
    return d;
  }
  function reassemble(pkts) {
    let cli = null;
    for (const p of pkts) {
      if ((p.flags & 0x12) === 0x02) { cli = [p.src, p.sport]; break; }
      if ((p.flags & 0x12) === 0x12) { cli = [p.dst, p.dport]; break; }
    }
    if (!cli) {
      // Started before the capture: the server is usually the side with the well-known or lower port.
      const p = pkts[0], srcIsSrv = PORT_APP[p.sport] ? (!PORT_APP[p.dport] || p.sport < p.dport) : (!PORT_APP[p.dport] && p.sport < p.dport);
      cli = srcIsSrv ? [p.dst, p.dport] : [p.src, p.sport];
    }
    const isCli = p => p.src === cli[0] && p.sport === cli[1];
    const p0 = pkts.find(p => !isCli(p)) || pkts[0];
    const server = isCli(p0) ? {ip: p0.dst, port: p0.dport} : {ip: p0.src, port: p0.sport};
    return {client: {ip: cli[0], port: cli[1]}, server, dirs: [tcpSide(pkts.filter(isCli)), tcpSide(pkts.filter(p => !isCli(p)))]};
  }
  // Interleaves both directions as in Wireshark's "Follow TCP Stream": each piece is placed at the packet
  // that made it deliverable in order (the latest packet up to that offset), so out-of-order data reads right.
  function buildTurns(dirs) {
    const all = [];
    dirs.forEach((d, dir) => {
      const items = d.chunks.map(c => ({off: c.off, len: c.len, t: c.t, i: c.i, gap: false})).concat(d.gaps.map(g => ({off: g.off, len: g.len, t: g.t, i: g.i, gap: true}))).sort((a, b) => a.off - b.off);
      let mi = 0, mt = 0;
      for (const c of items) { if (c.i > mi) { mi = c.i; mt = c.t; } all.push({dir, off: c.off, len: c.len, t: mt, i: mi, gap: c.gap}); }
    });
    all.sort((a, b) => a.i - b.i || a.dir - b.dir || a.off - b.off);
    const turns = [];
    for (const c of all) {
      const l = turns[turns.length - 1];
      if (l && l.dir === c.dir && l.gap === c.gap && l.off + l.len === c.off) l.len += c.len; else turns.push(c);
    }
    return turns;
  }
  function followTcp(M, fid, k) {
    const flow = M.flowById.get(fid);
    if (!flow || flow.proto !== 'TCP') return null;
    const conns = tcpConnections(M, fid);
    if (!conns.length) return {flow, conns: 0};
    const c = conns[Math.max(0, Math.min(conns.length - 1, k | 0))];
    const r = reassemble(c.pkts);
    r.flow = flow; r.conns = conns.length; r.k = c.k; r.first = c.first; r.last = c.last; r.pkts = c.pkts.length; r.firstPkt = c.pkts[0].i;
    r.turns = buildTurns(r.dirs);
    r.files = M.files.filter(f => f.fid === fid && f.conn === c.k);
    return r;
  }
  // Chunk (and so time and packet) that delivered a given stream offset.
  function chunkAt(d, off) {
    const c = d.chunks; if (!c.length) return {t: 0, i: 0};
    let lo = 0, hi = c.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (c[m].off <= off) lo = m; else hi = m - 1; }
    return c[lo];
  }
  const hasGap = (d, s, e) => d.gaps.some(g => g.off < e && g.off + g.len > s) || e > d.bytes.length;
  function printable(b, s = 0, e = b.length) {
    const parts = [];
    for (let i = s; i < e; i += 8192) {
      const n = Math.min(8192, e - i), a = new Array(n); let k = 0;
      for (let j = 0; j < n; j++) { const c = b[i + j]; if (c === 13) continue; a[k++] = c === 10 || c === 9 || (c >= 32 && c < 127) ? c : 46; }
      a.length = k; parts.push(String.fromCharCode.apply(null, a));
    }
    return parts.join('');
  }
  function indexOfSeq(b, nd, from, to) {
    const n = nd.length, last = Math.min(to, b.length) - n;
    for (let i = b.indexOf(nd[0], from); i >= 0 && i <= last; i = b.indexOf(nd[0], i + 1)) {
      let j = 1; while (j < n && b[i + j] === nd[j]) j++;
      if (j === n) return i;
    }
    return -1;
  }
  const bytesOf = s => Uint8Array.from(s, c => c.charCodeAt(0) & 255);
  const CRLF = bytesOf('\r\n'), CRLF2 = bytesOf('\r\n\r\n');
  function concatBytes(parts, total) { const out = new Uint8Array(total); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; }

  // ---------- SHA-256 (pure JS: no WebCrypto, so it also works on http:// outside localhost and in Node) ----------
  const K256 = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  function sha256(u) {
    const H = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]), W = new Int32Array(64);
    function block(m, o) {
      for (let i = 0; i < 16; i++) { const q = o + i * 4; W[i] = (m[q] << 24) | (m[q + 1] << 16) | (m[q + 2] << 8) | m[q + 3]; }
      for (let i = 16; i < 64; i++) {
        const x = W[i - 15], y = W[i - 2];
        W[i] = ((((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) + (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) + W[i - 7] + W[i - 16]) | 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) | 0;
        const t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const n = u.length, full = n - (n % 64);
    for (let o = 0; o < full; o += 64) block(u, o);
    const tail = new Uint8Array(n - full < 56 ? 64 : 128), L = tail.length;
    tail.set(u.subarray(full)); tail[n - full] = 0x80;
    const hi = Math.floor(n / 0x20000000), lo = ((n % 0x20000000) * 8) >>> 0;
    tail[L - 8] = hi >>> 24; tail[L - 7] = (hi >>> 16) & 255; tail[L - 6] = (hi >>> 8) & 255; tail[L - 5] = hi & 255;
    tail[L - 4] = lo >>> 24; tail[L - 3] = (lo >>> 16) & 255; tail[L - 2] = (lo >>> 8) & 255; tail[L - 1] = lo & 255;
    block(tail, 0); if (L === 128) block(tail, 64);
    return Array.from(H, x => (x >>> 0).toString(16).padStart(8, '0')).join('');
  }

  // ---------- File extraction (HTTP, FTP, SMB2) ----------
  // Real type from the first bytes, regardless of the name or the declared Content-Type.
  function fileMagic(b) {
    const n = b.length, s = latin(b, 0, Math.min(n, 16)), m4 = n >= 4 ? r32(b, 0) : 0;
    if (!n) return {label: 'Vacío', kind: 'otro'};
    if (s.startsWith('MZ')) { const pe = n >= 0x40 ? b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) : -1; return {label: pe > 0 && latin(b, pe, pe + 4) === 'PE\0\0' ? 'Ejecutable Windows (PE)' : 'Ejecutable MS-DOS (MZ)', kind: 'exe'}; }
    if (s.startsWith('\x7fELF')) return {label: 'Ejecutable Linux (ELF)', kind: 'exe'};
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m4)) return {label: 'Ejecutable macOS (Mach-O)', kind: 'exe'};
    if (m4 === 0xcafebabe) return {label: 'Mach-O universal o clase Java', kind: 'exe'};
    if (s.startsWith('PK\x03\x04')) {
      const nm = n >= 30 ? latin(b, 30, 30 + (b[26] | (b[27] << 8))) : '';
      if (nm === '[Content_Types].xml' || /^(word|xl|ppt)\//.test(nm)) return {label: 'Documento Office (OOXML)', kind: 'doc'};
      if (nm.startsWith('META-INF/') || nm === 'AndroidManifest.xml' || nm === 'classes.dex') return {label: 'Paquete Java o Android (JAR/APK)', kind: 'exe'};
      return {label: 'Archivo ZIP', kind: 'archivo'};
    }
    if (s.startsWith('%PDF')) return {label: 'Documento PDF', kind: 'doc'};
    if (m4 === 0xd0cf11e0) return {label: 'Documento Office antiguo o MSI (OLE)', kind: 'doc'};
    if (s.startsWith('{\\rtf')) return {label: 'Documento RTF', kind: 'doc'};
    if (s.startsWith('\x89PNG')) return {label: 'Imagen PNG', kind: 'imagen'};
    if (s.startsWith('\xff\xd8\xff')) return {label: 'Imagen JPEG', kind: 'imagen'};
    if (s.startsWith('GIF8')) return {label: 'Imagen GIF', kind: 'imagen'};
    if (s.startsWith('RIFF') && latin(b, 8, 12) === 'WEBP') return {label: 'Imagen WebP', kind: 'imagen'};
    if (s.startsWith('Rar!')) return {label: 'Archivo RAR', kind: 'archivo'};
    if (s.startsWith('7z\xbc\xaf')) return {label: 'Archivo 7-Zip', kind: 'archivo'};
    if (s.startsWith('\x1f\x8b')) return {label: 'Archivo gzip', kind: 'archivo'};
    if (s.startsWith('BZh')) return {label: 'Archivo bzip2', kind: 'archivo'};
    if (s.startsWith('MSCF')) return {label: 'Archivo CAB', kind: 'archivo'};
    if (s.startsWith('#!')) return {label: 'Script (#!)', kind: 'script'};
    const head = latin(b, 0, Math.min(n, 512));
    if (/^\s*<\?xml/i.test(head)) return {label: 'XML', kind: 'texto'};
    if (/^\s*(<!doctype html|<html)/i.test(head)) return {label: 'HTML', kind: 'texto'};
    let bad = 0; const m = Math.min(n, 1024); for (let i = 0; i < m; i++) { const c = b[i]; if (c < 9 || (c > 13 && c < 32) || c === 127) bad++; }
    return bad / m < 0.02 ? {label: /^\s*[{[]/.test(head) ? 'JSON o texto' : 'Texto', kind: 'texto'} : {label: 'Binario desconocido', kind: 'otro'};
  }
  const EXE_EXT = /\.(exe|dll|sys|scr|com|cpl|ocx|drv|efi|msi|bin|elf|so|o|out|run|dylib|jar|apk|class)$/i;
  const MIME_EXT = {'text/html': 'html', 'application/json': 'json', 'text/plain': 'txt', 'application/javascript': 'js', 'text/javascript': 'js', 'text/css': 'css', 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/svg+xml': 'svg', 'image/x-icon': 'ico', 'image/webp': 'webp', 'application/pdf': 'pdf', 'application/xml': 'xml', 'text/xml': 'xml', 'application/zip': 'zip', 'application/octet-stream': 'bin'};
  // Names come from the capture: strip directories, control and reserved characters before using them as file names.
  function safeName(s, fb) {
    s = String(s || '').split(/[\\/]/).pop().replace(/[\x00-\x1f\x7f<>:"|?*]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '');
    if (s.length > 120) { const e = s.match(/\.[a-z0-9]{1,8}$/i); s = s.slice(0, 120 - (e ? e[0].length : 0)) + (e ? e[0] : ''); }
    return s || fb || 'archivo';
  }
  function addFile(out, o) {
    const mg = fileMagic(o.data);
    if (!/\.[a-z0-9]{1,8}$/i.test(o.name) && o.mime && MIME_EXT[o.mime.split(';')[0].trim().toLowerCase()]) o.name += '.' + MIME_EXT[o.mime.split(';')[0].trim().toLowerCase()];
    o.name = safeName(o.name);
    o.size = o.data.length; o.sha256 = sha256(o.data); o.type = mg.label; o.kind = mg.kind;
    o.disguised = mg.kind === 'exe' && /\.[a-z0-9]{1,8}$/i.test(o.name) && !EXE_EXT.test(o.name);
    o.notes = o.notes || [];
    if (o.disguised) o.notes.push('La extensión no corresponde al contenido real (' + mg.label + ').');
    else if (mg.kind === 'exe' && o.mime && !/octet-stream|x-msdownload|x-dosexec|executable|java-archive|android/i.test(o.mime)) o.notes.push('Declarado como ' + o.mime + ', pero el contenido es ' + mg.label + '.');
    out.push(o);
  }

  // HTTP/1.x: requests in the client stream, responses in the server stream, paired in order.
  function dechunk(b, pos) {
    const parts = []; let total = 0;
    while (pos < b.length) {
      const le = indexOfSeq(b, CRLF, pos, pos + 1024); if (le < 0) break;
      const size = parseInt(latin(b, pos, le).split(';')[0].trim(), 16);
      if (!(size >= 0)) break;
      pos = le + 2;
      if (size === 0) {
        const te = b[pos] === 13 && b[pos + 1] === 10 ? pos : indexOfSeq(b, CRLF2, pos - 2, pos + 8192);
        return {body: concatBytes(parts, total), end: te < 0 ? b.length : te === pos ? pos + 2 : te + 4, complete: true};
      }
      const take = Math.min(size, b.length - pos);
      parts.push(b.subarray(pos, pos + take)); total += take;
      if (take < size) return {body: concatBytes(parts, total), end: b.length, complete: false};
      pos += size + 2;
    }
    return {body: concatBytes(parts, total), end: b.length, complete: false};
  }
  function httpMessages(d, isReq, reqs) {
    const b = d.bytes, out = [], START = bytesOf(isReq ? '\n' : 'HTTP/1.');
    let pos = 0, qi = 0;
    while (pos < b.length && out.length < 5000) {
      const he = indexOfSeq(b, CRLF2, pos, pos + 65536);
      const lines = he < 0 ? [] : latin(b, pos, he).split('\r\n'), start = lines[0] || '';
      if (he < 0 || !(isReq ? HTTP_METHODS.test(start) : start.startsWith('HTTP/1.'))) {
        // Lost bytes or an unknown protocol: look for the next message start.
        let nx = indexOfSeq(b, START, pos + 1, b.length);
        if (isReq) while (nx >= 0 && !HTTP_METHODS.test(latin(b, nx + 1, nx + 9))) nx = indexOfSeq(b, START, nx + 1, b.length);
        if (nx < 0) break;
        pos = isReq ? nx + 1 : nx; continue;
      }
      const h = {};
      for (const ln of lines.slice(1)) { const i = ln.indexOf(':'); if (i > 0) h[ln.slice(0, i).trim().toLowerCase()] = ln.slice(i + 1).trim(); }
      const msg = {start, h, off: pos, t: chunkAt(d, pos).t, method: '', uri: '', status: 0, req: null, body: EMPTY, complete: true};
      let bs = he + 4, end = bs;
      if (isReq) { const sp = start.split(' '); msg.method = sp[0]; msg.uri = sp[1] || '/'; }
      else {
        msg.status = parseInt(start.split(' ')[1], 10) || 0;
        if (msg.status >= 100 && msg.status < 200) { pos = bs; continue; }
        msg.req = reqs[qi++] || null;
      }
      const te = (h['transfer-encoding'] || '').toLowerCase(), cl = (h['content-length'] || '').trim();
      if (!isReq && (msg.status === 204 || msg.status === 304 || (msg.req && msg.req.method === 'HEAD'))) end = bs;
      else if (te.includes('chunked')) { const r = dechunk(b, bs); msg.body = r.body; end = r.end; msg.complete = r.complete; }
      else if (/^\d+$/.test(cl)) { end = bs + +cl; if (end > b.length) { msg.complete = false; end = b.length; } msg.body = b.subarray(bs, end); }
      else if (!isReq) { end = b.length; msg.body = b.subarray(bs); msg.complete = d.fin || d.rst; }
      if (hasGap(d, bs, Math.max(bs, end))) msg.complete = false;
      out.push(msg); pos = Math.max(end, pos + 1);
    }
    return out;
  }
  async function inflate(u8, fmt) {
    const ds = new DecompressionStream(fmt), w = ds.writable.getWriter();
    w.write(u8).catch(() => {}); w.close().catch(() => {});
    const rd = ds.readable.getReader(), parts = []; let total = 0;
    for (;;) {
      const {done, value} = await rd.read(); if (done) break;
      parts.push(value); total += value.length;
      if (total > 512 * 1048576) { rd.cancel().catch(() => {}); throw new Error('demasiado grande'); }
    }
    return concatBytes(parts, total);
  }
  async function decodeBody(body, enc) {
    enc = String(enc || '').toLowerCase().trim();
    if (!enc || enc === 'identity' || !body.length) return {data: body};
    if (typeof DecompressionStream === 'undefined' || !/^(x-)?(gzip|deflate)$/.test(enc)) return {data: body, note: 'Codificación "' + enc + '" sin decodificar: el hash corresponde a los datos comprimidos.'};
    for (const fmt of enc.includes('gzip') ? ['gzip'] : ['deflate', 'deflate-raw']) { try { return {data: await inflate(body, fmt)}; } catch (e) {} }
    return {data: body, note: 'No se pudo descomprimir (' + enc + ', quizá incompleto): el hash corresponde a los datos comprimidos.'};
  }
  function multipart(body, ctype) {
    const m = String(ctype).match(/boundary=(?:"([^"]+)"|([^;\s]+))/i); if (!m) return [];
    const bnd = bytesOf('--' + (m[1] || m[2])), parts = [];
    let pos = indexOfSeq(body, bnd, 0, body.length);
    while (pos >= 0 && parts.length < 200) {
      const s = pos + bnd.length;
      if (body[s] === 45 && body[s + 1] === 45) break;
      const he = indexOfSeq(body, CRLF2, s, s + 8192); if (he < 0) break;
      const head = latin(body, s, he), next = indexOfSeq(body, bnd, he + 4, body.length);
      const fn = head.match(/filename\*?=\s*(?:UTF-8'')?"?([^"\r\n;]*)"?/i), ct = head.match(/content-type:\s*([^\r\n]+)/i);
      if (fn && fn[1]) parts.push({name: decodeSafe(fn[1]), data: body.subarray(he + 4, Math.max(he + 4, next < 0 ? body.length : next - 2)), ctype: ct ? ct[1].trim() : ''});
      pos = next;
    }
    return parts;
  }
  async function httpFiles(r, fid, k, out) {
    const reqs = httpMessages(r.dirs[0], true, null), resps = httpMessages(r.dirs[1], false, reqs);
    const C = r.client, Sv = r.server, base = (o, extra) => Object.assign({fid, conn: k, proto: 'HTTP'}, o, extra);
    for (const res of resps) {
      if (!res.body.length) continue;
      const q = res.req, cd = res.h['content-disposition'] || '';
      const cdm = cd.match(/filename\*\s*=\s*[\w-]*'[^']*'([^;]+)/i) || cd.match(/filename\s*=\s*"([^"]*)"/i) || cd.match(/filename\s*=\s*([^;]+)/i);
      const path = q ? q.uri.split(/[?#]/)[0] : '';
      const dec = await decodeBody(res.body, res.h['content-encoding']);
      const notes = dec.note ? [dec.note] : [];
      if (!res.complete) notes.push('Faltan bytes del cuerpo en la captura.');
      addFile(out, base({dir: 'descarga', name: cdm ? decodeSafe(cdm[1].trim()) : decodeSafe(path.split('/').pop()) || 'index', path: (q ? (q.h.host || Sv.ip) + q.uri : Sv.ip + ' (respuesta sin petición)').slice(0, 500),
        mime: res.h['content-type'] || '', src: Sv.ip, sport: Sv.port, dst: C.ip, dport: C.port, t: res.t, complete: res.complete, data: dec.data.slice(), notes}));
    }
    for (const q of reqs) {
      if (!q.body.length) continue;
      const ct = q.h['content-type'] || '', where = (q.h.host || Sv.ip) + q.uri, notes = q.complete ? [] : ['Faltan bytes del cuerpo en la captura.'];
      const up = o => addFile(out, base({dir: 'subida', path: where.slice(0, 500), src: C.ip, sport: C.port, dst: Sv.ip, dport: Sv.port, t: q.t, complete: q.complete, notes: notes.slice()}, o));
      if (/multipart\/form-data/i.test(ct)) { for (const p of multipart(q.body, ct)) up({name: p.name, mime: p.ctype, data: p.data.slice()}); }
      else if (!/x-www-form-urlencoded/i.test(ct)) {
        const dec = await decodeBody(q.body, q.h['content-encoding']);
        up({name: decodeSafe(q.uri.split(/[?#]/)[0].split('/').pop()) || q.method.toLowerCase(), mime: ct, data: dec.data.slice()});
      }
    }
  }

  // FTP: commands and replies on port 21 say which data connection carries each file.
  function ftpTransfers(r) {
    const ev = [], srv = r.server.ip, xs = [];
    r.dirs.forEach((d, dir) => {
      const b = d.bytes; let pos = 0;
      while (pos < b.length && ev.length < 50000) { let e = b.indexOf(10, pos); if (e < 0) e = b.length; const c = chunkAt(d, pos); ev.push({cli: dir === 0, text: latin(b, pos, e).replace(/\r$/, '').trim(), t: c.t, i: c.i}); pos = e + 1; }
    });
    ev.sort((a, b) => a.i - b.i);
    let ep = null, type = 'A', cwd = '', cur = null;
    for (const e of ev) {
      if (e.cli) {
        const m = e.text.match(/^([A-Za-z]{3,4})\s*(.*)$/); if (!m) continue;
        const cmd = m[1].toUpperCase(), arg = m[2].trim();
        if (cmd === 'TYPE') type = arg.toUpperCase().startsWith('A') ? 'A' : 'I';
        else if (cmd === 'CWD') cwd = arg.startsWith('/') ? arg : cwd.replace(/\/$/, '') + '/' + arg;
        else if (cmd === 'PORT') { const n = arg.split(',').map(Number); if (n.length === 6) ep = {ips: [n.slice(0, 4).join('.')], port: n[4] * 256 + n[5], t: e.t}; }
        else if (cmd === 'EPRT') { const p = arg.split(arg[0]); if (p.length >= 4) ep = {ips: [p[2]], port: +p[3], t: e.t}; }
        else if (/^(RETR|STOR|STOU|APPE|LIST|NLST|MLSD)$/.test(cmd)) { cur = {cmd, arg, t: e.t, ep, type, cwd, expect: null, ok: null}; xs.push(cur); ep = null; }
      } else {
        const code = +e.text.slice(0, 3);
        if (code === 227) { const m = e.text.match(/(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/); if (m) ep = {ips: [m.slice(1, 5).join('.'), srv], port: +m[5] * 256 + +m[6], t: e.t}; }
        else if (code === 229) { const m = e.text.match(/\((.)\1\1(\d+)\1\)/); if (m) ep = {ips: [srv], port: +m[2], t: e.t}; }
        else if (cur && (code === 150 || code === 125)) { const m = e.text.match(/\((\d+) bytes\)/i); if (m) cur.expect = +m[1]; }
        else if (cur && (code === 226 || code === 250)) { cur.ok = true; cur = null; }
        else if (cur && code >= 400) { cur.ok = false; cur = null; }
      }
    }
    return xs;
  }
  function ftpFiles(M, r, fid, used, out, notes) {
    const where = 'ftp://' + r.server.ip;
    for (const x of ftpTransfers(r)) {
      const list = /^(LIST|NLST|MLSD)$/.test(x.cmd), what = list ? 'listado de ' + (x.arg || x.cwd || '/') : x.arg;
      if (!x.ep) { if (!list) notes.push('FTP ' + x.cmd + ' ' + x.arg + ' en ' + where + ': no se vio la orden PASV/PORT que indica la conexión de datos.'); continue; }
      const cand = M.flows.filter(f => f.proto === 'TCP' && f.id !== fid && !used.has(f.id) && f.first >= x.ep.t - 1 &&
        ((f.ap === x.ep.port && x.ep.ips.concat(r.client.ip).includes(f.a)) || (f.bp === x.ep.port && x.ep.ips.concat(r.client.ip).includes(f.b)))).sort((a, b) => a.first - b.first);
      const conns = cand.length ? tcpConnections(M, cand[0].id) : [];
      const c = conns.find(c => c.last >= x.ep.t - 1) || conns[0];
      if (!c) { if (!list) notes.push('FTP ' + x.cmd + ' ' + x.arg + ' en ' + where + ': la conexión de datos (puerto ' + x.ep.port + ') no está en la captura.'); continue; }
      used.add(cand[0].id);
      const d = reassemble(c.pkts), dir = d.dirs[1].bytes.length >= d.dirs[0].bytes.length ? 1 : 0, s = d.dirs[dir];
      if (!s.bytes.length) continue;
      const from = dir ? d.server : d.client, to = dir ? d.client : d.server, fileNotes = [];
      const complete = !s.missing && !s.truncated && x.ok !== false && (x.expect === null || x.expect === s.bytes.length);
      if (x.expect !== null && x.expect !== s.bytes.length) fileNotes.push('El servidor anunció ' + x.expect + ' bytes y se reconstruyeron ' + s.bytes.length + '.');
      if (s.missing) fileNotes.push('Faltan ' + s.missing + ' bytes en la captura.');
      if (x.type === 'A' && !list) fileNotes.push('Transferido en modo ASCII (TYPE A): los saltos de línea pueden diferir del original y cambiar el hash.');
      const path = (x.arg.startsWith('/') ? '' : x.cwd.replace(/\/$/, '') + '/') + x.arg;
      addFile(out, {proto: 'FTP', dir: /^(STOR|STOU|APPE)$/.test(x.cmd) ? 'subida' : 'descarga', name: list ? 'listado-' + (x.arg || x.cwd || 'raiz') + '.txt' : x.arg, path: where + (list ? ' ' + what : path.startsWith('/') ? path : '/' + path),
        mime: '', src: from.ip, sport: from.port, dst: to.ip, dport: to.port, t: x.t, fid: cand[0].id, conn: c.k, ctrl: fid, complete, data: s.bytes.slice(0, s.bytes.length), notes: fileNotes});
    }
  }

  // SMB2/3 over TCP 445 (or NetBIOS 139): CREATE gives name and FileId, READ responses and WRITE requests carry the data.
  const le16 = (b, o) => b[o] | (b[o + 1] << 8);
  const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const le64 = (b, o) => le32(b, o) + le32(b, o + 4) * 4294967296;
  const hexId = (b, o) => { let s = ''; for (let i = 0; i < 16; i++) s += hex2(b[o + i] || 0); return s; };
  const utf16 = (b, s, e) => { let out = ''; for (let i = s; i + 1 < Math.min(e, b.length); i += 2) out += String.fromCharCode(le16(b, i)); return out; };
  const SMB2_MAGIC = bytesOf('\xfeSMB'), NO_FID = 'f'.repeat(32);
  function smbFiles(r, fid, k, out, notes) {
    const reqs = new Map(), resps = [], writes = [], trees = new Map(), info = new Map(), createFid = new Map(), segs = new Map();
    let enc = 0, smb1 = 0;
    const walk = (d, isReq) => {
      const b = d.bytes; let pos = 0;
      while (pos + 4 <= b.length) {
        const len = (b[pos + 1] << 16) | (b[pos + 2] << 8) | b[pos + 3];
        if (b[pos] >= 0x81 && b[pos] <= 0x85) { pos += 4 + len; continue; }
        const h = pos + 4;
        if (b[pos] !== 0 || len < 4 || len > 16 * 1048576 || !((b[h] === 0xfe || b[h] === 0xfd || b[h] === 0xff) && b[h + 1] === 0x53 && b[h + 2] === 0x4d && b[h + 3] === 0x42)) {
          const nx = indexOfSeq(b, SMB2_MAGIC, pos + 5, b.length); if (nx < 0) break; pos = nx - 4; continue;
        }
        const end = Math.min(b.length, h + len);
        if (b[h] === 0xfd) enc++; else if (b[h] === 0xff) smb1++; else smb2Chain(d, h, end, isReq);
        pos = end;
      }
    };
    const smb2Chain = (d, h, end, isReq) => {
      const b = d.bytes; let createMid = null;
      for (let guard = 0; h + 64 <= end && guard < 64; guard++) {
        if (b[h] !== 0xfe) break;
        const cmd = le16(b, h + 12), flags = le32(b, h + 16), next = le32(b, h + 20), mid = le32(b, h + 24) + ':' + le32(b, h + 28), body = h + 64, c = chunkAt(d, h);
        if (!(flags & 1)) {
          const q = {cmd, tree: flags & 2 ? null : le32(b, h + 36)};
          if (cmd === 3) q.path = utf16(b, h + le16(b, body + 4), h + le16(b, body + 4) + le16(b, body + 6));
          else if (cmd === 5) { q.name = utf16(b, h + le16(b, body + 44), h + le16(b, body + 44) + le16(b, body + 46)); createMid = mid; }
          else if (cmd === 8) { q.off = le64(b, body + 8); q.fileId = hexId(b, body + 16); if (q.fileId === NO_FID) q.via = createMid; }
          else if (cmd === 9) {
            const doff = h + le16(b, body + 2), dl = le32(b, body + 4), w = {fileId: hexId(b, body + 16), off: le64(b, body + 8), data: b.subarray(doff, Math.min(doff + dl, b.length)), want: dl, gap: hasGap(d, doff, doff + dl), t: c.t};
            if (w.fileId === NO_FID) w.via = createMid;
            writes.push(w);
          }
          reqs.set(mid, q);
        } else resps.push({cmd, mid, status: le32(b, h + 8), tree: le32(b, h + 36), b, h, body, d, t: c.t});
        if (!next) break;
        h += next;
      }
    };
    walk(r.dirs[0], true); walk(r.dirs[1], false);
    const seg = (id, s) => { if (!id) return; let a = segs.get(id); if (!a) { a = []; segs.set(id, a); } a.push(s); };
    for (const s of resps) {
      const q = reqs.get(s.mid); if (!q || s.cmd !== q.cmd || s.status === 0x103) continue;
      const b = s.b, body = s.body;
      if (s.cmd === 3 && s.status === 0) trees.set(s.tree, q.path);
      else if (s.cmd === 5 && s.status === 0) {
        const id = hexId(b, body + 64); createFid.set(s.mid, id);
        info.set(id, {name: q.name, share: trees.get(q.tree) || '', eof: le64(b, body + 48), isDir: !!(le32(b, body + 56) & 0x10)});
      } else if (s.cmd === 8 && (s.status === 0 || s.status === 0x80000005)) {
        const doff = s.h + b[body + 2], dl = le32(b, body + 4);
        seg(q.via ? createFid.get(q.via) : q.fileId, {off: q.off, data: b.subarray(doff, Math.min(doff + dl, b.length)), want: dl, gap: hasGap(s.d, doff, doff + dl), t: s.t, read: true});
      }
    }
    for (const w of writes) seg(w.via ? createFid.get(w.via) : w.fileId, w);
    const conn = r.client.ip + ' ↔ ' + r.server.ip;
    if (enc) notes.push('SMB3 cifrado en ' + conn + ' (' + enc + ' mensajes): sin la clave de sesión no se pueden extraer archivos.');
    if (smb1) notes.push('SMB1 en ' + conn + ' (' + smb1 + ' mensajes): solo se extraen archivos de SMB2/3.');
    for (const [id, list] of segs) {
      const inf = info.get(id) || {name: '', share: '', eof: 0, isDir: false};
      if (inf.isDir || /IPC\$$/i.test(inf.share)) continue;
      const reads = list.some(s => s.read), writesTo = list.some(s => !s.read);
      let size = 0; for (const s of list) size = Math.max(size, s.off + s.data.length);
      if (reads && !writesTo && inf.eof && inf.eof > size) size = inf.eof;
      if (size > 1024 * 1048576) { notes.push('SMB ' + inf.name + ': archivo de ' + fmtBytes(size) + ', demasiado grande para reconstruirlo en el navegador.'); continue; }
      const data = new Uint8Array(size); let cover = 0, holes = false, gaps = false;
      list.sort((a, b) => a.off - b.off || a.t - b.t);
      for (const s of list) { if (s.off > cover) holes = true; data.set(s.data, s.off); cover = Math.max(cover, s.off + s.data.length); if (s.gap || s.data.length < s.want) gaps = true; }
      if (cover < size) holes = true;
      const from = reads ? r.server : r.client, to = reads ? r.client : r.server, fileNotes = [];
      if (holes) fileNotes.push('No se capturaron todas las lecturas o escrituras: hay partes del archivo sin datos (rellenas con ceros).');
      if (gaps) fileNotes.push('Faltan bytes por pérdida de paquetes en la captura.');
      if (reads && writesTo) fileNotes.push('El archivo se leyó y se escribió en la misma sesión; se muestra el resultado combinado.');
      addFile(out, {proto: 'SMB', dir: reads ? 'descarga' : 'subida', name: inf.name || 'smb-' + id.slice(0, 8), path: (inf.share ? inf.share.replace(/\\$/, '') + '\\' : '') + (inf.name || '(nombre no visto, FileId ' + id + ')'),
        mime: '', src: from.ip, sport: from.port, dst: to.ip, dport: to.port, t: list[0].t, fid, conn: k, complete: !holes && !gaps, data, notes: fileNotes});
    }
  }

  async function extractFiles(M) {
    const idx = tcpIndex(M), out = [], notes = [], used = new Set(), ftp = [], smb = [], http = [];
    for (const [fid, pkts] of idx) {
      const p = pkts[0];
      if (p.sport === 21 || p.dport === 21) ftp.push(fid);
      else if ([445, 139].includes(p.sport) || [445, 139].includes(p.dport)) smb.push(fid);
      else if (pkts.some(q => q.http)) http.push(fid);
    }
    for (const fid of ftp) for (const c of tcpConnections(M, fid)) ftpFiles(M, reassemble(c.pkts), fid, used, out, notes);
    for (const fid of smb) for (const c of tcpConnections(M, fid)) smbFiles(reassemble(c.pkts), fid, c.k, out, notes);
    for (let n = 0; n < http.length; n++) {
      const fid = http[n]; if (used.has(fid)) continue;
      for (const c of tcpConnections(M, fid)) await httpFiles(reassemble(c.pkts), fid, c.k, out);
      if (n % 200 === 199) await tick();
    }
    out.sort((a, b) => a.t - b.t);
    out.forEach((f, i) => { f.n = i + 1; f.saveAs = String(i + 1).padStart(3, '0') + '-' + f.name; });
    M.files = out; M.fileNotes = notes;
    if (M.pktsTruncated) notes.push('Solo se reconstruyen flujos de los primeros ' + MAX_PKTS + ' paquetes.');
  }

  // ---------- Snort helpers ----------
  function snortContent(s) {
    let out = '';
    for (const ch of s) { const c = ch.charCodeAt(0); if (ch === '"' || ch === ';' || ch === '\\' || ch === '|' || c < 32 || c > 126) out += '|' + hex2(c & 255).toUpperCase() + '|'; else out += ch; }
    return out.replace(/\|\|/g, ' ');
  }
  function dnsWire(domain) { return domain.split('.').filter(Boolean).map(l => '|' + hex2(l.length).toUpperCase() + '|' + snortContent(l)).join('') + '|00|'; }
  const cleanMsg = s => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[";\\|]/g, '').slice(0, 120);

  // ---------- MITRE ATT&CK and incident phases ----------
  // Enterprise techniques used by the detections: official name and tactic (in Spanish).
  const ATTACK = {
    T1595: ['Active Scanning', 'Reconocimiento'], 'T1595.001': ['Active Scanning: Scanning IP Blocks', 'Reconocimiento'],
    'T1595.002': ['Active Scanning: Vulnerability Scanning', 'Reconocimiento'], 'T1595.003': ['Active Scanning: Wordlist Scanning', 'Reconocimiento'],
    T1046: ['Network Service Discovery', 'Descubrimiento'], T1018: ['Remote System Discovery', 'Descubrimiento'],
    T1190: ['Exploit Public-Facing Application', 'Acceso inicial'], 'T1110.001': ['Brute Force: Password Guessing', 'Acceso a credenciales'],
    T1040: ['Network Sniffing', 'Acceso a credenciales'], 'T1557.002': ['Adversary-in-the-Middle: ARP Cache Poisoning', 'Acceso a credenciales'],
    T1021: ['Remote Services', 'Movimiento lateral'], 'T1059.001': ['Command and Scripting Interpreter: PowerShell', 'Ejecución'],
    'T1036.008': ['Masquerading: Masquerade File Type', 'Evasión de defensas'],
    T1071: ['Application Layer Protocol', 'Comando y control'], 'T1071.001': ['Application Layer Protocol: Web Protocols', 'Comando y control'],
    'T1071.004': ['Application Layer Protocol: DNS', 'Comando y control'], T1095: ['Non-Application Layer Protocol', 'Comando y control'],
    T1105: ['Ingress Tool Transfer', 'Comando y control'], T1571: ['Non-Standard Port', 'Comando y control'],
    'T1568.002': ['Dynamic Resolution: Domain Generation Algorithms', 'Comando y control'],
    T1041: ['Exfiltration Over C2 Channel', 'Exfiltración'], T1048: ['Exfiltration Over Alternative Protocol', 'Exfiltración'],
    'T1498.001': ['Network Denial of Service: Direct Network Flood', 'Impacto']
  };
  const attackUrl = id => 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
  const att = (...ids) => ids.filter(Boolean).map(id => ({id, name: ATTACK[id][0], tactic: ATTACK[id][1], url: attackUrl(id)}));
  function uaAttack(tool) {
    if (tool === 'hydra') return {phase: 'acceso', mitre: att('T1110.001')};
    if (tool === 'metasploit') return {phase: 'acceso', mitre: att('T1190')};
    if (/dirbuster|gobuster/.test(tool)) return {phase: 'reconocimiento', mitre: att('T1595.003')};
    if (UA_HIGH.test(tool)) return {phase: 'reconocimiento', mitre: att('T1595.002')};
    if (tool === 'powershell') return {phase: 'c2', mitre: att('T1059.001', 'T1105')};
    return {phase: 'c2', mitre: att('T1071.001')};
  }
  // Phases of the incident timeline, in kill-chain order. Each finding sets its own phase in detect().
  const PHASES = [
    {id: 'reconocimiento', label: 'Reconocimiento', desc: 'Exploración de la red: qué equipos y servicios hay y qué puntos débiles tienen.'},
    {id: 'acceso', label: 'Acceso', desc: 'Intentos de entrar: explotación de aplicaciones, contraseñas por fuerza bruta, credenciales expuestas o intercepción.'},
    {id: 'c2', label: 'Comando y control', desc: 'Equipos que contactan con un servidor de control o descargan herramientas.'},
    {id: 'exfiltracion', label: 'Exfiltración', desc: 'Datos que salen de la red por canales grandes o encubiertos.'},
    {id: 'impacto', label: 'Impacto', desc: 'Acciones que degradan o interrumpen servicios.'}
  ];
  function incident(M) {
    const F = M.findings.slice().sort((a, b) => a.t - b.t);
    const phases = PHASES.map(ph => {
      const list = F.filter(f => f.phase === ph.id), techs = new Map(), ips = new Map();
      for (const f of list) { for (const m of f.mitre) techs.set(m.id, m); for (const ip of new Set(f.ips)) ips.set(ip, (ips.get(ip) || 0) + 1); }
      return {...ph, findings: list, start: list.length ? list[0].t : null, end: list.length ? Math.max(...list.map(f => f.tEnd)) : null,
        techniques: [...techs.values()], ips: [...ips.entries()].sort((a, b) => b[1] - a[1]).map(e => e[0])};
    });
    // Hosts seen in more than one phase are what ties the stages together (attacker, victim, C2).
    const seen = new Map();
    for (const ph of phases) for (const ip of ph.ips) { if (!seen.has(ip)) seen.set(ip, []); seen.get(ip).push(ph.id); }
    const links = [...seen.entries()].filter(e => e[1].length > 1).map(([ip, ph]) => ({ip, internal: isInternal(ip), name: M.ipNames.get(ip), phases: ph})).sort((a, b) => b.phases.length - a.phases.length);
    const active = phases.filter(p => p.findings.length), order = active.slice().sort((a, b) => a.start - b.start).map(p => p.id);
    return {phases, links, active: active.map(p => p.id), order, inOrder: order.join() === active.map(p => p.id).join(),
      techniques: [...new Map(F.flatMap(f => f.mitre).map(m => [m.id, m])).values()]};
  }

  // ---------- Detection ----------
  function detect(M) {
    const A = M.acc, F = [];
    let sid = 1000001;
    const R = (header, opts) => { const r = header + ' (msg:"' + cleanMsg(opts.msg) + '"; ' + (opts.body ? opts.body + ' ' : '') + 'classtype:' + opts.cls + '; sid:' + (sid++) + '; rev:1;)'; return r; };
    // Indicators of compromise: only external addresses count as IoC; internal ones are affected assets.
    const ipIoc = (ip, role) => isInternal(ip) ? [] : [{type: 'ip', value: ip, role}];
    const add = o => {
      o.id = 'h' + (F.length + 1);
      o.ioc = o.ioc || [];
      o.tEnd = Math.max(o.t, o.tEnd || o.t);
      const ref = 'reference:url,attack.mitre.org/techniques/' + o.mitre[0].id.replace('.', '/') + '/; classtype:';
      o.rules = o.rules.map(r => r.startsWith('#') ? r : r.replace(' classtype:', ' ' + ref));
      F.push(o);
    };
    const dur = s => s < 1 ? (s * 1000).toFixed(0) + ' ms' : s < 120 ? s.toFixed(1) + ' s' : (s / 60).toFixed(1) + ' min';

    // Scans grouped by source
    const scanBySrc = new Map();
    for (const s of A.scan.values()) if (s.ports.size >= 15) getOr(scanBySrc, s.src, () => []).push(s);
    for (const [src, list] of scanBySrc) {
      const total = list.reduce((a, s) => a + s.ports.size, 0), first = Math.min(...list.map(s => s.first)), last = Math.max(...list.map(s => s.lastNew));
      add({ioc: ipIoc(src, 'Origen del escaneo de puertos'), phase: 'reconocimiento', mitre: att('T1046', isInternal(src) ? null : 'T1595'), tEnd: last, sev: total >= 100 ? 'alta' : 'media', cat: 'Reconocimiento', title: 'Escaneo de puertos desde ' + src, t: first, ips: [src, ...list.map(s => s.dst)],
        desc: src + ' envió SYN a ' + total + ' puertos distintos en ' + list.length + ' host(s) durante ' + dur(last - first) + '. Es el patrón típico de un escaneo tipo nmap -sS.',
        evidence: list.slice(0, 6).map(s => s.dst + ': ' + s.ports.size + ' puertos probados' + (s.open.size ? ', abiertos: ' + [...s.open].sort((a, b) => a - b).slice(0, 15).join(', ') : ', ninguno respondió abierto')),
        rules: [R('alert tcp any any -> $HOME_NET any', {msg: 'SONDA Escaneo de puertos TCP SYN', body: 'flags:S; detection_filter:track by_src, count 20, seconds 5;', cls: 'attempted-recon'}),
                R('alert ip ' + src + ' any -> $HOME_NET any', {msg: 'SONDA Trafico desde host que escaneo la red ' + src, cls: 'attempted-recon'})]});
    }
    // Sweeps
    for (const s of A.sweep.values()) {
      if (s.dsts.size < 10) continue;
      const icmp = s.kind === 'icmp';
      add({ioc: ipIoc(s.src, 'Origen del barrido de hosts'), phase: 'reconocimiento', mitre: att('T1018', isInternal(s.src) ? null : 'T1595.001'), tEnd: s.last, sev: 'media', cat: 'Reconocimiento', title: 'Barrido de hosts ' + (icmp ? 'ICMP' : 'TCP') + ' desde ' + s.src, t: s.first, ips: [s.src],
        desc: s.src + ' contactó ' + s.dsts.size + ' direcciones distintas con ' + (icmp ? 'pings (echo request)' : 'paquetes SYN') + ' en ' + dur(s.last - s.first) + ', buscando qué equipos están activos.',
        evidence: ['Destinos (muestra): ' + [...s.dsts].slice(0, 12).join(', ')],
        rules: [icmp ? R('alert icmp any any -> $HOME_NET any', {msg: 'SONDA Barrido ICMP de hosts', body: 'itype:8; detection_filter:track by_src, count 10, seconds 10;', cls: 'attempted-recon'})
                     : R('alert tcp any any -> $HOME_NET any', {msg: 'SONDA Barrido TCP de hosts', body: 'flags:S; detection_filter:track by_src, count 10, seconds 10;', cls: 'attempted-recon'})]});
    }
    // Brute force
    const bruteKeys = new Set();
    for (const b of A.brute.values()) {
      if (b.count < 10) continue;
      bruteKeys.add(b.src + '|' + b.dst + '|' + b.port);
      const svc = AUTH_PORTS[b.port], span = Math.max(1, b.last - b.first);
      add({ioc: ipIoc(b.src, 'Origen de fuerza bruta contra ' + svc), phase: 'acceso', mitre: att('T1110.001'), tEnd: b.last, sev: b.count >= 30 ? 'alta' : 'media', cat: 'Acceso no autorizado', title: 'Posible fuerza bruta ' + svc + ' contra ' + b.dst, t: b.first, ips: [b.src, b.dst],
        desc: b.src + ' abrió ' + b.count + ' conexiones nuevas a ' + svc + ' (' + b.dst + ':' + b.port + ') en ' + dur(span) + ', unas ' + (b.count / span * 60).toFixed(1) + ' por minuto. Muchas conexiones cortas y repetidas al mismo servicio de autenticación indican intentos de contraseñas.',
        evidence: ['Origen ' + b.src + ' → ' + b.dst + ':' + b.port, b.count + ' intentos de conexión (SYN)'],
        rules: [R('alert tcp any any -> ' + b.dst + ' ' + b.port, {msg: 'SONDA Posible fuerza bruta ' + svc, body: 'flags:S; detection_filter:track by_src, count 5, seconds 60;', cls: 'attempted-admin'})]});
    }
    // SYN flood
    for (const fl of A.flood.values()) {
      const sa = A.synack.get(fl.dst + '|' + fl.port) || 0;
      if (fl.syn < 300 || sa / fl.syn > 0.3) continue;
      const span = Math.max(0.001, fl.last - fl.first);
      add({phase: 'impacto', mitre: att('T1498.001'), tEnd: fl.last, sev: 'alta', cat: 'Denegación de servicio', title: 'Posible SYN flood contra ' + fl.dst + ':' + fl.port, t: fl.first, ips: [fl.dst],
        desc: fl.syn + ' SYN en ' + dur(span) + ' desde ' + fl.srcs.size + ' origen(es), con solo ' + sa + ' respuestas SYN-ACK. El servidor no completa las conexiones.',
        evidence: ['Tasa: ' + (fl.syn / span).toFixed(0) + ' SYN/s', 'Orígenes distintos: ' + fl.srcs.size],
        rules: [R('alert tcp any any -> ' + fl.dst + ' ' + fl.port, {msg: 'SONDA Posible SYN flood', body: 'flags:S; detection_filter:track by_dst, count 100, seconds 2;', cls: 'attempted-dos'})]});
    }
    // Suspicious ports
    const susByPort = new Map();
    for (const s of A.sus.values()) getOr(susByPort, s.proto + '/' + s.port, () => []).push(s);
    for (const [k, list] of susByPort) {
      const [proto, port] = k.split('/');
      const n = list.reduce((a, s) => a + s.count, 0);
      add({ioc: list.flatMap(s => ipIoc(s.dst, 'Destino de conexiones al puerto ' + port)).concat([{type: 'puerto', value: port + '/' + proto, role: SUS_PORTS[port]}]), phase: 'c2', mitre: att('T1571'), tEnd: Math.max(...list.map(s => s.last)), sev: ['4444', '31337', '4445', '1337'].includes(port) ? 'alta' : 'media', cat: 'Puerto sospechoso', title: 'Conexiones al puerto ' + port + '/' + proto, t: Math.min(...list.map(s => s.first)), ips: list.flatMap(s => [s.src, s.dst]),
        desc: 'Se vieron ' + n + ' intentos de conexión al puerto ' + port + ', ' + SUS_PORTS[port] + '. Conviene verificar qué proceso usa ese puerto en los equipos implicados.',
        evidence: list.slice(0, 6).map(s => s.src + ' → ' + s.dst + ':' + s.port + ' (' + s.count + ' veces)'),
        rules: [R('alert ' + proto + ' any any -> any ' + port, {msg: 'SONDA Conexion a puerto sospechoso ' + port, body: proto === 'tcp' ? 'flags:S;' : '', cls: 'trojan-activity'})]});
    }
    // Beaconing
    for (const bc of A.beacon.values()) {
      if (bc.times.length < 6 || bruteKeys.has(bc.src + '|' + bc.dst + '|' + bc.port)) continue;
      const ts = bc.times.slice().sort((a, b) => a - b), iv = [];
      for (let i = 1; i < ts.length; i++) iv.push(ts[i] - ts[i - 1]);
      const mean = iv.reduce((a, b) => a + b, 0) / iv.length;
      if (mean < 2) continue;
      const sd = Math.sqrt(iv.reduce((a, b) => a + (b - mean) * (b - mean), 0) / iv.length), cv = sd / mean;
      if (cv > 0.15) continue;
      const ext = !isInternal(bc.dst);
      add({ioc: ipIoc(bc.dst, 'Servidor de C2 (conexiones cada ~' + mean.toFixed(0) + ' s)'), phase: 'c2', mitre: att('T1071', PORT_APP[bc.port] ? null : 'T1571'), tEnd: ts[ts.length - 1], sev: ext ? 'alta' : 'media', cat: 'Comando y control', title: 'Posible beaconing de ' + bc.src + ' a ' + bc.dst + ':' + bc.port, t: ts[0], ips: [bc.src, bc.dst],
        desc: bc.src + ' se conectó ' + ts.length + ' veces a ' + bc.dst + ':' + bc.port + ' cada ~' + mean.toFixed(1) + ' s (variación ' + (cv * 100).toFixed(1) + '%). Las conexiones a intervalos tan regulares son típicas de malware que consulta a su servidor de control.',
        evidence: ['Intervalo medio ' + mean.toFixed(2) + ' s, desviación ' + sd.toFixed(2) + ' s', ext ? 'Destino externo a la red' : 'Destino interno'],
        rules: [R('alert tcp ' + bc.src + ' any -> ' + bc.dst + ' ' + bc.port, {msg: 'SONDA Posible beaconing C2 hacia ' + bc.dst, body: 'flags:S; detection_filter:track by_src, count 3, seconds ' + Math.ceil(mean * 3.5) + ';', cls: 'trojan-activity'})]});
    }
    // DNS tunneling
    for (const tu of A.tun.values()) {
      const avg = tu.subs.size ? tu.subLen / tu.count : 0;
      if (!(tu.maxLabel >= 40 || (tu.subs.size >= 30 && avg >= 20))) continue;
      add({ioc: [{type: 'dominio', value: tu.base, role: 'Dominio usado como túnel DNS'}], phase: 'exfiltracion', mitre: att('T1071.004', 'T1048'), tEnd: tu.last, sev: 'alta', cat: 'Exfiltración', title: 'Posible túnel DNS hacia ' + tu.base, t: tu.first, ips: [...tu.srcs],
        desc: tu.count + ' consultas a ' + tu.base + ' con ' + tu.subs.size + ' subdominios únicos y etiquetas de hasta ' + tu.maxLabel + ' caracteres' + (tu.txt ? ' (' + tu.txt + ' de tipo TXT)' : '') + '. Subdominios largos y aleatorios suelen codificar datos que salen por DNS.',
        evidence: ['Ejemplo: ' + (tu.longest.length > 90 ? tu.longest.slice(0, 90) + '…' : tu.longest), 'Equipos que consultan: ' + [...tu.srcs].slice(0, 6).join(', ')],
        rules: [R('alert udp any any -> any 53', {msg: 'SONDA Consulta DNS al dominio de tunel ' + tu.base, body: 'content:"' + dnsWire(tu.base) + '"; nocase;', cls: 'trojan-activity'}),
                R('alert udp any any -> any 53', {msg: 'SONDA DNS con etiqueta de 40 o mas caracteres', body: 'dsize:>80; pcre:"/[a-z0-9-]{40,}/i";', cls: 'trojan-activity'})]});
    }
    // NXDOMAIN / DGA
    for (const n of M.nx.values()) {
      if (n.count < 15) continue;
      add({ioc: [...n.names].map(d => ({type: 'dominio', value: d, role: 'Posible dominio DGA (no existe)'})), phase: 'c2', mitre: att('T1568.002'), tEnd: n.last, sev: 'media', cat: 'Comando y control', title: 'Muchas respuestas NXDOMAIN para ' + n.ip, t: n.first, ips: [n.ip],
        desc: n.ip + ' recibió ' + n.count + ' respuestas "dominio inexistente". Puede ser un error de configuración, pero también malware con algoritmo de generación de dominios (DGA) buscando su servidor.',
        evidence: ['Dominios (muestra): ' + [...n.names].slice(0, 8).join(', ')],
        rules: [R('alert udp any 53 -> ' + n.ip + ' any', {msg: 'SONDA Respuestas NXDOMAIN repetidas posible DGA', body: 'content:"|81 83|"; offset:2; depth:2; detection_filter:track by_dst, count 10, seconds 60;', cls: 'trojan-activity'})]});
    }
    // Clear-text credentials
    const credBy = new Map();
    for (const c of M.creds) getOr(credBy, c.proto, () => []).push(c);
    for (const [proto, list] of credBy) {
      const rule = proto === 'HTTP Basic' ? R('alert tcp any any -> any $HTTP_PORTS', {msg: 'SONDA Autenticacion HTTP Basic en texto claro', body: 'flow:to_server,established; content:"Authorization|3A| Basic"; nocase;', cls: 'policy-violation'})
        : proto === 'FTP' ? R('alert tcp any any -> any 21', {msg: 'SONDA Contrasena FTP en texto claro', body: 'flow:to_server,established; content:"PASS "; depth:5;', cls: 'policy-violation'})
        : R('alert tcp any any -> any $HTTP_PORTS', {msg: 'SONDA Formulario con contrasena enviado por HTTP', body: 'flow:to_server,established; content:"POST"; depth:4; content:"pass"; nocase; distance:0;', cls: 'policy-violation'});
      add({phase: 'acceso', mitre: att('T1040'), tEnd: list[list.length - 1].t, sev: 'alta', cat: 'Credenciales expuestas', title: 'Credenciales en texto claro (' + proto + ')', t: list[0].t, ips: list.flatMap(c => [c.src, c.dst]),
        desc: 'Se capturaron ' + list.length + ' credencial(es) enviadas sin cifrar por ' + proto + '. Cualquiera en la ruta de red puede leerlas. Las contraseñas se muestran enmascaradas.',
        evidence: list.slice(0, 6).map(c => c.src + ' → ' + c.where + ' usuario "' + c.user + '" contraseña ' + c.secret), rules: [rule]});
    }
    // Telnet
    const telnet = M.flows.filter(f => f.proto === 'TCP' && (f.bp === 23 || f.ap === 23) && f.synack > 0);
    if (telnet.length) add({phase: 'acceso', mitre: att('T1021', 'T1040'), tEnd: Math.max(...telnet.map(f => f.last)), sev: 'media', cat: 'Protocolo inseguro', title: 'Sesiones Telnet sin cifrar', t: telnet[0].first, ips: telnet.flatMap(f => [f.a, f.b]),
      desc: telnet.length + ' sesión(es) Telnet establecidas. Telnet transmite usuario, contraseña y comandos en texto claro; lo recomendable es reemplazarlo por SSH.',
      evidence: telnet.slice(0, 5).map(f => f.a + ' → ' + f.b + ':23, ' + f.pkts + ' paquetes'),
      rules: [R('alert tcp any any -> any 23', {msg: 'SONDA Sesion Telnet en texto claro', body: 'flow:to_server,established;', cls: 'policy-violation'})]});
    // User agents of tools
    const uaBy = new Map();
    for (const u of A.ua) getOr(uaBy, u.tool, () => []).push(u);
    for (const [tool, list] of uaBy) {
      add({ioc: [...new Set(list.map(u => u.ua))].slice(0, 5).map(ua => ({type: 'user-agent', value: ua, role: 'User-Agent de ' + tool})).concat([...new Set(list.map(u => u.src))].flatMap(ip => ipIoc(ip, 'Origen de peticiones con ' + tool))), ...uaAttack(tool), tEnd: list[list.length - 1].t, sev: UA_HIGH.test(tool) ? 'alta' : 'baja', cat: UA_HIGH.test(tool) ? 'Ataque web' : 'Automatización', title: 'User-Agent de herramienta: ' + tool, t: list[0].t, ips: list.flatMap(u => [u.src, u.dst]),
        desc: list.length + ' petición(es) HTTP identificadas como "' + tool + '". ' + (UA_HIGH.test(tool) ? 'Es una herramienta de ataque o auditoría; si nadie autorizó la prueba, trátalo como un ataque.' : 'Es un cliente de línea de comandos o script; normal en servidores, raro en equipos de usuario.'),
        evidence: list.slice(0, 4).map(u => u.src + ' → ' + u.dst + ':' + u.port + ' "' + u.ua.slice(0, 80) + '"'),
        rules: [R('alert tcp any any -> any $HTTP_PORTS', {msg: 'SONDA User-Agent de herramienta ' + tool, body: 'flow:to_server,established; content:"User-Agent|3A|"; nocase; content:"' + snortContent(tool) + '"; nocase; distance:0;', cls: UA_HIGH.test(tool) ? 'web-application-attack' : 'policy-violation'})]});
    }
    // Web attacks
    const webBy = new Map();
    for (const w of A.web) getOr(webBy, w.id, () => []).push(w);
    for (const [id, list] of webBy) {
      const pat = WEB_PATTERNS.find(w => w.id === id);
      const body = 'flow:to_server,established; ' + pat.contents.map((c, i) => 'content:"' + snortContent(c) + '"; nocase;' + (i ? ' distance:0;' : '')).join(' ');
      add({ioc: [...new Set(list.map(w => w.src))].flatMap(ip => ipIoc(ip, 'Origen de ' + pat.kind.charAt(0).toLowerCase() + pat.kind.slice(1))), phase: 'acceso', mitre: att('T1190'), tEnd: list[list.length - 1].t, sev: 'alta', cat: 'Ataque web', title: pat.kind + ' en peticiones HTTP', t: list[0].t, ips: list.flatMap(w => [w.src, w.dst]),
        desc: list.length + ' petición(es) contienen patrones de ' + pat.kind.toLowerCase() + '. Revisa en el servidor si devolvieron errores o datos inesperados.',
        evidence: list.slice(0, 5).map(w => w.src + ' → ' + w.host + ' ' + decodeSafe(w.uri).slice(0, 110)),
        rules: [R('alert tcp any any -> any $HTTP_PORTS', {msg: 'SONDA ' + pat.kind, body, cls: 'web-application-attack'})]});
    }
    // Large outbound transfers (to a C2 destination it is T1041, exfiltration over the C2 channel)
    const c2Ips = new Set(F.filter(f => f.phase === 'c2').flatMap(f => f.ips).filter(ip => !isInternal(ip)));
    for (const f of M.flows) {
      const out = isInternal(f.a) && !isInternal(f.b) ? {src: f.a, dst: f.b, bytes: f.ab, port: f.bp} : isInternal(f.b) && !isInternal(f.a) ? {src: f.b, dst: f.a, bytes: f.ba, port: f.ap} : null;
      if (!out || out.bytes < 5e6) continue;
      add({ioc: ipIoc(out.dst, 'Destino de ' + fmtBytes(out.bytes) + ' salientes'), phase: 'exfiltracion', mitre: att(c2Ips.has(out.dst) ? 'T1041' : 'T1048'), tEnd: f.last, sev: out.bytes >= 5e7 ? 'alta' : 'media', cat: 'Exfiltración', title: 'Transferencia saliente grande hacia ' + out.dst, t: f.first, ips: [out.src, out.dst],
        desc: out.src + ' envió ' + fmtBytes(out.bytes) + ' a ' + out.dst + ':' + out.port + ' en ' + dur(f.last - f.first) + '. Puede ser un backup o subida legítima; confirma que el destino es conocido.',
        evidence: ['Conversación ' + f.proto + ' ' + f.a + ':' + f.ap + ' ↔ ' + f.b + ':' + f.bp, 'Total en la conversación: ' + fmtBytes(f.bytes)],
        rules: [R('alert ip ' + out.src + ' any -> ' + out.dst + ' any', {msg: 'SONDA Trafico hacia destino de transferencia voluminosa ' + out.dst, cls: 'policy-violation'})]});
    }
    // ARP spoofing
    for (const a of M.arp.values()) {
      if (a.macs.length < 2) continue;
      add({ioc: a.macs.slice(1).map(m => ({type: 'mac', value: m, role: 'MAC que suplanta a ' + a.ip})), phase: 'acceso', mitre: att('T1557.002'), tEnd: a.last, sev: 'alta', cat: 'Ataque en red local', title: 'Posible ARP spoofing de ' + a.ip, t: a.conflictT || a.first, ips: [a.ip],
        desc: 'La IP ' + a.ip + ' fue anunciada por ' + a.macs.length + ' direcciones MAC distintas. Si es la puerta de enlace, alguien podría estar interceptando el tráfico (man-in-the-middle).',
        evidence: a.macs.map((m, i) => 'MAC ' + (i + 1) + ': ' + m + (i === 0 ? ' (la primera vista)' : '')),
        rules: ['# ARP no se detecta con reglas: activa el inspector arp_spoof con la pareja IP/MAC legitima.\n' +
                '# Snort 3 (snort.lua): arp_spoof = { hosts = { { ip = \'' + a.ip + '\', mac = \'' + a.macs[0] + '\' } } }\n' +
                '# Snort 2 (snort.conf): preprocessor arpspoof_detect_host: ' + a.ip + ' ' + a.macs[0]]});
    }
    // Big ICMP payloads
    for (const ib of A.icmpBig.values()) {
      if (ib.count < 10) continue;
      add({ioc: ipIoc(ib.dst, 'Destino de pings con carga grande'), phase: 'exfiltracion', mitre: att('T1095', 'T1048'), tEnd: ib.last, sev: 'media', cat: 'Exfiltración', title: 'Pings con carga inusualmente grande', t: ib.first, ips: [ib.src, ib.dst],
        desc: ib.src + ' envió ' + ib.count + ' echo request a ' + ib.dst + ' con hasta ' + ib.max + ' bytes de datos. Un ping normal lleva 32–64 bytes; cargas grandes pueden indicar un túnel ICMP.',
        evidence: [ib.src + ' → ' + ib.dst], rules: [R('alert icmp any any -> any any', {msg: 'SONDA ICMP con carga inusualmente grande', body: 'itype:8; dsize:>600;', cls: 'bad-unknown'})]});
    }
    // Executables transferred in clear text (from the reassembled files)
    const exes = M.files.filter(f => f.kind === 'exe');
    if (exes.length) {
      const disguised = exes.filter(f => f.disguised), ext = exes.some(f => !isInternal(f.src)), protos = [...new Set(exes.map(f => f.proto))].join(', ');
      add({ioc: exes.flatMap(f => [{type: 'sha256', value: f.sha256, role: 'Ejecutable ' + f.name + ' (' + f.type + ')'}].concat(f.proto === 'HTTP' ? [{type: 'url', value: 'http://' + f.path, role: 'Descarga de ' + f.name}] : [], ipIoc(f.src, 'Origen de ' + f.name))), phase: 'c2', mitre: att('T1105', disguised.length ? 'T1036.008' : null), tEnd: exes[exes.length - 1].t, sev: disguised.length || ext ? 'alta' : 'media', cat: 'Malware', title: disguised.length ? 'Ejecutable disfrazado transferido por ' + protos : 'Ejecutables transferidos por ' + protos, t: exes[0].t, ips: exes.flatMap(f => [f.src, f.dst]),
        desc: exes.length + ' archivo(s) ejecutable(s) viajaron sin cifrar' + (ext ? ', alguno desde fuera de la red' : '') + '.' + (disguised.length ? ' ' + disguised.length + ' tiene(n) una extensión que no corresponde a su contenido, una táctica habitual para colar malware.' : '') + ' Busca su SHA-256 en tu antivirus o en un servicio de reputación y ábrelos solo en un entorno aislado.',
        evidence: exes.slice(0, 6).map(f => f.name + ' (' + f.type + ', ' + fmtBytes(f.size) + ') ' + f.src + ' → ' + f.dst + ' por ' + f.proto + ', SHA-256 ' + f.sha256),
        rules: [R('alert tcp any any -> any any', {msg: 'SONDA Ejecutable Windows PE transferido en claro', body: 'flow:established; content:"This program cannot be run in DOS mode"; nocase;', cls: 'trojan-activity'})]});
    }
    const rank = {alta: 0, media: 1, baja: 2};
    F.sort((a, b) => rank[a.sev] - rank[b.sev] || a.t - b.t);
    M.findings = F; M.nextSid = sid;
  }
  function fmtBytes(n) { if (n < 1024) return n + ' B'; const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3); return n.toFixed(n < 10 ? 2 : 1) + ' ' + u[i]; }

  // ---------- Snort rule parsing and testing ----------
  function splitOpts(s) {
    const out = []; let cur = '', q = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\' && i + 1 < s.length) { cur += c + s[++i]; continue; }
      if (c === '"') q = !q;
      if (c === ';' && !q) { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
      cur += c;
    }
    return {opts: out, rest: cur.trim(), unbalanced: q};
  }
  function parseRule(text) {
    const t = text.trim(), errors = [], warnings = [];
    if (!t || t.split('\n').every(l => !l.trim() || l.trim().startsWith('#'))) return {comment: true, errors, warnings};
    if (t.includes('\n') && t.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length > 1) { errors.push('Escribe una sola regla por bloque (hay varias líneas de regla).'); return {errors, warnings}; }
    const body = t.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).join(' ');
    const m = body.match(/^(alert|log|pass|drop|reject|sdrop|block)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\(([\s\S]*)\)\s*$/);
    if (!m) { errors.push('La cabecera debe tener la forma: acción protocolo origen puerto -> destino puerto (opciones;)'); return {errors, warnings}; }
    const r = {action: m[1], proto: m[2].toLowerCase(), src: m[3], sport: m[4], dir: m[5], dst: m[6], dport: m[7], opts: [], errors, warnings};
    if (!['tcp', 'udp', 'icmp', 'ip'].includes(r.proto)) warnings.push('Protocolo "' + r.proto + '": válido en Snort 3, pero la prueba contra la captura solo cubre tcp, udp, icmp e ip.');
    const so = splitOpts(m[8]);
    if (so.unbalanced) errors.push('Hay comillas sin cerrar en las opciones.');
    if (so.rest) errors.push('La última opción debe terminar en ";" (' + so.rest.slice(0, 30) + ').');
    for (const o of so.opts) { const i = o.indexOf(':'); r.opts.push(i < 0 ? {k: o.trim().toLowerCase(), v: ''} : {k: o.slice(0, i).trim().toLowerCase(), v: o.slice(i + 1).trim()}); }
    const get = k => r.opts.find(o => o.k === k);
    if (!get('msg')) errors.push('Falta la opción msg.');
    else if (!/^".*"$/.test(get('msg').v)) errors.push('msg debe ir entre comillas.');
    const sidO = get('sid');
    if (!sidO) errors.push('Falta la opción sid.'); else if (!/^\d+$/.test(sidO.v)) errors.push('sid debe ser un número.'); else { r.sid = +sidO.v; if (r.sid < 1000000) warnings.push('Usa sid de 1000000 en adelante para reglas locales.'); }
    if (!get('rev')) warnings.push('Añade rev:1; para versionar la regla.');
    const msgO = get('msg'); r.msg = msgO ? msgO.v.replace(/^"|"$/g, '') : '';
    for (const o of r.opts) if (o.k === 'content' && !/^!?\s*".*"$/.test(o.v)) errors.push('content debe ir entre comillas: ' + o.v.slice(0, 30));
    return r;
  }
  function contentBytes(v) {
    let neg = false; v = v.trim(); if (v.startsWith('!')) { neg = true; v = v.slice(1).trim(); }
    v = v.replace(/^"|"$/g, '');
    const out = []; let i = 0;
    while (i < v.length) {
      if (v[i] === '|') { const j = v.indexOf('|', i + 1); if (j < 0) break; for (const h of v.slice(i + 1, j).trim().split(/\s+/).join('').match(/../g) || []) out.push(parseInt(h, 16)); i = j + 1; }
      else if (v[i] === '\\' && i + 1 < v.length) { out.push(v.charCodeAt(i + 1)); i += 2; }
      else { out.push(v.charCodeAt(i) & 255); i++; }
    }
    return {bytes: out, neg};
  }
  function ipToNum(ip) { const p = ip.split('.').map(Number); return p.length === 4 && p.every(x => x >= 0 && x <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; }
  function matchAddr(spec, ip) {
    spec = spec.trim();
    if (spec.startsWith('!')) return !matchAddr(spec.slice(1), ip);
    if (spec === 'any') return true;
    if (spec.startsWith('[')) return spec.slice(1, -1).split(',').some(s => matchAddr(s, ip));
    if (spec === '$HOME_NET') return isInternal(ip);
    if (spec.startsWith('$')) return true;
    if (spec.includes('/')) { const [net, bits] = spec.split('/'); const a = ipToNum(net), b = ipToNum(ip); if (a === null || b === null) return false; const m = +bits === 0 ? 0 : (0xffffffff << (32 - +bits)) >>> 0; return ((a & m) >>> 0) === ((b & m) >>> 0); }
    return spec.toLowerCase() === String(ip).toLowerCase();
  }
  const HTTP_PORTS = new Set([80, 81, 311, 591, 593, 901, 1220, 1414, 1830, 2301, 2381, 2809, 3128, 3702, 4343, 5250, 7001, 7145, 7510, 7777, 7779, 8000, 8008, 8014, 8028, 8080, 8088, 8118, 8123, 8180, 8181, 8243, 8280, 8800, 8888, 8899, 9080, 9090, 9091, 9443, 9999, 11371, 55555]);
  function matchPort(spec, port) {
    spec = spec.trim();
    if (spec.startsWith('!')) return !matchPort(spec.slice(1), port);
    if (spec === 'any') return true;
    if (spec.startsWith('[')) return spec.slice(1, -1).split(',').some(s => matchPort(s, port));
    if (spec === '$HTTP_PORTS') return HTTP_PORTS.has(port);
    if (spec.startsWith('$')) return true;
    if (spec.includes(':')) { const [a, b] = spec.split(':'); return port >= (a === '' ? 0 : +a) && port <= (b === '' ? 65535 : +b); }
    return +spec === port;
  }
  function findBytes(hay, nd, from, to, nocase) {
    const n = nd.length; if (!n) return from;
    const lc = c => (nocase && c >= 65 && c <= 90) ? c + 32 : c;
    const ndl = nocase ? nd.map(lc) : nd;
    for (let i = Math.max(0, from); i + n <= Math.min(hay.length, to); i++) {
      let ok = true; for (let j = 0; j < n; j++) { if ((nocase ? lc(hay[i + j]) : hay[i + j]) !== ndl[j]) { ok = false; break; } }
      if (ok) return i;
    }
    return -1;
  }
  function compileRule(r) {
    const checks = [], ignored = [];
    let cur = null, filter = null;
    for (const o of r.opts) {
      switch (o.k) {
        case 'content': cur = {type: 'content', ...contentBytes(o.v), nocase: false}; checks.push(cur); break;
        case 'nocase': if (cur) cur.nocase = true; break;
        case 'depth': case 'offset': case 'distance': case 'within': if (cur) cur[o.k] = parseInt(o.v, 10); break;
        case 'flags': checks.push({type: 'flags', v: o.v.split(',')[0].trim()}); break;
        case 'itype': checks.push({type: 'num', field: 'itype', v: o.v}); break;
        case 'icode': checks.push({type: 'num', field: 'icode', v: o.v}); break;
        case 'dsize': checks.push({type: 'num', field: 'dsize', v: o.v}); break;
        case 'pcre': { const mm = o.v.replace(/^!?\s*"|"$/g, '').match(/^\/(.*)\/([a-zA-Z]*)$/); if (mm) { try { checks.push({type: 'pcre', re: new RegExp(mm[1], mm[2].replace(/[^ism]/g, '')), neg: o.v.trim().startsWith('!')}); } catch (e) { ignored.push('pcre (expresión no compatible con JavaScript)'); } } break; }
        case 'flow': if (/established/.test(o.v)) checks.push({type: 'established'}); break;
        case 'detection_filter': { const tr = o.v.match(/by_(src|dst)/), c = o.v.match(/count\s+(\d+)/), s = o.v.match(/seconds\s+(\d+)/); if (tr && c && s) filter = {by: tr[1], count: +c[1], seconds: +s[1]}; break; }
        case 'msg': case 'sid': case 'rev': case 'classtype': case 'metadata': case 'reference': case 'priority': case 'gid': break;
        default: ignored.push(o.k);
      }
    }
    return {checks, ignored: [...new Set(ignored)], filter};
  }
  function numCheck(spec, val) {
    spec = spec.trim(); let m;
    if ((m = spec.match(/^(\d+)\s*<>\s*(\d+)$/))) return val > +m[1] && val < +m[2];
    if ((m = spec.match(/^>\s*=?\s*(\d+)$/))) return spec.includes('=') ? val >= +m[1] : val > +m[1];
    if ((m = spec.match(/^<\s*=?\s*(\d+)$/))) return spec.includes('=') ? val <= +m[1] : val < +m[1];
    return val === parseInt(spec, 10);
  }
  function flagsCheck(spec, f) {
    let mod = ''; if (/^[+*!]/.test(spec)) { mod = spec[0]; spec = spec.slice(1); } else if (/[+*!]$/.test(spec)) { mod = spec.slice(-1); spec = spec.slice(0, -1); }
    const map = {F: 1, S: 2, R: 4, P: 8, A: 16, U: 32, E: 64, C: 128, '1': 128, '2': 64, '0': 0};
    let want = 0; for (const c of spec.toUpperCase()) want |= map[c] || 0;
    const fl = f & 0x3f, w = want & 0x3f;
    if (mod === '+') return (fl & w) === w;
    if (mod === '*') return (fl & w) !== 0;
    if (mod === '!') return (fl & w) === 0;
    return fl === w;
  }
  function packetMatches(r, c, p, estab) {
    const proto = r.proto;
    if (proto === 'tcp' && p.proto !== 'TCP') return false;
    if (proto === 'udp' && p.proto !== 'UDP') return false;
    if (proto === 'icmp' && p.proto !== 'ICMP') return false;
    if (proto === 'ip' && !p.ipv) return false;
    if (!['tcp', 'udp', 'icmp', 'ip'].includes(proto)) return false;
    const fwd = matchAddr(r.src, p.src) && matchPort(r.sport, p.sport) && matchAddr(r.dst, p.dst) && matchPort(r.dport, p.dport);
    const bwd = r.dir === '<>' && matchAddr(r.src, p.dst) && matchPort(r.sport, p.dport) && matchAddr(r.dst, p.src) && matchPort(r.dport, p.sport);
    if (!fwd && !bwd) return false;
    const pl = p.pl || new Uint8Array(0);
    let last = 0; let txt = null;
    for (const ch of c.checks) {
      if (ch.type === 'content') {
        let from = 0, to = pl.length;
        if (ch.distance !== undefined || ch.within !== undefined) { from = last + (ch.distance || 0); if (ch.within !== undefined) to = from + ch.within; }
        if (ch.offset !== undefined) from = Math.max(from, ch.offset);
        if (ch.depth !== undefined) to = Math.min(to, (ch.offset || 0) + ch.depth);
        const at = findBytes(pl, ch.bytes, from, to, ch.nocase);
        if (ch.neg) { if (at >= 0) return false; } else { if (at < 0) return false; last = at + ch.bytes.length; }
      } else if (ch.type === 'flags') { if (p.proto !== 'TCP' || !flagsCheck(ch.v, p.flags)) return false; }
      else if (ch.type === 'num') { const v = ch.field === 'dsize' ? pl.length : p[ch.field]; if (v === undefined || !numCheck(ch.v, v)) return false; }
      else if (ch.type === 'pcre') { if (txt === null) txt = latin(pl, 0, pl.length); const ok = ch.re.test(txt); if (ok === ch.neg) return false; }
      else if (ch.type === 'established') { if (p.proto === 'TCP' && !estab(p)) return false; }
    }
    return true;
  }
  function testRule(text, M) {
    const r = parseRule(text);
    if (r.comment) return {comment: true, errors: [], warnings: []};
    if (r.errors.length) return {errors: r.errors, warnings: r.warnings, hits: 0, sample: []};
    const c = compileRule(r);
    if (!M) return {errors: [], warnings: r.warnings, ignored: c.ignored, hits: null, sample: [], sid: r.sid, msg: r.msg};
    const estabSet = new Set();
    for (const f of M.flows) if (f.synack > 0 || (f.syn === 0 && f.pkts > 1)) estabSet.add(f.proto + '|' + f.a + '|' + f.ap + '|' + f.b + '|' + f.bp);
    const estab = p => estabSet.has('TCP|' + p.src + '|' + p.sport + '|' + p.dst + '|' + p.dport) || estabSet.has('TCP|' + p.dst + '|' + p.dport + '|' + p.src + '|' + p.sport);
    let hits = 0; const sample = [], win = new Map();
    for (const p of M.pkts) {
      if (!packetMatches(r, c, p, estab)) continue;
      if (c.filter) {
        const key = c.filter.by === 'src' ? p.src : p.dst; let q = win.get(key); if (!q) { q = []; win.set(key, q); }
        q.push(p.t); while (q.length && q[0] < p.t - c.filter.seconds) q.shift();
        if (q.length <= c.filter.count) continue;
      }
      hits++; if (sample.length < 25) sample.push(p.i);
    }
    return {errors: [], warnings: r.warnings, ignored: c.ignored, hits, sample, sid: r.sid, msg: r.msg};
  }

  // ---------- Sample capture generator ----------
  function sampleCapture() {
    const out = [];
    const T0 = Date.UTC(2026, 9, 9, 14, 0, 0) / 1000;
    let rnd = 42; const rand = () => { rnd = (rnd * 1103515245 + 12345) & 0x7fffffff; return rnd / 0x7fffffff; };
    const MACS = {'192.168.10.1': '00:1a:2b:3c:4d:01', '192.168.10.5': '52:54:00:12:34:05', '192.168.10.8': '52:54:00:12:34:08', '192.168.10.23': '3c:22:fb:10:aa:23', '192.168.10.44': '3c:22:fb:10:aa:44'};
    const GW = MACS['192.168.10.1'];
    const macB = s => s.split(':').map(h => parseInt(h, 16));
    const ipB = s => s.split('.').map(Number);
    const txt = s => Array.from(s, ch => ch.charCodeAt(0) & 255);
    const u16 = n => [(n >> 8) & 255, n & 255], u32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    const macOf = ip => MACS[ip] || GW;
    function frame(src, dst, proto, l4b, cap) {
      const ip = [0x45, 0, ...u16(20 + l4b.length), ...u16(Math.floor(rand() * 65535)), 0x40, 0, src.startsWith('192.168') ? 64 : 52, proto, 0, 0, ...ipB(src), ...ipB(dst)];
      const eth = [...macB(macOf(dst)), ...macB(macOf(src)), 0x08, 0x00];
      return eth.concat(ip, l4b);
    }
    const push = (t, bytes, cap) => out.push({t, bytes: cap ? bytes.slice(0, cap) : bytes, orig: bytes.length});
    const tcpSeg = (sp, dp, seq, ack, flags, pl = []) => [...u16(sp), ...u16(dp), ...u32(seq), ...u32(ack), 0x50, flags, ...u16(64240), 0, 0, 0, 0, ...pl];
    const udpSeg = (sp, dp, pl) => [...u16(sp), ...u16(dp), ...u16(8 + pl.length), 0, 0, ...pl];
    const S = 2, SA = 0x12, A = 0x10, PA = 0x18, FA = 0x11, RA = 0x14;
    function tcpConv(t, c, cp, s, sp, msgs, opts = {}) {
      let cs = Math.floor(rand() * 1e9), ss = Math.floor(rand() * 1e9);
      push(t, frame(c, s, 6, tcpSeg(cp, sp, cs, 0, S))); t += 0.0004 + rand() * 0.02;
      push(t, frame(s, c, 6, tcpSeg(sp, cp, ss, cs + 1, SA))); t += 0.0003 + rand() * 0.02;
      push(t, frame(c, s, 6, tcpSeg(cp, sp, cs + 1, ss + 1, A))); cs++; ss++;
      for (const m of msgs) {
        t += m.dt || (0.002 + rand() * 0.05);
        const pl = typeof m.data === 'string' ? txt(m.data) : m.data;
        // Split into MSS-sized segments; "desorden" swaps two of them and retransmits the first.
        const segs = [];
        for (let o = 0; o === 0 || o < pl.length; o += 1460) segs.push({o, d: pl.slice(o, o + 1460)});
        if (m.desorden && segs.length > 2) { [segs[1], segs[2]] = [segs[2], segs[1]]; segs.push(segs[0]); }
        segs.forEach((g, k) => {
          if (k) t += 0.0003;
          if (m.from === 'c') push(t, frame(c, s, 6, tcpSeg(cp, sp, cs + g.o, ss, PA, g.d)), m.cap);
          else push(t, frame(s, c, 6, tcpSeg(sp, cp, ss + g.o, cs, PA, g.d)), m.cap);
        });
        if (m.from === 'c') cs += pl.length; else ss += pl.length;
      }
      if (!opts.noClose) {
        t += 0.01 + rand() * 0.05; push(t, frame(c, s, 6, tcpSeg(cp, sp, cs, ss, FA)));
        t += 0.001; push(t, frame(s, c, 6, tcpSeg(sp, cp, ss, cs + 1, FA)));
        t += 0.001; push(t, frame(c, s, 6, tcpSeg(cp, sp, cs + 1, ss + 1, A)));
      }
      return t;
    }
    const qname = n => n.split('.').flatMap(l => [l.length, ...txt(l)]).concat([0]);
    const dnsQ = (id, name, qt) => [...u16(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(name), ...u16(qt), 0, 1];
    function dnsR(id, name, qt, ips, rcode = 0) {
      const ans = []; for (const ip of ips) ans.push(0xc0, 0x0c, ...u16(1), 0, 1, ...u32(300), 0, 4, ...ipB(ip));
      if (qt === 16 && !rcode) { const tx = txt('ok' + id); ans.push(0xc0, 0x0c, ...u16(16), 0, 1, ...u32(60), ...u16(tx.length + 1), tx.length, ...tx); }
      const an = ips.length + (qt === 16 && !rcode ? 1 : 0);
      return [...u16(id), 0x81, 0x80 | rcode, 0, 1, ...u16(an), 0, 0, 0, 0, ...qname(name), ...u16(qt), 0, 1, ...ans];
    }
    function dnsLookup(t, cli, name, qt, ips, rcode = 0) {
      const id = Math.floor(rand() * 65535), cp = 49152 + Math.floor(rand() * 16000);
      push(t, frame(cli, '192.168.10.1', 17, udpSeg(cp, 53, dnsQ(id, name, qt))));
      push(t + 0.008 + rand() * 0.03, frame('192.168.10.1', cli, 17, udpSeg(53, cp, dnsR(id, name, qt, ips, rcode))));
    }
    function clientHello(sni) {
      const host = txt(sni);
      const ext = [0, 0, ...u16(host.length + 5), ...u16(host.length + 3), 0, ...u16(host.length), ...host];
      const body = [3, 3, ...Array.from({length: 32}, () => Math.floor(rand() * 256)), 0, 0, 2, 0x13, 0x01, 1, 0, ...u16(ext.length), ...ext];
      const hs = [1, 0, ...u16(body.length), ...body];
      return [0x16, 3, 1, ...u16(hs.length), ...hs];
    }
    const appData = n => [0x17, 3, 3, ...u16(n), ...Array.from({length: n}, () => Math.floor(rand() * 256))];
    const WS = '192.168.10.23', SRV = '192.168.10.5', FTPS = '192.168.10.8', INF = '192.168.10.44', EVIL = '203.0.113.66', C2 = '198.51.100.77';
    const sites = [['www.google.com', '142.250.184.196'], ['github.com', '140.82.121.4'], ['login.microsoftonline.com', '20.190.159.0'], ['slack.com', '3.94.12.80'], ['es.wikipedia.org', '185.15.58.224'], ['outlook.office365.com', '52.97.146.162']];
    // background browsing
    for (let t = 1; t < 590; t += 5 + rand() * 35) {
      const [name, ip] = sites[Math.floor(rand() * sites.length)];
      const cli = rand() < 0.75 ? WS : INF;
      dnsLookup(t, cli, name, 1, [ip]);
      tcpConv(t + 0.05, cli, 50000 + Math.floor(rand() * 15000), ip, 443, [{from: 'c', data: clientHello(name)}, {from: 's', data: appData(1200)}, {from: 's', data: appData(1400)}, {from: 'c', data: appData(300)}, {from: 's', data: appData(900 + Math.floor(rand() * 500))}]);
    }
    dnsLookup(28, WS, 'example.com', 1, ['93.184.216.34']);
    tcpConv(28.1, WS, 51522, '93.184.216.34', 80, [{from: 'c', data: 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0\r\nAccept: text/html\r\n\r\n'}, {from: 's', data: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\n\r\n<html><body>Example Domain</body></html>'}]);
    // ICMP sweep
    const alive = new Set([1, 5, 8, 23, 44]);
    for (let h = 1; h <= 40; h++) {
      const t = 60 + h * 0.9, dst = '192.168.10.' + h, pl = [0, 0, 0, 0, ...u16(1), ...u16(h), ...txt('abcdefghijklmnopqrstuvwabcdefghi')];
      push(t, frame(EVIL, dst, 1, [8, 0, ...pl]));
      if (alive.has(h)) push(t + 0.002, frame(dst, EVIL, 1, [0, 0, ...pl]));
    }
    // Port scan
    const ports = []; for (let p = 1; p <= 230; p++) ports.push(p); ports.push(443, 445, 3306, 3389, 5432, 8080, 8443);
    ports.forEach((p, i) => {
      const t = 110 + i * 0.11, sp = 40000 + i;
      push(t, frame(EVIL, SRV, 6, tcpSeg(sp, p, 1000 + i, 0, S)));
      if (p === 22 || p === 80) { push(t + 0.001, frame(SRV, EVIL, 6, tcpSeg(p, sp, 5000, 1001 + i, SA))); push(t + 0.002, frame(EVIL, SRV, 6, tcpSeg(sp, p, 1001 + i, 0, 4))); }
      else push(t + 0.001, frame(SRV, EVIL, 6, tcpSeg(p, sp, 0, 1001 + i, RA)));
    });
    // SSH brute force
    let tb = 150;
    for (let i = 0; i < 42; i++) {
      tcpConv(tb, EVIL, 52000 + i * 3, SRV, 22, [{from: 's', data: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'}, {from: 'c', data: 'SSH-2.0-libssh2_1.10.0\r\n'}, {from: 'c', data: Array.from({length: 600}, () => Math.floor(rand() * 256))}, {from: 's', data: Array.from({length: 900}, () => Math.floor(rand() * 256))}, {from: 'c', data: Array.from({length: 120}, () => Math.floor(rand() * 256))}, {from: 's', data: Array.from({length: 60}, () => Math.floor(rand() * 256))}]);
      tb += 2 + rand() * 2;
    }
    // Web attacks with sqlmap
    const attacks = ['/products.php?id=1%20UNION%20ALL%20SELECT%20username,password,3%20FROM%20users--', "/login.php?user=admin'%20OR%20'1'='1", '/download.php?file=../../../../etc/passwd'];
    attacks.forEach((u, i) => tcpConv(285 + i * 1.5, EVIL, 53100 + i, SRV, 80, [{from: 'c', data: 'GET ' + u + ' HTTP/1.1\r\nHost: intranet.empresa.local\r\nUser-Agent: sqlmap/1.8.2#stable (https://sqlmap.org)\r\nAccept: */*\r\n\r\n'}, {from: 's', data: 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n'}]));
    // HTTP basic auth
    tcpConv(300, WS, 51800, SRV, 80, [{from: 'c', data: 'GET /admin/ HTTP/1.1\r\nHost: intranet.empresa.local\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0\r\n\r\n'}, {from: 's', data: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 32\r\n\r\n<h1>Panel de administracion</h1>'}]);
    // FTP (the messages with a fixed dt do not consume rand(), so the rest of the capture stays the same)
    const pseudo = (n, seed) => { const a = []; for (let i = 0; i < n; i++) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; a.push(seed >> 16 & 255); } return a; };
    const XLSX = [0x50, 0x4b, 3, 4, 20, 0, 6, 0, 8, 0, 0, 0, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, ...txt('[Content_Types].xml'), ...pseudo(9200, 7)];
    tcpConv(320, WS, 51900, FTPS, 21, [{from: 's', data: '220 (vsFTPd 3.0.5)\r\n'}, {from: 'c', data: 'USER ftpuser\r\n'}, {from: 's', data: '331 Please specify the password.\r\n'}, {from: 'c', data: 'PASS Invierno2026!\r\n'}, {from: 's', data: '230 Login successful.\r\n'},
      {from: 'c', data: 'TYPE I\r\n', dt: 0.01}, {from: 's', data: '200 Switching to Binary mode.\r\n', dt: 0.002}, {from: 'c', data: 'PASV\r\n', dt: 0.01}, {from: 's', data: '227 Entering Passive Mode (192,168,10,8,195,149).\r\n', dt: 0.002},
      {from: 'c', data: 'RETR nominas_octubre.xlsx\r\n'}, {from: 's', data: '150 Opening BINARY mode data connection for nominas_octubre.xlsx (' + XLSX.length + ' bytes).\r\n'}, {from: 's', data: '226 Transfer complete.\r\n', dt: 0.6}]);
    // Beaconing to C2 on 4444
    for (let i = 0; i < 12; i++) tcpConv(5 + i * 30 + (rand() - 0.5) * 0.6, INF, 55000 + i, C2, 4444, [{from: 'c', data: 'BCN|' + INF + '|' + i}, {from: 's', data: 'NOP'}]);
    // DNS tunnel
    const b32 = 'abcdefghijklmnopqrstuvwxyz234567';
    for (let i = 0; i < 60; i++) {
      let lab = ''; for (let k = 0; k < 52; k++) lab += b32[Math.floor(rand() * 32)];
      dnsLookup(380 + i * 1.0 + rand() * 0.3, INF, lab + '.' + i + '.d.exfil-cdn.net', 16, []);
    }
    // DGA NXDOMAIN
    for (let i = 0; i < 22; i++) {
      let lab = ''; for (let k = 0; k < 12; k++) lab += b32[Math.floor(rand() * 26)];
      dnsLookup(450 + i * 0.8, INF, lab + (i % 2 ? '.com' : '.net'), 1, [], 3);
    }
    // Large upload (headers only captured)
    let tu = 480; let seq = 1;
    tcpConv(tu, INF, 56010, C2, 443, [{from: 'c', data: clientHello('cdn-update-sync.net')}], {noClose: true});
    for (let i = 0; i < 4200; i++) { tu += 0.012 + rand() * 0.004; push(tu, frame(INF, C2, 6, tcpSeg(56010, 443, seq, 1, A, appData(1395))), 66); seq += 1400; if (i % 20 === 0) push(tu + 0.001, frame(C2, INF, 6, tcpSeg(443, 56010, 1, seq, A))); }
    // ARP: legit and spoofed gateway
    const arpPkt = (op, sha, spa, tha, tpa) => [...macB(op === 1 ? 'ff:ff:ff:ff:ff:ff' : tha), ...macB(sha), 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, op, ...macB(sha), ...ipB(spa), ...macB(tha), ...ipB(tpa)];
    push(2, arpPkt(1, MACS[WS], WS, '00:00:00:00:00:00', '192.168.10.1'));
    push(2.001, arpPkt(2, GW, '192.168.10.1', MACS[WS], WS));
    for (let i = 0; i < 6; i++) push(550 + i * 2, arpPkt(2, 'de:ad:be:ef:13:37', '192.168.10.1', MACS[WS], WS));
    // FTP passive data connection for the RETR above
    tcpConv(320.45, WS, 51901, FTPS, 50069, [{from: 's', data: XLSX, dt: 0.001}]);
    // Executable disguised as a PDF, downloaded with PowerShell, plus a chunked reply on the same connection
    const pe = pseudo(6144, 99);
    for (let i = 0; i < 0x40; i++) pe[i] = 0;
    pe[0] = 0x4d; pe[1] = 0x5a; pe[2] = 0x90; pe[0x3c] = 0x80;
    txt('This program cannot be run in DOS mode.\r\r\n$').forEach((v, i) => pe[0x4e + i] = v);
    [0x50, 0x45, 0, 0, 0x4c, 0x01].forEach((v, i) => pe[0x80 + i] = v);
    const ps = 'User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; es-ES) WindowsPowerShell/5.1.19041.4648\r\n';
    const chunk = s => s.length.toString(16) + '\r\n' + s + '\r\n';
    tcpConv(512, INF, 56200, C2, 80, [
      {from: 'c', data: 'GET /assets/factura.pdf HTTP/1.1\r\nHost: cdn-update-sync.net\r\n' + ps + 'Connection: Keep-Alive\r\n\r\n'},
      {from: 's', data: [...txt('HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: ' + pe.length + '\r\n\r\n'), ...pe], desorden: true},
      {from: 'c', data: 'GET /api/config?id=44 HTTP/1.1\r\nHost: cdn-update-sync.net\r\n' + ps + '\r\n'},
      {from: 's', data: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n' + chunk('{"intervalo":30,"jitter":0.1,') + chunk('"tareas":["inventario","subir"]}') + '0\r\n\r\n'}]);
    // SMB2: reads a PDF from a share and writes a text file
    const L16 = n => [n & 255, (n >> 8) & 255], L32 = n => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255], L64 = n => [...L32(n >>> 0), ...L32(Math.floor(n / 4294967296))];
    const w16 = s => Array.from(s).flatMap(ch => L16(ch.charCodeAt(0)));
    const zeros = n => new Array(n).fill(0);
    function smb2(cmd, mid, resp, body) {
      const m = [0xfe, 0x53, 0x4d, 0x42, ...L16(64), 0, 0, ...L32(0), ...L16(cmd), ...L16(1), ...L32(resp ? 1 : 0), ...L32(0), ...L64(mid), ...L32(0), ...L32(cmd === 3 && !resp ? 0 : 5), ...L64(0x4400000011), ...zeros(16), ...body];
      return [0, (m.length >> 16) & 255, (m.length >> 8) & 255, m.length & 255, ...m];
    }
    const fidB = n => [...L64(n), ...L64(0xa000 + n)];
    const create = (name, disp) => { const nm = w16(name); return [...L16(57), 0, 0, ...L32(2), ...zeros(16), ...L32(0x12019f), ...L32(0x80), ...L32(7), ...L32(disp), ...L32(0x40), ...L16(120), ...L16(nm.length), ...L32(0), ...L32(0), ...nm]; };
    const created = (n, size) => [...L16(89), 0, 0, ...L32(1), ...zeros(32), ...L64(size), ...L64(size), ...L32(0x20), ...L32(0), ...fidB(n), ...L32(0), ...L32(0)];
    const read = (n, off, len) => [...L16(49), 0x50, 0, ...L32(len), ...L64(off), ...fidB(n), ...zeros(12), ...L16(0), ...L16(0), 0];
    const readResp = data => [...L16(17), 0x50, 0, ...L32(data.length), ...L32(0), ...L32(0), ...data];
    const close = n => [...L16(24), ...L16(0), ...L32(0), ...fidB(n)];
    let pdf = '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
    for (let i = 1; pdf.length < 7000; i++) pdf += 'BT /F1 11 Tf 72 ' + (760 - (i % 60) * 12) + ' Td (Clausula ' + i + ': condiciones del contrato de servicios 2026) Tj ET\n';
    pdf += '%%EOF\n';
    const PDF = txt(pdf), NOTE = txt('Pendiente: revisar contratos firmados y enviar copia a direccion antes del viernes.\r\n');
    const share = '\\\\192.168.10.5\\compartido', path = w16(share);
    tcpConv(345, WS, 51950, SRV, 445, [
      {from: 'c', data: smb2(3, 2, false, [...L16(9), 0, 0, ...L16(72), ...L16(path.length), ...path])},
      {from: 's', data: smb2(3, 2, true, [...L16(16), 1, 0, ...L32(0), ...L32(0), ...L32(0x1f01ff)])},
      {from: 'c', data: smb2(5, 3, false, create('contratos\\contrato_2026.pdf', 1))},
      {from: 's', data: smb2(5, 3, true, created(1, PDF.length))},
      {from: 'c', data: smb2(8, 4, false, read(1, 0, 4096))},
      {from: 's', data: smb2(8, 4, true, readResp(PDF.slice(0, 4096)))},
      {from: 'c', data: smb2(8, 5, false, read(1, 4096, 4096))},
      {from: 's', data: smb2(8, 5, true, readResp(PDF.slice(4096)))},
      {from: 'c', data: smb2(6, 6, false, close(1))},
      {from: 's', data: smb2(6, 6, true, [...L16(60), ...zeros(58)])},
      {from: 'c', data: smb2(5, 7, false, create('notas.txt', 2))},
      {from: 's', data: smb2(5, 7, true, created(2, 0))},
      {from: 'c', data: smb2(9, 8, false, [...L16(49), ...L16(112), ...L32(NOTE.length), ...L64(0), ...fidB(2), ...zeros(8), ...L16(0), ...L16(0), ...L32(0), ...NOTE])},
      {from: 's', data: smb2(9, 8, true, [...L16(17), ...L16(0), ...L32(NOTE.length), ...L32(0), ...L16(0), ...L16(0)])},
      {from: 'c', data: smb2(6, 9, false, close(2))},
      {from: 's', data: smb2(6, 9, true, [...L16(60), ...zeros(58)])}]);
    out.sort((a, b) => a.t - b.t);
    let size = 24; for (const p of out) size += 16 + p.bytes.length;
    const buf = new ArrayBuffer(size), dv = new DataView(buf), u8 = new Uint8Array(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
    let off = 24;
    for (const p of out) {
      const ts = T0 + p.t, sec = Math.floor(ts), us = Math.round((ts - sec) * 1e6) % 1000000;
      dv.setUint32(off, sec, true); dv.setUint32(off + 4, us, true); dv.setUint32(off + 8, p.bytes.length, true); dv.setUint32(off + 12, p.orig, true);
      u8.set(p.bytes, off + 16); off += 16 + p.bytes.length;
    }
    return buf;
  }

  // ---------- Summaries for the agent ----------
  function summary(M, fileName) {
    const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({nombre: k, veces: v}));
    const sev = {alta: 0, media: 0, baja: 0}; M.findings.forEach(f => sev[f.sev]++);
    return {
      archivo: fileName, formato: M.format, paquetes: M.count, bytes: M.bytes, volumen: fmtBytes(M.bytes),
      inicio: new Date(M.start * 1000).toISOString(), fin: new Date(M.end * 1000).toISOString(), duracion_seg: +M.duration.toFixed(2),
      captura_truncada: M.truncated, paquetes_almacenados_para_consulta: M.pkts.length,
      protocolos: Object.entries(M.proto).sort((a, b) => b[1].pkts - a[1].pkts).slice(0, 12).map(([k, v]) => ({protocolo: k, paquetes: v.pkts, bytes: v.bytes})),
      hosts_principales: M.hostList.slice(0, 10).map(h => ({ip: h.ip, interno: isInternal(h.ip), enviado: fmtBytes(h.bytesOut), recibido: fmtBytes(h.bytesIn), contactos: h.peers.size, nombre_dns: M.ipNames.get(h.ip) || undefined})),
      puertos_servicio: M.portList.slice(0, 10).map(p => ({puerto: p.proto + '/' + p.port, servicio: p.app || undefined, conversaciones: p.flows, bytes: p.bytes})),
      dominios_dns: top(M.dnsCount, 10), sni_tls: top(M.sniCount, 8), hosts_http: top(M.httpHostCount, 8),
      conversaciones: M.flows.length, hosts: M.hosts.size,
      archivos_extraidos: {total: M.files.length, ejecutables: M.files.filter(f => f.kind === 'exe').length, por_protocolo: M.files.reduce((a, f) => (a[f.proto] = (a[f.proto] || 0) + 1, a), {})},
      hallazgos: {total: M.findings.length, ...sev, lista: M.findings.map(f => f.sev + ': ' + f.title + ' [' + f.mitre.map(m => m.id).join(', ') + ']')},
      fases_del_incidente: incident(M).phases.filter(p => p.findings.length).map(p => ({fase: p.label, hallazgos: p.findings.length, desde_t: +(p.start - M.start).toFixed(1), hasta_t: +(p.end - M.start).toFixed(1)}))
    };
  }

  return {parse, forTransfer, addPackets, sampleCapture, summary, incident, PHASES, ATTACK, attackUrl, parseRule, testRule, followTcp, tcpConnections, printable, sha256, fmtBytes, flagStr, isInternal, QT, PORT_APP, MAX_PKTS};
})();
if (typeof module !== 'undefined') module.exports = Engine;
