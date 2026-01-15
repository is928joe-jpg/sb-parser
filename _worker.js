/**
 * sb-parser (Cloudflare Worker - Robust Version)
 * 
 * Update Log:
 * - [Fix] Rewrote SimpleYAML parser to strictly handle nested Inline Flow Style (e.g., - { ... { ... } }).
 * - [Fix] Improved comma splitting logic to respect quotes and nested brackets depth.
 * - [Fix] Added compatibility for unquoted strings in YAML values.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/parse') {
      const targetUrl = url.searchParams.get('url');
      const allowLan = url.searchParams.get('lan') === 'true';

      if (!targetUrl) {
        return new Response(JSON.stringify({ error: "Missing 'url' parameter" }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      try {
        const outbounds = await parseContent(targetUrl, allowLan);
        return new Response(JSON.stringify({ 
          outbounds: outbounds,
          _metadata: { count: outbounds.length, generated_at: new Date().toISOString() }
        }, null, 2), {
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
          }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
    }

    return new Response(`
      <!DOCTYPE html>
      <body style="font-family: system-ui; max-width: 800px; margin: 2rem auto; padding: 1rem;">
        <h1>🚀 sb-parser (Robust)</h1>
        <p>Worker Standalone Version with fixed YAML parser.</p>
        <pre style="background:#f4f4f4;padding:1rem;">/parse?url=SUBSCRIPTION_LINK</pre>
      </body>
    `, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};

// ============================================================
// 1. Core Logic
// ============================================================

async function parseContent(input, allowLan) {
  let content = input;

  // 1. Download
  if (input.startsWith('http://') || input.startsWith('https://')) {
    if (!allowLan && isLanIP(new URL(input).hostname)) throw new Error("LAN access denied");
    
    const resp = await fetch(input, {
      headers: { 'User-Agent': 'Mozilla/5.0 (sb-parser/worker)' },
      redirect: 'follow'
    });
    if (!resp.ok) throw new Error(`Fetch error: ${resp.status}`);
    content = await resp.text();
  }

  content = content.trim();
  if (!content) throw new Error("Empty content");

  // 2. Base64 Decode
  if (!content.includes('proxies:') && !content.startsWith('{') && !content.startsWith('[') && !content.includes('://')) {
    try { content = safeBase64Decode(content); } catch (e) {}
  }

  const nodes = [];

  // 3. Sing-box JSON
  if (content.startsWith('{') || content.startsWith('[')) {
    try {
      const json = JSON.parse(content);
      const list = Array.isArray(json) ? json : (json.outbounds || [json]);
      list.forEach(r => { const n = sanitizeNode(r); if(n) nodes.push(n); });
      if(nodes.length > 0) return nodes;
    } catch(e) {}
  }

  // 4. Clash YAML (Using Robust Simple Parser)
  if (content.includes('proxies:')) {
    try {
      const proxies = SimpleYAML.parseProxies(content);
      if (proxies && proxies.length > 0) {
        proxies.forEach(p => {
          try {
            const n = parseClashProxy(p);
            if (n) {
               const san = sanitizeNode(n);
               if(san) nodes.push(san);
            }
          } catch(err) {}
        });
        if (nodes.length > 0) return nodes;
      }
    } catch (e) {
      console.warn("YAML parse error:", e);
    }
  }

  // 5. URI List
  const lines = content.split(/\r?\n/);
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    try {
      let node = null;
      if (line.startsWith('ss://')) node = parseSS(line);
      else if (line.startsWith('vmess://')) node = parseVMess(line);
      else if (line.startsWith('vless://')) node = parseVLESS(line);
      else if (line.startsWith('trojan://')) node = parseTrojan(line);
      else if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) node = parseHysteria2(line);
      else if (line.startsWith('hysteria://')) node = parseHysteria1(line);
      else if (line.startsWith('tuic://')) node = parseTuic(line);
      else if (line.startsWith('anytls://')) node = parseAnyTLS(line);
      
      if (node) {
        const sanitized = sanitizeNode(node);
        if (sanitized) nodes.push(sanitized);
      }
    } catch(e) {}
  }

  if (nodes.length === 0) throw new Error("No valid nodes found");
  return nodes;
}

// ============================================================
// 2. Built-in Robust YAML Parser (State Machine Based)
// ============================================================
const SimpleYAML = {
  parseProxies(content) {
    const lines = content.split(/\r?\n/);
    const proxies = [];
    let inProxies = false;
    let currentProxy = null;

    for (let line of lines) {
      const commentIdx = line.indexOf('#');
      if (commentIdx !== -1) line = line.substring(0, commentIdx);
      const trimmed = line.trim();
      if (!trimmed) continue;

      if (trimmed === 'proxies:') {
        inProxies = true;
        continue;
      }

      if (inProxies) {
        const currentIndent = line.search(/\S/);
        // Exit block check
        if (currentIndent === 0 && !trimmed.startsWith('-')) break;

        if (trimmed.startsWith('-')) {
          if (currentProxy) proxies.push(currentProxy);
          
          const contentAfterDash = trimmed.substring(1).trim();
          
          if (contentAfterDash.startsWith('{')) {
             // Inline Flow Style: - { name: ... }
             currentProxy = this.parseInlineObject(contentAfterDash);
          } else {
             // Block Style start: - name: ...
             currentProxy = {};
             if (contentAfterDash) this.parseLine(contentAfterDash, currentProxy);
          }
        } else {
          // Inside a block property
          if (currentProxy) {
             this.parseLine(trimmed, currentProxy);
          }
        }
      }
    }
    if (currentProxy && Object.keys(currentProxy).length > 0) proxies.push(currentProxy);
    return proxies;
  },

  // Parse a single "key: value" line
  parseLine(str, obj) {
    const idx = str.indexOf(':');
    if (idx !== -1) {
      let key = str.substring(0, idx).trim();
      let val = str.substring(idx + 1).trim();
      // Remove quotes from key
      if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.substring(1, key.length - 1);
      }
      obj[key] = this.parseValue(val);
    }
  },

  // Recursive parser for values (String, Number, Bool, Object, Array)
  parseValue(val) {
    if (!val) return val;
    val = val.trim();
    
    // 1. Quoted String
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      return val.substring(1, val.length - 1);
    }
    // 2. Object { ... }
    if (val.startsWith('{')) return this.parseInlineObject(val);
    // 3. Array [ ... ]
    if (val.startsWith('[')) return this.parseInlineArray(val);
    
    // 4. Boolean / Number
    if (val === 'true') return true;
    if (val === 'false') return false;
    // Check if it's a pure number (no spaces inside)
    if (!isNaN(Number(val)) && val !== '' && !val.includes(' ')) return Number(val);
    
    return val;
  },

  // State machine to parse "{ k:v, k2:v2 }" robustly
  parseInlineObject(str) {
    str = str.trim();
    if (str.startsWith('{') && str.endsWith('}')) str = str.slice(1, -1);
    
    const obj = {};
    const parts = this.splitByComma(str);
    
    for (const part of parts) {
      this.parseLine(part, obj);
    }
    return obj;
  },

  // Parse "[ a, b, c ]"
  parseInlineArray(str) {
    str = str.trim();
    if (str.startsWith('[') && str.endsWith(']')) str = str.slice(1, -1);
    
    const arr = [];
    const parts = this.splitByComma(str);
    for (const part of parts) {
      arr.push(this.parseValue(part));
    }
    return arr;
  },

  // Robust splitter that respects quotes and brackets
  splitByComma(str) {
    const parts = [];
    let buffer = '';
    let depth = 0; // {} []
    let inQuote = false;
    let quoteChar = '';
    
    for (let i = 0; i < str.length; i++) {
        const c = str[i];
        
        // Handle Quotes
        if ((c === '"' || c === "'") && (i === 0 || str[i-1] !== '\\')) {
            if (!inQuote) {
                inQuote = true;
                quoteChar = c;
            } else if (c === quoteChar) {
                inQuote = false;
            }
        }
        
        // Handle Brackets (only if not in quote)
        if (!inQuote) {
            if (c === '{' || c === '[') depth++;
            if (c === '}' || c === ']') depth--;
            
            // Split condition
            if (c === ',' && depth === 0) {
                if (buffer.trim()) parts.push(buffer.trim());
                buffer = '';
                continue;
            }
        }
        buffer += c;
    }
    if (buffer.trim()) parts.push(buffer.trim());
    return parts;
  }
};

// ============================================================
// 3. Protocol Parsers
// ============================================================

function parseSS(uri) {
  let raw = uri.substring(5);
  const hashIdx = raw.indexOf('#');
  let tag = "";
  if (hashIdx !== -1) {
    tag = decodeURIComponent(raw.substring(hashIdx + 1));
    raw = raw.substring(0, hashIdx);
  }
  const qIdx = raw.indexOf('?');
  let queryStr = "";
  if (qIdx !== -1) {
    queryStr = raw.substring(qIdx + 1);
    raw = raw.substring(0, qIdx);
  }

  let method, password, server, port;
  if (raw.includes('@')) {
    const lastAt = raw.lastIndexOf('@');
    const userInfo = raw.substring(0, lastAt);
    const address = raw.substring(lastAt + 1);
    let decodedUser = userInfo;
    if (!userInfo.includes(':')) {
      try { decodedUser = safeBase64Decode(userInfo); } catch(e){}
    }
    const parts = decodedUser.split(':');
    method = parts[0];
    password = parts.slice(1).join(':');
    const addr = splitHostPort(address);
    server = addr.host;
    port = addr.port;
  } else {
    try {
        const decoded = safeBase64Decode(raw);
        const lastAt = decoded.lastIndexOf('@');
        const userInfo = decoded.substring(0, lastAt);
        const address = decoded.substring(lastAt + 1);
        const parts = userInfo.split(':');
        method = parts[0];
        password = parts.slice(1).join(':');
        const addr = splitHostPort(address);
        server = addr.host;
        port = addr.port;
    } catch(e) { throw new Error("Invalid SS"); }
  }

  const node = { type: 'shadowsocks', tag: tag || `SS-${server}:${port}`, server, server_port: port, method, password };

  if (queryStr) {
    let pluginVal = "";
    const params = queryStr.split('&');
    for (const param of params) {
        const eqIdx = param.indexOf('=');
        if (eqIdx !== -1) {
            const k = param.substring(0, eqIdx);
            try {
                if (decodeURIComponent(k) === 'plugin') {
                    pluginVal = decodeURIComponent(param.substring(eqIdx + 1));
                    break;
                }
            } catch(e){}
        }
    }
    if (pluginVal) {
       const scIdx = pluginVal.indexOf(';');
       if (scIdx !== -1) {
           node.plugin = pluginVal.substring(0, scIdx);
           node.plugin_opts = pluginVal.substring(scIdx + 1);
       } else {
           node.plugin = pluginVal;
       }
    }
  }
  return node;
}

function parseVMess(uri) {
  const v = JSON.parse(safeBase64Decode(uri.substring(8)));
  const node = {
    type: 'vmess', tag: v.ps || `VMess-${v.add}`, server: v.add, server_port: parseInt(v.port),
    uuid: v.id, security: v.scy || 'auto', alter_id: parseInt(v.aid || 0), packet_encoding: 'xudp'
  };
  const trans = buildTransport(v.net, v.type, v.path, v.host, "");
  if (trans) node.transport = trans;
  if (v.tls === 'tls') {
    node.tls = buildTLS(v.sni || v.host, null, v.fp, true);
    if (node.transport && node.transport.type === 'ws') node.tls.record_fragment = true;
  }
  return node;
}

function parseVLESS(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'vless', tag: fragment || `VLESS-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    uuid: u.username, flow: q.get('flow'), packet_encoding: 'xudp'
  };
  const security = q.get('security');
  node.transport = buildTransport(q.get('type'), q.get('headerType'), q.get('path'), q.get('host'), q.get('serviceName'));
  if (node.transport && node.transport.type === 'ws') node.packet_encoding = undefined;

  if (security === 'reality') {
    node.tls = {
      enabled: true, server_name: q.get('sni') || q.get('peer'),
      utls: { enabled: true, fingerprint: q.get('fp') || 'chrome' },
      reality: { enabled: true, public_key: q.get('pbk'), short_id: q.get('sid') }
    };
  } else if (security === 'tls' || security === 'xtls') {
    node.tls = buildTLS(q.get('sni') || q.get('peer') || u.hostname, null, q.get('fp'), true);
    if (node.transport && node.transport.type === 'ws') node.tls.record_fragment = true;
  }
  return node;
}

function parseTrojan(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'trojan', tag: fragment || `Trojan-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port), password: u.username
  };
  node.transport = buildTransport(q.get('type'), null, q.get('path'), q.get('host'), q.get('serviceName'));
  node.tls = buildTLS(q.get('sni') || q.get('peer') || u.hostname, q.get('alpn') ? q.get('alpn').split(',') : undefined, q.get('fp'), q.get('allowInsecure') === '1');
  if (node.transport && node.transport.type === 'ws') node.tls.record_fragment = true;
  return node;
}

function parseHysteria2(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  let auth = u.username; if(u.password) auth = u.password;
  const node = {
    type: 'hysteria2', tag: fragment || `Hy2-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    password: auth, up_mbps: 100, down_mbps: 100
  };
  if(q.get('obfs') && q.get('obfs')!=='none') node.obfs = { type: q.get('obfs'), password: q.get('obfs-password') };
  node.tls = buildTLS(q.get('sni')||u.hostname, q.get('alpn')?q.get('alpn').split(','):undefined, null, q.get('insecure')==='1');
  return node;
}

function parseHysteria1(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'hysteria', tag: fragment || `Hysteria-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    auth_str: q.get('auth') || u.username,
    up_mbps: parseInt(q.get('up') || q.get('up_mbps') || 100), 
    down_mbps: parseInt(q.get('down') || q.get('down_mbps') || 100),
    disable_mtu_discovery: true
  };
  const sni = q.get('sni') || q.get('peer') || u.hostname;
  const alpn = q.get('alpn') ? q.get('alpn').split(',') : ['h3'];
  node.tls = buildTLS(sni, alpn, null, q.get('insecure')==='1');
  return node;
}

function parseTuic(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'tuic', tag: fragment || `Tuic-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    uuid: u.username, password: u.password, congestion_control: 'bbr', zero_rtt_handshake: true
  };
  node.tls = buildTLS(q.get('sni')||u.hostname, q.get('alpn')?q.get('alpn').split(','):['h3'], null, false);
  return node;
}

function parseAnyTLS(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  let pwd = u.username;
  if (u.password) pwd = u.password;
  const node = {
    type: 'anytls', tag: fragment || `AnyTLS-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    password: pwd
  };
  const sni = q.get('sni') || u.hostname;
  node.tls = buildTLS(sni, null, null, false);
  return node;
}

function parseClashProxy(p) {
    if (!p || typeof p !== 'object') return null;
    const type = (p.type || "").toLowerCase();
    const node = { tag: p.name, server: p.server, server_port: Number(p.port), type };
    
    if (['ss', 'shadowsocks'].includes(type)) {
        node.type = 'shadowsocks'; node.method = p.cipher; node.password = p.password;
        if (p.plugin) {
            node.plugin = p.plugin;
            // Fix: handle plugin-opts being an object (Inline Flow) or raw string
            if (p['plugin-opts']) {
                if (typeof p['plugin-opts'] === 'object') {
                    node.plugin_opts = Object.entries(p['plugin-opts']).map(([k,v])=>`${k}=${v}`).join(';');
                } else {
                    node.plugin_opts = String(p['plugin-opts']);
                }
            }
        }
    } else if (type === 'vmess') {
        node.uuid = p.uuid; node.security = p.cipher || 'auto'; node.alter_id = p.alterId || 0; node.packet_encoding = 'xudp';
        const net = p.network || 'tcp'; 
        const opts = p[`${net}-opts`] || {};
        node.transport = buildTransport(net, null, opts.path, opts.headers?.Host, opts['grpc-service-name']);
        if (p.tls) {
            node.tls = buildTLS(p.servername || p.server, p.alpn, p['client-fingerprint'], p['skip-cert-verify']);
            if (net === 'ws') node.tls.record_fragment = true;
        }
    } else if (type === 'vless') {
        node.uuid = p.uuid; node.flow = p.flow; node.packet_encoding = 'xudp';
        const net = p.network || 'tcp'; const opts = p[`${net}-opts`] || {};
        node.transport = buildTransport(net, null, opts.path, opts.headers?.Host, opts['grpc-service-name']);
        if (p.tls) {
            const sni = p.servername || p.server;
            if (p['reality-opts']) {
                 const ro = p['reality-opts'];
                 node.tls = { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: p['client-fingerprint'] || 'chrome' }, reality: { enabled: true, public_key: ro['public-key'], short_id: ro['short-id'] } };
            } else {
                 node.tls = buildTLS(sni, p.alpn, p['client-fingerprint'], p['skip-cert-verify']);
                 if(net==='ws') node.tls.record_fragment = true;
            }
        }
        if(net==='ws') node.packet_encoding = undefined;
    } else if (type === 'hysteria2') {
        node.type = 'hysteria2'; node.password = p.password; node.up_mbps = p.up || 100; node.down_mbps = p.down || 100;
        if(p.obfs) node.obfs = { type: p.obfs, password: p['obfs-password'] };
        node.tls = buildTLS(p.sni || p.server, p.alpn, p['client-fingerprint'], p['skip-cert-verify']);
    } else if (type === 'hysteria') {
        node.type = 'hysteria'; 
        node.auth_str = p['auth-str'] || p.auth_str; 
        node.up_mbps = p.up || p.up_mbps || 100; 
        node.down_mbps = p.down || p.down_mbps || 100;
        node.disable_mtu_discovery = false;
        node.tls = buildTLS(p.sni || p.server, p.alpn, p['client-fingerprint'], p['skip-cert-verify']);
    } else if (type === 'tuic') {
        node.type = 'tuic'; 
        node.uuid = p.uuid; 
        node.password = p.password || p.token;
        node.congestion_control = 'bbr'; 
        node.zero_rtt_handshake = true;
        const alpn = p.alpn && p.alpn.length > 0 ? p.alpn : ['h3'];
        node.tls = buildTLS(p.sni || p.server, alpn, p['client-fingerprint'], p['skip-cert-verify']);
    } else if (type === 'anytls') {
        node.type = 'anytls'; 
        node.password = p.password;
        node.tls = buildTLS(p.sni || p.server, null, null, p['skip-cert-verify']);
    } else if (type === 'trojan') {
        node.type = 'trojan'; node.password = p.password;
        const net = p.network || 'tcp'; const opts = p[`${net}-opts`] || {};
        node.transport = buildTransport(net, null, opts.path, opts.headers?.Host, opts['grpc-service-name']);
        node.tls = buildTLS(p.sni || p.server, p.alpn, p['client-fingerprint'], p['skip-cert-verify']);
        if (net === 'ws') node.tls.record_fragment = true;
    }
    
    return ['shadowsocks','vmess','vless','trojan','hysteria2','hysteria','tuic','anytls'].includes(node.type) ? node : null;
}

// ============================================================
// 4. Utils
// ============================================================

function buildTransport(type, tQuery, path, host, svc) {
  let t = (type || tQuery || 'tcp').toLowerCase();
  if (['tcp','udp','xhttp'].includes(t)) return undefined;
  const trans = {};
  if (t === 'ws' || t === 'websocket') { trans.type = 'ws'; trans.path = path || '/'; if(host) trans.headers = { Host: host }; }
  else if (t === 'grpc') { trans.type = 'grpc'; trans.service_name = svc || path; }
  else if (t === 'http' || t === 'h2') { trans.type = 'http'; trans.path = path; if(host) trans.host = [host]; }
  else if (t === 'httpupgrade') { trans.type = 'httpupgrade'; trans.path = path; if(host) trans.headers = { Host: host }; }
  return trans;
}

function buildTLS(sni, alpn, fp, ins) {
  return { enabled: true, server_name: sni, insecure: !!ins, alpn: alpn, utls: fp ? { enabled: true, fingerprint: fp } : undefined };
}

function sanitizeNode(node) {
  if (!node) return null;
  const m = {
      'ss':'shadowsocks','vmess':'vmess','vless':'vless','trojan':'trojan',
      'hysteria2':'hysteria2','hy2':'hysteria2','hysteria':'hysteria','tuic':'tuic',
      'anytls':'anytls', 'shadowtls':'shadowtls', 'shadowtls-v3':'shadowtls-v3'
  };
  let type = (node.type || '').toLowerCase();
  if (!m[type] && type !== 'shadowsocks') return null;
  node.type = m[type];
  if (!node.tag) node.tag = `${node.type}-${node.server}`;
  if (!node.transport) delete node.transport;
  if (!node.tls) delete node.tls;
  if (node.transport && node.transport.type === 'ws' && node.tls) {
      node.tls.record_fragment = true;
      if (!node.tls.utls) node.tls.utls = { enabled: true, fingerprint: 'chrome' };
  }
  Object.keys(node).forEach(k => (node[k] === undefined || node[k] === null || node[k] === "") && delete node[k]);
  return node;
}

function parseUrlObj(uri) {
  try { const u = new URL(uri); return { u, q: u.searchParams, fragment: decodeURIComponent(u.hash.substring(1)) }; } 
  catch(e) { throw new Error("Invalid URI"); }
}

function splitHostPort(s) {
    const idx = s.lastIndexOf(':');
    if (idx === -1) return { host: s, port: 80 };
    if (s.includes(']') && idx > s.lastIndexOf(']')) return { host: s.substring(0, idx), port: parseInt(s.substring(idx+1)) };
    return { host: s.substring(0, idx), port: parseInt(s.substring(idx+1)) };
}

function safeBase64Decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try { return atob(str); } catch(e) { return atob(str.substring(0, str.length - 1) + '='); } // simple fix padding
}

function isLanIP(h) {
    if (h === 'localhost') return true;
    const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
        const p = m.slice(1).map(Number);
        if (p[0] === 127 || p[0] === 10) return true;
        if (p[0] === 192 && p[1] === 168) return true;
        if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
        if (p[0] === 0) return true;
    }
    return h === '::1';
}