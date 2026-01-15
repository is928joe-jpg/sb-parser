/**
 * sb-parser (Cloudflare Worker - Ultimate v0.0.1)
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/parse') {
      let inputStr = url.searchParams.get('url');
      if (request.method === 'POST') {
        inputStr = await request.text();
      }

      const allowLan = url.searchParams.get('lan') === 'true';

      if (!inputStr) {
        return new Response(JSON.stringify({ error: "Missing 'url' parameter or POST body" }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      let inputs = [];
      const trimmedInput = inputStr.trim();
      
      if (trimmedInput.startsWith('http://') || trimmedInput.startsWith('https://')) {
          inputs = trimmedInput.split(/[|,]/).map(u => u.trim()).filter(u => u);
      } else {
          inputs = [trimmedInput];
      }

      try {
        const results = await Promise.allSettled(inputs.map(u => parseContent(u, allowLan)));
        
        let allOutbounds = [];
        let errors = [];

        results.forEach((res, index) => {
          if (res.status === 'fulfilled') {
            allOutbounds.push(...res.value);
          } else {
            const label = inputs.length > 1 && inputs[index].startsWith('http') ? inputs[index] : "Input Content";
            console.warn(`Failed to parse ${label}: ${res.reason.message}`);
            errors.push({ source: label, error: res.reason.message });
          }
        });

        const finalOutbounds = processTags(allOutbounds);

        if (finalOutbounds.length === 0 && errors.length > 0) {
           return new Response(JSON.stringify({ error: "Parsing failed", details: errors }), {
             status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
           });
        }

        return new Response(JSON.stringify({ 
          outbounds: finalOutbounds
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
        <h1>🚀 sb-parser (Ultimate v0.0.32)</h1>
        <p>Patched: Forced insecure=true for Hysteria v1/v2.</p>
        <pre style="background:#f4f4f4;padding:1rem;">/parse?url=LINK</pre>
      </body>
    `, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};

// ============================================================
// 1. Core Logic & Helpers
// ============================================================

async function parseContent(input, allowLan) {
  let content = input;

  if (input.startsWith('http://') || input.startsWith('https://')) {
    if (!allowLan && isLanIP(new URL(input).hostname)) throw new Error("LAN access denied");
    
    const resp = await fetch(input, {
      headers: { 'User-Agent': 'Clash/1.0 (sb-parser/worker)' },
      redirect: 'follow'
    });
    if (!resp.ok) throw new Error(`Fetch error: ${resp.status}`);
    content = await resp.text();
  }

  content = content.trim();
  if (!content) throw new Error("Empty content");

  if (!content.includes('proxies:') && !content.startsWith('{') && !content.startsWith('[') && !content.includes('://')) {
    try { content = safeBase64Decode(content); } catch (e) {}
  }

  const nodes = [];

  // 1. JSON Parsing
  if (content.startsWith('{') || content.startsWith('[')) {
    try {
      const json = JSON.parse(content);
      const list = Array.isArray(json) ? json : (json.outbounds || [json]);
      list.forEach(r => { const n = sanitizeNode(r); if(n) nodes.push(n); });
      if(nodes.length > 0) return nodes;
    } catch(e) {}
  }

  // 2. YAML Parsing
  if (content.includes('proxies:')) {
    try {
      const proxies = SimpleYAML.parseProxies(content);
      if (proxies && proxies.length > 0) {
        proxies.forEach(p => {
          try {
            const n = parseClashProxy(p);
            if (n) {
               if (n.type === 'vless') nodes.push(n); 
               else {
                   const san = sanitizeNode(n);
                   if(san) nodes.push(san);
               }
            }
          } catch(err) {}
        });
        if (nodes.length > 0) return nodes;
      }
    } catch (e) {
      console.warn("YAML parse error:", e);
    }
  }

  // 3. Line-by-Line Parsing
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
        if (node.type === 'vless') nodes.push(node);
        else {
            const sanitized = sanitizeNode(node);
            if (sanitized) nodes.push(sanitized);
        }
      }
    } catch(e) {}
  }

  if (nodes.length === 0) throw new Error("No valid nodes found");
  return nodes;
}

// ============================================================
// Tag Processing
// ============================================================

function processTags(nodes) {
  const seenTags = new Set();
  const escapeRegExp = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  for (const node of nodes) {
    let oldTag = node.tag || "";
    const server = node.server || "";
    const port = String(node.server_port || "");
    const type = node.type || "";

    let cleanTag = oldTag;
    const partsToRemove = [
        `${server}:${port}`,
        server,
        port,
        type,
        `[${type}]`
    ];

    partsToRemove.forEach(part => {
        if (!part) return;
        try {
            const regex = new RegExp(escapeRegExp(part), 'gi');
            cleanTag = cleanTag.replace(regex, '');
        } catch(e) {}
    });

    cleanTag = cleanTag.replace(/\[\s*\]/g, ' ')
                       .replace(/\(\s*\)/g, ' ')
                       .replace(/\{\s*\}/g, ' ');
    
    cleanTag = cleanTag.replace(/\s+[:|\-]+\s+/g, ' '); 
    cleanTag = cleanTag.replace(/^[:|\-\s]+|[:|\-\s]+$/g, ''); 
    cleanTag = cleanTag.replace(/\s+/g, ' ').trim();

    let newTag = "";
    if (cleanTag) newTag += cleanTag + " ";
    newTag += `${server}:${port}`;
    newTag += ` [${type}]`; 

    let finalTag = newTag;
    let counter = 1;
    while (seenTags.has(finalTag)) {
       finalTag = `${newTag} (${counter})`;
       counter++;
    }
    
    seenTags.add(finalTag);
    node.tag = finalTag;
  }
  
  return nodes;
}

// ============================================================
// 2. Built-in Robust YAML Parser
// ============================================================
const SimpleYAML = {
  parseProxies(content) {
    const lines = content.split(/\r?\n/);
    const proxies = [];
    let inProxies = false;
    let currentProxyLines = [];

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
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
        if (currentIndent === 0 && !trimmed.startsWith('-')) break;

        if (trimmed.startsWith('-')) {
          if (currentProxyLines.length > 0) {
             proxies.push(this.processProxyBlock(currentProxyLines));
             currentProxyLines = [];
          }
          currentProxyLines.push(line);
        } else {
          if (currentProxyLines.length > 0) {
             currentProxyLines.push(line);
          }
        }
      }
    }
    if (currentProxyLines.length > 0) {
       proxies.push(this.processProxyBlock(currentProxyLines));
    }
    return proxies;
  },

  processProxyBlock(lines) {
      const raw = lines.join('\n');
      const obj = { _raw: raw };
      let firstLine = lines[0].trim().substring(1).trim();
      if (firstLine.startsWith('{')) {
          const inline = this.parseInlineObject(firstLine);
          Object.assign(obj, inline);
      } else {
          this.parseLine(firstLine, obj);
      }
      for (let i = 1; i < lines.length; i++) {
          this.parseLine(lines[i].trim(), obj);
      }
      return obj;
  },

  parseLine(str, obj) {
    const idx = str.indexOf(':');
    if (idx !== -1) {
      let key = str.substring(0, idx).trim();
      let val = str.substring(idx + 1).trim();
      if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.substring(1, key.length - 1);
      }
      obj[key] = this.parseValue(val);
    }
  },

  parseValue(val) {
    if (!val) return val;
    val = val.trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      return val.substring(1, val.length - 1);
    }
    if (val.startsWith('{')) return this.parseInlineObject(val);
    if (val.startsWith('[')) return this.parseInlineArray(val);
    if (val === 'true') return true;
    if (val === 'false') return false;
    if (val === 'null') return null;
    if (!isNaN(Number(val)) && val !== '') return Number(val);
    return val;
  },

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

  splitByComma(str) {
    const parts = [];
    let buffer = '';
    let depth = 0; 
    let inQuote = false;
    let quoteChar = '';
    for (let i = 0; i < str.length; i++) {
        const c = str[i];
        if ((c === '"' || c === "'") && (i === 0 || str[i-1] !== '\\')) {
            if (!inQuote) { inQuote = true; quoteChar = c; }
            else if (c === quoteChar) { inQuote = false; }
        }
        if (!inQuote) {
            if (c === '{' || c === '[') depth++;
            if (c === '}' || c === ']') depth--;
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
// 3. Helpers
// ============================================================

function extractNumber(val, def = 0) {
    if (typeof val === 'number') return val;
    if (!val) return def;
    const match = String(val).match(/(\d+)/);
    return match ? parseInt(match[1]) : def;
}

function deepFind(obj, keys) {
    if (!obj) return undefined;
    for (const k of keys) {
        if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
    }
    const nestedKeys = ['tls', 'tls-opts', 'reality-opts', 'realityOpts'];
    for (const nk of nestedKeys) {
        if (obj[nk] && typeof obj[nk] === 'object') {
            for (const k of keys) {
                 if (obj[nk][k] !== undefined && obj[nk][k] !== null && obj[nk][k] !== "") return obj[nk][k];
            }
        }
    }
    return undefined;
}

function isIP(host) {
    if (!host) return false;
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
}

function safeBase64Decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try { return atob(str); } catch(e) { return atob(str.substring(0, str.length - 1) + '='); } 
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

function splitHostPort(s) {
    const idx = s.lastIndexOf(':');
    if (idx === -1) return { host: s, port: 80 };
    if (s.includes(']') && idx > s.lastIndexOf(']')) return { host: s.substring(0, idx), port: parseInt(s.substring(idx+1)) };
    return { host: s.substring(0, idx), port: parseInt(s.substring(idx+1)) };
}

// ============================================================
// 4. Global Builders
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
  const obj = { 
    enabled: true, 
    insecure: !!ins
  };
  if (sni && typeof sni === 'string' && sni.trim() !== '') {
      obj.server_name = sni;
  }
  if (alpn && alpn.length > 0) obj.alpn = alpn;
  if (fp) obj.utls = { enabled: true, fingerprint: fp };
  return obj;
}

// Wrapper for global consistency
function buildGlobalTLS(sni, alpn, fp, ins) {
  return buildTLS(sni, alpn, fp, ins);
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
  
  const clean = (obj) => {
      Object.keys(obj).forEach(k => {
          if (obj[k] && typeof obj[k] === 'object') clean(obj[k]);
          if (obj[k] === undefined || obj[k] === null || obj[k] === "") delete obj[k];
      });
  };
  clean(node);
  return node;
}

// ============================================================
// 5. Protocol Parsers
// ============================================================

function parseClashProxy(p) {
    if (!p || typeof p !== 'object') return null;
    
    // Type Normalization
    let type = (p.type || "").toLowerCase();
    if (type === 'hy2') type = 'hysteria2';
    if (type === 'ss') type = 'shadowsocks';
    if (type === 'tuic-v5') type = 'tuic';

    const raw = p._raw || "";
    const findInRaw = (regex) => {
        const m = raw.match(regex);
        return m ? m[1] : null;
    };

    // --- VLESS BRANCH ---
    if (type === 'vless') {
        const rawSNI = 
            p.sni || 
            p['server-name'] || 
            p.server_name || 
            p.servername || 
            findInRaw(/(?:sni|server-name|servername|host)\s*:\s*['"]?([^'"\s\n]+)['"]?/i);
        
        const rawFlow = p.flow || findInRaw(/flow\s*:\s*['"]?([^'"\s\n]+)['"]?/i);
        
        let realityOpts = p['reality-opts'] || p.realityOpts || {};
        const pbk = realityOpts['public-key'] || realityOpts.publicKey || p['public-key'] || p.publicKey || findInRaw(/(?:public-key|pbk)\s*:\s*([^ \n]+)/i);
        const sid = realityOpts['short-id'] || realityOpts.shortId || p['short-id'] || p.shortId || findInRaw(/(?:short-id|sid)\s*:\s*([^ \n]+)/i);
        
        let realityObj = undefined;
        if (pbk) {
            realityObj = { public_key: pbk, short_id: sid };
        }

        let explicitInsecure = false;
        if (p['skip-cert-verify'] === true || p.insecure === true || p['allow-insecure'] === true) explicitInsecure = true;
        if (!explicitInsecure && (/skip-cert-verify\s*:\s*(true|1)/i.test(raw) || /insecure\s*:\s*(true|1)/i.test(raw))) explicitInsecure = true;

        const vlessInput = {
            tag: p.name,
            server: p.server,
            port: Number(p.port),
            uuid: p.uuid,
            flow: (rawFlow && rawFlow !== 'null' && rawFlow !== 'none') ? rawFlow : undefined,
            network: p.network || 'tcp',
            tls: !!p.tls,
            insecure: explicitInsecure,
            sni: rawSNI,
            reality: realityObj,
            ws_opts: p['ws-opts'],
            grpc_opts: p['grpc-opts'],
            utls_fingerprint: p['client-fingerprint'] || 'chrome'
        };

        return convertVLESS(vlessInput);
    }

    // --- OTHER PROTOCOLS ---
    
    const node = { tag: p.name, server: p.server, server_port: Number(p.port), type: type };

    let rawInsecure = null;
    if (p['skip-cert-verify'] === true || p.insecure === true) rawInsecure = true;
    else if (/skip-cert-verify\s*:\s*(true|1)/i.test(raw)) rawInsecure = true;
    else if (/insecure\s*:\s*(true|1)/i.test(raw)) rawInsecure = true;
    else if (/allow-insecure\s*:\s*(true|1)/i.test(raw)) rawInsecure = true;
    else if (/skip-cert-verify\s*:\s*(false|0)/i.test(raw)) rawInsecure = false;
    else if (/insecure\s*:\s*(false|0)/i.test(raw)) rawInsecure = false;

    const getFinalInsecure = (protoType) => {
        if (rawInsecure !== null) return rawInsecure;
        // Strict logic: No defaults for Hy/Tuic
        return false;
    };

    let extractedSNI = p.sni || p['server-name'] || p.server_name || p.servername || findInRaw(/(?:sni|server-name|servername|host)\s*:\s*['"]?([^'"\s\n]+)['"]?/i);
    if (extractedSNI && isIP(extractedSNI)) extractedSNI = undefined;

    const getFinalSNI = (protoType) => {
        if (extractedSNI) return extractedSNI;
        
        // AnyTLS: Allow IP fallback (Compatibility)
        if (protoType === 'anytls') return p.server;
        
        // Hysteria/Tuic: DO NOT fallback to apple.com
        
        // Standard: Fallback only if Domain
        if (p.server && !isIP(p.server)) return p.server;
        
        return undefined;
    };

    const rawUp = extractNumber(p.up_mbps ?? p.up ?? findInRaw(/(?:up|up-mbps|up_mbps)\s*:\s*(\d+)/i));
    const rawDown = extractNumber(p.down_mbps ?? p.down ?? findInRaw(/(?:down|down-mbps|down_mbps)\s*:\s*(\d+)/i));
    const up_mbps = (type === 'hysteria' ? (rawUp > 0 ? rawUp : 11) : (rawUp > 0 ? rawUp : 55));
    const down_mbps = rawDown > 0 ? rawDown : 55;

    const buildProxyTLS = (protoType, alpnDefault) => {
        const sni = getFinalSNI(protoType);
        const insecure = getFinalInsecure(protoType);
        const alpn = 
            Array.isArray(p.alpn) && p.alpn.length > 0 
                ? p.alpn 
                : (['hysteria2', 'hysteria', 'tuic'].includes(protoType) ? ['h3'] : alpnDefault);
        const fp = p['client-fingerprint'] || findInRaw(/client-fingerprint\s*:\s*([^ \n]+)/i);
        return buildGlobalTLS(sni, alpn, fp, insecure);
    };

    if (['ss', 'shadowsocks'].includes(type)) {
        node.type = 'shadowsocks'; node.method = p.cipher; node.password = p.password;
        if (p.plugin) {
            node.plugin = p.plugin;
            if (p['plugin-opts']) {
                if (typeof p['plugin-opts'] === 'object') {
                    node.plugin_opts = Object.entries(p['plugin-opts']).map(([k,v])=>`${k}=${v}`).join(';');
                } else {
                    node.plugin_opts = String(p['plugin-opts']);
                }
            }
        }
    } 
    else if (type === 'vmess') {
        node.uuid = p.uuid; node.security = p.cipher || 'auto'; node.alter_id = p.alterId || 0; node.packet_encoding = 'xudp';
        const net = p.network || 'tcp'; const opts = p[`${net}-opts`] || {};
        node.transport = buildTransport(net, null, opts.path, opts.headers?.Host, opts['grpc-service-name']);
        if (p.tls) {
            node.tls = buildProxyTLS('vmess');
            if (net === 'ws') node.tls.record_fragment = true;
        }
    } 
    else if (type === 'hysteria2') {
        node.type = 'hysteria2'; node.password = p.password; 
        node.up_mbps = up_mbps; node.down_mbps = down_mbps;
        if(p.obfs) node.obfs = { type: p.obfs, password: p['obfs-password'] };
        
        // [Diff] Manual Hy2 TLS
        const alpn = Array.isArray(p.alpn) && p.alpn.length > 0 ? p.alpn : ['h3'];
        const sni = p.sni || p.serverName || p['server-name'] || undefined;
        // hysteria v2: force skip cert verify
        node.tls = buildGlobalTLS(sni, alpn, null, true);
    } 
    else if (type === 'hysteria') {
        node.type = 'hysteria'; 
        node.auth_str = deepFind(p, ['auth-str', 'auth_str']); 
        node.up_mbps = up_mbps; 
        node.down_mbps = down_mbps;
        node.disable_mtu_discovery = p.disable_mtu_discovery ?? false;
        
        // [Diff] Manual Hy1 TLS
        const alpn = Array.isArray(p.alpn) && p.alpn.length > 0 ? p.alpn : ['h3'];
        const sni = p.sni || p.serverName || p['server-name'] || undefined;
        // hysteria v1: force skip cert verify
        node.tls = buildGlobalTLS(sni, alpn, null, true);
    } 
    else if (type === 'tuic') {
        node.type = 'tuic'; 
        node.uuid = p.uuid; 
        node.password = p.password || p.token;
        
        // [Diff] TUIC fields
        node.congestion_control = p['congestion-controller'] || undefined;
        node.zero_rtt_handshake = p['reduce-rtt'] ?? p.zero_rtt_handshake ?? undefined;
        
        const finalSNI = getFinalSNI('tuic') || p.sni || 'apple.com'; // User's diff kept explicit 'apple.com' fallback here specifically for TUIC in the diff block provided
        const alpn = Array.isArray(p.alpn) && p.alpn.length > 0 ? p.alpn : ['h3'];
        // Force insecure per user diff for TUIC specifically
        node.tls = buildGlobalTLS(finalSNI, alpn, null, true);
    } 
    else if (type === 'anytls') {
        node.type = 'anytls'; 
        node.password = p.password;
        
        // [Diff] AnyTLS
        const alpn = Array.isArray(p.alpn) && p.alpn.length > 0 ? p.alpn : undefined;
        // Force insecure per diff
        node.tls = buildGlobalTLS(p.server, alpn, p['client-fingerprint'], true);
    } 
    else if (type === 'trojan') {
        node.type = 'trojan'; node.password = p.password;
        const net = p.network || 'tcp'; const opts = p[`${net}-opts`] || {};
        node.transport = buildTransport(net, null, opts.path, opts.headers?.Host, opts['grpc-service-name']);
        node.tls = buildProxyTLS('trojan');
        if (net === 'ws') node.tls.record_fragment = true;
    }
    
    return ['shadowsocks','vmess','vless','trojan','hysteria2','hysteria','tuic','anytls'].includes(node.type) ? node : null;
}

// ============================================================
// VLESS Converter (Strict Logic)
// ============================================================

function resolveSNI({ explicitSNI, server, isReality }) {
  if (explicitSNI) return explicitSNI;
  if (isReality) return undefined; 
  if (server && !isIP(server)) return server; 
  return undefined;
}

function buildVLESSTLS({ sni, reality, utls, insecure }) {
  const tls = { enabled: true };
  if (sni) tls.server_name = sni;
  if (insecure) tls.insecure = true;
  if (utls) tls.utls = utls;
  if (reality) tls.reality = reality;
  return tls;
}

function convertVLESS(input) {
  const {
    tag, server, port, uuid, flow, network, tls, insecure, sni, reality,
    ws_opts, grpc_opts, utls_fingerprint,
  } = input;

  const isReality = Boolean(reality && reality.public_key);
  const finalSNI = resolveSNI({ explicitSNI: sni, server, isReality });

  const outbound = {
    tag: tag,
    type: "vless",
    server,
    server_port: port,
    uuid,
    packet_encoding: "xudp",
  };

  if (flow && flow !== 'null' && flow !== 'none') {
      outbound.flow = flow;
  }

  if (network === "ws") {
    outbound.transport = {
      type: "ws",
      path: ws_opts?.path || "/",
      headers: ws_opts?.headers || {},
    };
  } else if (network === "grpc") {
    outbound.transport = {
      type: "grpc",
      service_name: grpc_opts?.service_name || "",
    };
  }

  if (tls || isReality) {
    outbound.tls = buildVLESSTLS({
      sni: finalSNI,
      insecure: insecure,
      utls: utls_fingerprint ? { enabled: true, fingerprint: utls_fingerprint } : undefined,
      reality: isReality ? { enabled: true, public_key: reality.public_key, short_id: reality.short_id } : undefined,
    });
  }

  return outbound;
}

// ============================================================
// URL Parsers
// ============================================================

function parseHysteria2(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const up = extractNumber(q.get('up_mbps') || q.get('up'));
  const down = extractNumber(q.get('down_mbps') || q.get('down'));
  const node = {
    type: 'hysteria2', tag: fragment || `Hy2-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    password: u.password || u.username, 
    up_mbps: up > 0 ? up : 55, down_mbps: down > 0 ? down : 55
  };
  if(q.get('obfs') && q.get('obfs')!=='none') node.obfs = { type: q.get('obfs'), password: q.get('obfs-password') };
  const alpn = q.get('alpn') ? q.get('alpn').split(',') : ['h3'];
  let sni = q.get('sni') || q.get('peer') || q.get('serverName');
  if (sni && isIP(sni)) sni = undefined;
  if (!sni && !isIP(u.hostname)) sni = u.hostname;
  let ins = false;
  if (q.has('insecure') && (q.get('insecure')==='1'||q.get('insecure')==='true')) ins = true;
  node.tls = buildTLS(sni, alpn, null, ins); 
  return node;
}

function parseHysteria1(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const up = extractNumber(q.get('up') || q.get('up_mbps'));
  const down = extractNumber(q.get('down') || q.get('down_mbps'));
  const node = {
    type: 'hysteria', tag: fragment || `Hysteria-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    auth_str: q.get('auth') || u.username,
    up_mbps: up > 0 ? up : 11, down_mbps: down > 0 ? down : 55,
    disable_mtu_discovery: true
  };
  const alpn = q.get('alpn') ? q.get('alpn').split(',') : ['h3'];
  let sni = q.get('sni') || q.get('peer') || q.get('serverName');
  if (sni && isIP(sni)) sni = undefined;
  if (!sni && !isIP(u.hostname)) sni = u.hostname;
  let ins = false;
  if (q.has('insecure') && (q.get('insecure')==='1'||q.get('insecure')==='true')) ins = true;
  node.tls = buildTLS(sni, alpn, null, ins);
  return node;
}

function parseTuic(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'tuic', tag: fragment || `Tuic-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    uuid: u.username, password: u.password, congestion_control: 'bbr', zero_rtt_handshake: true
  };
  const alpn = q.get('alpn') ? q.get('alpn').split(',') : ['h3'];
  let sni = q.get('sni') || q.get('peer') || q.get('serverName');
  if (sni && isIP(sni)) sni = undefined;
  if (!sni && !isIP(u.hostname)) sni = u.hostname;
  let ins = false;
  if (q.has('insecure') && (q.get('insecure')==='1'||q.get('insecure')==='true')) ins = true;
  node.tls = buildTLS(sni, alpn, null, ins);
  return node;
}

function parseAnyTLS(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  let pwd = u.username; if (u.password) pwd = u.password;
  const node = {
    type: 'anytls', tag: fragment || `AnyTLS-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port),
    password: pwd
  };
  let sni = q.get('sni') || q.get('peer') || q.get('serverName') || u.hostname;
  let ins = false;
  if (q.has('insecure') && (q.get('insecure')==='1'||q.get('insecure')==='true')) ins = true;
  node.tls = buildTLS(sni, undefined, null, ins);
  return node;
}

function parseVLESS(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const flowVal = q.get('flow');
  
  let realityObj = undefined;
  if (q.get('security') === 'reality' || q.has('pbk') || q.has('publicKey')) {
      realityObj = {
          public_key: q.get('pbk') || q.get('publicKey'),
          short_id: q.get('sid') || q.get('shortId')
      };
  }

  let ins = false;
  if (q.has('insecure') && (q.get('insecure') === '1' || q.get('insecure') === 'true')) ins = true;
  if (q.has('allowInsecure') && (q.get('allowInsecure') === '1' || q.get('allowInsecure') === 'true')) ins = true;

  const vlessInput = {
      tag: fragment || `VLESS-${u.hostname}`,
      server: u.hostname,
      port: parseInt(u.port),
      uuid: u.username,
      flow: (flowVal && flowVal !== 'null' && flowVal !== 'none') ? flowVal : undefined,
      network: q.get('type') || 'tcp',
      tls: q.get('security') === 'tls' || q.get('security') === 'xtls' || !!realityObj,
      insecure: ins,
      sni: q.get('sni') || q.get('peer') || q.get('serverName'),
      reality: realityObj,
      ws_opts: { path: q.get('path'), headers: q.get('host') ? { Host: q.get('host') } : undefined },
      grpc_opts: { service_name: q.get('serviceName') },
      utls_fingerprint: q.get('fp') || 'chrome'
  };

  return convertVLESS(vlessInput);
}

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

function parseTrojan(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'trojan', tag: fragment || `Trojan-${u.hostname}`, server: u.hostname, server_port: parseInt(u.port), password: u.username
  };
  node.transport = buildTransport(q.get('type'), null, q.get('path'), q.get('host'), q.get('serviceName'));
  let ins = false;
  if (q.has('allowInsecure') && (q.get('allowInsecure') === '1' || q.get('allowInsecure') === 'true')) ins = true;
  node.tls = buildTLS(q.get('sni') || q.get('peer') || u.hostname, q.get('alpn') ? q.get('alpn').split(',') : undefined, q.get('fp'), ins);
  if (node.transport && node.transport.type === 'ws') node.tls.record_fragment = true;
  return node;
}
