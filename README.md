The project documentation, including the **User Guide** and the **Protocol Extension Proposal**.

---

# sb-parser Project DocumentationT

**A Zero-Dependency, Robust Cloudflare Worker for Subscription Parsing**

This document consists of two parts:
1.  **User Guide**: How to submit subscriptions (GET/POST methods, merging links).
2.  **Technical Proposal**: Architecture design and guidelines for adding support for new protocols (WireGuard, SSH, SOCKS5, etc.).

---

# Part 1: User Guide

## 1. Overview
`sb-parser` features an **Intelligent Parsing Mode**. Whether you submit a remote HTTP link, a Base64 encoded string, or a block of mixed `vmess://` URIs, the worker automatically detects and handles the content.

*   **API Endpoint**: `https://<your-worker-domain>/parse`
*   **Separators**: You can use `|` (pipe) or `,` (comma) to separate multiple subscription sources.

## 2. GET Method
Best for quick testing via browser or simple CLI usage.

**Syntax**:
```
GET /parse?url=<link1>|<link2>
```

**Examples**:
```bash
# Single Link
curl "https://api.worker.dev/parse?url=https://sub.com/api"

# Multiple Links (Note: URL encoding is required for special chars like '|')
# %7C represents '|'
curl "https://api.worker.dev/parse?url=https://sub1.com%7Chttps://sub2.com"
```

## 3. POST Method (Recommended)
Submit data via the HTTP Request Body. This is recommended for merging large subscriptions or handling sensitive data, as it avoids URL length limits.

**Supported Content Types**:
1.  **URL List**: Multiple remote subscription links.
2.  **Raw Text**: Raw blocks containing `vmess://`, `ss://`, etc.
3.  **Hybrid Mode**: A mix of remote URLs and raw URI text.

**Example 1: Merging multiple remote subscriptions**
```bash
curl -X POST "https://api.worker.dev/parse" \
     -d "https://airport-a.com/api/sub|https://airport-b.com/api/sub"
```

**Example 2: Submitting a raw URI list**
```bash
# The worker will identify this as raw text (doesn't start with http) and parse immediately
curl -X POST "https://api.worker.dev/parse" \
     -d "vmess://ew0KICA...|ss://YmFzZTY0..."
```

**Example 3: Batch import from a local file**
Assuming `subs.txt` contains:
```text
https://my-private-sub.com/token=123
https://public-node-collection.com/list
hy2://password@1.1.1.1:443?sni=google.com
```

Command:
```bash
# The worker's logic handles newlines automatically
curl -X POST "https://api.worker.dev/parse" --data-binary @subs.txt
```

---

# Part 2: Protocol Extension Proposal

## 1. Background & Objectives
`sb-parser` is positioned as a **Zero-Dependency**, single-file converter. It currently supports mainstream V2Ray/Xray protocols and the Clash YAML format.

**Objective**: Establish a standardized workflow to rapidly integrate non-standard or legacy protocols (WireGuard, SSH, SOCKS5, HTTP) while maintaining the lightweight "single-file" architecture.

## 2. Architecture Analysis
The current parsing flow is:
1.  **Input Cleaning**: Fetch/Read -> Base64 Decode -> Format Detection.
2.  **Specific Parsing**:
    *   Clash YAML -> `SimpleYAML` -> `parseClashProxy`
    *   URI Text -> String Matching (`startsWith`) -> `parseSS`/`parseVMess`, etc.
3.  **Normalization**: `sanitizeNode` (Clean and convert to valid Sing-box JSON format).

## 3. Implementation Plan

To support new protocols, extensions are required in **Step 2** and **Step 3**.

### 3.1 Extending the URI Parser
For a new protocol (e.g., WireGuard), a dedicated parser function is needed following this signature:

```javascript
function parseWireGuard(uri) {
  // 1. Parse URI parameters (using the parseUrlObj utility)
  // 2. Extract core fields (Endpoint, PublicKey, PrivateKey, IP)
  // 3. Return a temporary node object
}
```

**Roadmap for New Protocols**:
*   **WireGuard**: `wg://` (Requires parsing Private Key, Public Key, MTU, Reserved bytes).
*   **SOCKS5**: `socks5://` (Requires User/Pass).
*   **HTTP**: `http://` (Requires User/Pass).
*   **ShadowTLS**: `shadowtls://` (Complex: acts as a wrapper for the Transport layer).

### 3.2 Extending the Clash Parser
Clash YAML configurations use specific field names for different protocols. We need to add `else if` branches in the `parseClashProxy(p)` function.

**Modification Example**:
```javascript
// Inside parseClashProxy function
else if (type === 'wireguard') {
    node.type = 'wireguard';
    // Map Clash 'kebab-case' to Sing-box 'snake_case'
    node.private_key = p['private-key'];
    node.peer_public_key = p['peer-public-key'];
    node.local_address = p.ip ? [p.ip] : (p['ipv6'] ? [p['ipv6']] : []);
    node.mtu = p.mtu || 1420;
    // ... map other fields
}
```

### 3.3 Extending the Sanitizer (Normalization)
The `sanitizeNode` function is the final gatekeeper. It determines which fields are allowed in the final JSON output.

**Current Logic**:
Uses a hardcoded mapping table `m`.
```javascript
const m = { 'ss':'shadowsocks', ... };
```

**Extension Plan**:
1.  **Update the Map**: Allow the new protocol types to pass through.
    ```javascript
    const m = {
        ...,
        'wg': 'wireguard',
        'wireguard': 'wireguard',
        'socks5': 'socks5',
        'http': 'http'
    };
    ```
2.  **Field Whitelisting**: The current logic removes "empty" fields. Some protocols (like WireGuard) might have valid fields that look empty (e.g., `reserved` bytes being `[0,0,0]`). The sanitizer logic needs adjustment to preserve these specific values.

## 4. Contribution Guide

Developers wishing to add support for a new protocol should follow these steps:

### Step 1: Define URI Parsing Logic
Add a new function at the end of the `// 3. Protocol Parsers` section.
*   **Input**: URI String.
*   **Output**: JavaScript Object adhering to Sing-box outbound specifications.

### Step 2: Register URI Recognition
Add the header detection in the main loop within `parseContent`:
```javascript
// 5. URI List Loop
else if (line.startsWith('newproto://')) node = parseNewProto(line);
```

### Step 3: Adapt Clash Format (Optional)
If the protocol is common in Clash subscriptions, add the field mapping logic in `parseClashProxy`. Pay attention to the naming convention differences (Clash `kebab-case` vs Sing-box `snake_case`).

### Step 4: Update Whitelist
Add the new protocol type to the whitelist map in `sanitizeNode`.

## 5. Example: Adding SOCKS5 Support

```javascript
// 1. Register in parseContent
// else if (line.startsWith('socks5://')) node = parseSocks5(line);

// 2. Implement Parser Function
function parseSocks5(uri) {
  const { u, q, fragment } = parseUrlObj(uri);
  const node = {
    type: 'socks5',
    tag: fragment || `Socks5-${u.hostname}`,
    server: u.hostname,
    server_port: parseInt(u.port),
    username: u.username || undefined,
    password: u.password || undefined
  };
  return node;
}

// 3. Update sanitizeNode map
// const m = { ..., 'socks5': 'socks5' };
```

## 6. Risk Assessment & Control
*   **Script Size**: As protocols are added, the Worker script size will increase. Since we cannot use Tree-shaking (Zero-Dependency), code must remain concise.
    *   *Mitigation*: Avoid importing large validation libraries; rely on basic string manipulation and RegEx.
*   **Fragmented URI Standards**: A single protocol (e.g., VLESS) may have multiple URI formats (V2RayN standard vs Clash standard).
    *   *Mitigation*: Adhere to the most generic standard (usually Xray/V2RayN). Compatibility patches should only be added if significant user issues arise.
