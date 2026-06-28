import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // =================【第一步：无条件转发 WebSocket 请求】=================
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // =================【第二步：无条件放行所有页面请求，杜绝白屏/黑屏】=================
    const response = await env.ASSETS.fetch(request);
    const contentType = response.headers.get('Content-Type') || '';

    // 只有在返回 HTML 网页时，我们才去动态处理按钮的隐藏和显示
    if (contentType.includes('text/html')) {
      let text = await response.text();

      // 1. 替换基础文本标签
      text = text.replace(/NodeCrypt/g, '阅后即焚');
      text = text.replace(/nodecrypt/g, '阅后即焚');
      text = text.replace(/@shuaieplus/g, '爆改自@shuaieplus');

      // 2. 🎯 【核心暗号显形逻辑】：
      // 默认情况下，给页面注入一段极其安全的 CSS，只要按钮或弹窗一露头，立刻隐形。
      // 但是！如果检测到你访问的链接里带着 `admin=1` 这个专属暗号，就不隐藏它，让你能正常点到。
      const showButton = url.searchParams.get('admin') === '1';

      if (!showButton) {
        // 普通人访问（不带 admin=1），注入极简的精准隐藏样式
        const injectStyle = `
          <style>
            /* 精准隐藏左侧栏的 “进入新の房间” 按钮（根据文本和常见类名匹配） */
            div:has(> span:contains("房间")), 
            div:has(> button:contains("房间")), 
            button:contains("房间"),
            li:contains("房间"),
            /* 隐藏点击之后可能弹出的中央模态框 */
            div[class*="modal"], 
            div[class*="dialog"] {
              display: none !important;
              opacity: 0 !important;
              pointer-events: none !important;
              visibility: hidden !important;
            }
          </style>
          <script>
            // 配合动态监听，普通人进来只要看到有这个按钮，直接物理移出，双重保险
            (function() {
              function clean() {
                document.querySelectorAll('div, button, li, span').forEach(el => {
                  if (el.textContent && (el.textContent.includes('进入新') || el.textContent.includes('新の房间'))) {
                    if (el.closest('.sidebar') || el.closest('[class*="sidebar"]') || el.closest('[class*="modal"]') || el.closest('[class*="dialog"]')) {
                      try { el.remove(); } catch(e){}
                    }
                  }
                });
              }
              clean();
              new MutationObserver(clean).observe(document.body, { childList: true, subtree: true });
            })();
          </script>
        `;
        text = text.replace('</body>', `${injectStyle}</body>`);
      }

      const newHeaders = new Headers(response.headers);
      newHeaders.delete('Content-Length');
      return new Response(text, { status: response.status, headers: newHeaders });
    }

    return response;
  }
};

// =================【Durable Object 房间核心中枢（保持原样，不做任何拦截伤害）】=================
export class ChatRoom {  
  constructor(state, env) {
    this.state = state;
    this.clients = {};
    this.channels = {};
    this.config = { seenTimeout: 60000, debug: false };
    this.initRSAKeyPair();
  }
  async initRSAKeyPair() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        const keyPair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([crypto.subtle.exportKey('spki', keyPair.publicKey), crypto.subtle.exportKey('pkcs8', keyPair.privateKey)]);
        stored = { rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))), rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)), createdAt: Date.now() };
        await this.state.storage.put('rsaKeyPair', stored);
      }
      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);
        stored.rsaPrivate = await crypto.subtle.importKey('pkcs8', privateKeyBuffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);      
      }
      this.keyPair = stored;
    } catch (error) {}
  }
  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') return new Response('Expected WebSocket Upgrade', { status: 426 });
    if (!this.keyPair) await this.initRSAKeyPair();
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    this.handleSession(server, request);
    return new Response(null, { status: 101, webSocket: client });
  }  
  async handleSession(connection, request) {    
    connection.accept();
    await this.cleanupOldConnections();
    const clientId = generateClientId();
    if (!clientId || this.clients[clientId]) { this.closeConnection(connection); return; }
    this.clients[clientId] = { connection: connection, seen: getTime(), key: null, shared: null, channel: null };
    try { this.sendMessage(connection, JSON.stringify({ type: 'server-key', key: this.keyPair.rsaPublic })); } catch (error) {}    
    connection.addEventListener('message', async (event) => {
      const message = event.data;
      if (!isString(message) || !this.clients[clientId]) return;
      this.clients[clientId].seen = getTime();
      if (message === 'ping') { this.sendMessage(connection, 'pong'); return; }
      if (!this.clients[clientId].shared && message.length < 2048) {
        try {
          const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits', 'deriveKey']);
          const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);
          const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, this.keyPair.rsaPrivate, publicKeyBuffer);
          const clientPublicKeyHex = message;
          const clientPublicKeyBytes = new Uint8Array(clientPublicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
          const clientPublicKey = await crypto.subtle.importKey('raw', clientPublicKeyBytes, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
          const sharedSecretBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: clientPublicKey }, keys.privateKey, 384);          
          this.clients[clientId].shared = new Uint8Array(sharedSecretBits).slice(8, 40);
          const response = Array.from(new Uint8Array(publicKeyBuffer)).map(b => b.toString(16).padStart(2, '0')).join('') + '|' + btoa(String.fromCharCode(...new Uint8Array(signature)));
          this.sendMessage(connection, response);
        } catch (error) { this.closeConnection(connection); }
        return;
      }
      if (this.clients[clientId].shared && message.length <= (8 * 1024 * 1024)) { this.processEncryptedMessage(clientId, message); }
    });    
    connection.addEventListener('close', async (event) => {
      const channel = this.clients[clientId].channel;
      if (channel && this.channels[channel]) {
        this.channels[channel].splice(this.channels[channel].indexOf(clientId), 1);
        if (this.channels[channel].length === 0) { delete(this.channels[channel]); } else {
          try {
            const members = this.channels[channel];
            for (const member of members) {
              const client = this.clients[member];              
              if (this.isClientInChannel(client, channel)) { this.sendMessage(client.connection, encryptMessage({ a: 'l', p: members.filter((value) => value !== member) }, client.shared)); }
            }
          } catch (error) {}
        }
      }
      if (this.clients[clientId]) delete(this.clients[clientId]);
    });
  }
  processEncryptedMessage(clientId, message) {
    let decrypted = null;
    try {
      decrypted = decryptMessage(message, this.clients[clientId].shared);
      if (!isObject(decrypted) || !isString(decrypted.a)) return;
      const action = decrypted.a;
      if (action === 'j') { this.handleJoinChannel(clientId, decrypted); } 
      else if (action === 'c') { this.handleClientMessage(clientId, decrypted); } 
      else if (action === 'w') { this.handleChannelMessage(clientId, decrypted); }
    } catch (error) {} finally { decrypted = null; }
  }
  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) return;
    try { const channel = decrypted.p; this.clients[clientId].channel = channel; if (!this.channels[channel]) { this.channels[channel] = [clientId]; } else { this.channels[channel].push(clientId); } this.broadcastMemberList(channel); } catch (error) {}
  }
  handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) return;
    try { const channel = this.clients[clientId].channel; const targetClient = this.clients[decrypted.c]; if (this.isClientInChannel(targetClient, channel)) { const messageObj = { a: 'c', p: decrypted.p, c: clientId }; this.sendMessage(targetClient.connection, encryptMessage(messageObj, targetClient.shared)); } } catch (error) {}
  }  
  handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) return;
    try { const channel = this.clients[clientId].channel; const validMembers = Object.keys(decrypted.p).filter(member => { const targetClient = this.clients[member]; return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel); }); for (const member of validMembers) { const targetClient = this.clients[member]; const messageObj = { a: 'c', p: decrypted.p[member], c: clientId }; this.sendMessage(targetClient.connection, encryptMessage(messageObj, targetClient.shared)); } } catch (error) {}
  }
  broadcastMemberList(channel) {
    try { const members = this.channels[channel]; for (const member of members) { const client = this.clients[member]; if (this.isClientInChannel(client, channel)) { this.sendMessage(client.connection, encryptMessage({ a: 'l', p: members.filter((value) => value !== member) }, client.shared)); } } } catch (error) {}
  }  
  isClientInChannel(client, channel) { return (client && client.connection && client.shared && client.channel && client.channel === channel); }
  sendMessage(connection, message) { try { if (connection.readyState === 1) connection.send(message); } catch (error) {} }  
  closeConnection(connection) { try { connection.close(); } catch (error) {} }
  async cleanupOldConnections() {
    const seenThreshold = getTime() - this.config.seenTimeout; const clientsToRemove = []; for (const clientId in this.clients) { if (this.clients[clientId].seen < seenThreshold) clientsToRemove.push(clientId); } for (const clientId of clientsToRemove) { try { this.clients[clientId].connection.close(); delete this.clients[clientId]; } catch (error) {} } return clientsToRemove.length;
  }
}
