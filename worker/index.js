import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // =================【第一步：截获并转发 WebSocket 请求】=================
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // =================【第二步：无条件放行带房间参数的网页内容请求】=================
    if (url.searchParams.has('r')) {
      const response = await env.ASSETS.fetch(request);
      return handleTextReplacement(response, false); 
    }

    // =================【第三步：精准拦截首页根目录（看门人守卫逻辑）】=================
    if (url.pathname === '/') {
      const cookieHeader = request.headers.get('Cookie') || '';
      
      // 检查 A：URL 后面带着固定暗号 kamiko (只有你通过这个链接进入，才能作为管理员创建房间)
      if (url.searchParams.get('create') === 'kamiko') {
        const response = await env.ASSETS.fetch(request);
        const replacedResponse = await handleTextReplacement(response, true); 
        const newResponse = new Response(replacedResponse.body, replacedResponse);
        newResponse.headers.append('Set-Cookie', 'chat_auth=kamiko; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax');
        return newResponse;
      }

      // 检查 B：浏览器里已经有通行证（Cookie）了
      if (cookieHeader.includes('chat_auth=kamiko')) {
        const response = await env.ASSETS.fetch(request);
        return handleTextReplacement(response, true);
      }

      // 检查 C：普通访客直接拦截
      return new Response('Access Denied: Please use the correct creation link.', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // =================【第四步：处理其余 API 和静态资产请求】=================
    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }

    const response = await env.ASSETS.fetch(request);
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('text/html') || contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      return handleTextReplacement(response, false);
    }
    return response;
  }
};

// 💡【核心动态文本与前端功能篡改函数】
async function handleTextReplacement(response, isAdmin) {
  if (!response.ok) return response;
  
  let text = await response.text();

  // 1. 替换基础文本标签
  text = text.replace(/NodeCrypt/g, '阅后即焚');
  text = text.replace(/nodecrypt/g, '阅后即焚');
  text = text.replace(/@shuaieplus/g, '爆改自@shuaieplus');

  // 2. 切除分享链接里的暗号
  text = text.replace(/window\.location\.href/g, 'window.location.href.replace("create=kamiko&", "").replace("create=kamiko", "")');
  text = text.replace(/location\.href/g, 'location.href.replace("create=kamiko&", "").replace("create=kamiko", "")');
  text = text.replace(/window\.location\.search/g, 'window.location.search.replace("create=kamiko&", "").replace("create=kamiko", "")');

  // 3. 核心大招：如果【不是管理员】，注入高频强力自动化清洗脚本
  if (!isAdmin) {
    const killScriptInject = `
      <script>
        (function() {
          function purgeTargetElements() {
            // 扫描整个网页中所有包含"房间"或"进入"的 DOM 节点
            const elements = document.querySelectorAll('div, button, a, span, p, h3');
            elements.forEach(el => {
              if (el.textContent && (el.textContent.includes('房间') || el.textContent.includes('进入'))) {
                // 如果是侧边栏的“进入新の房间”按钮项，或者弹窗的“进入新の房间”标题
                // 顺着节点往上找，把整个容器直接彻底干掉
                if (el.tagName === 'DIV' || el.tagName === 'BUTTON' || el.tagName === 'A' || el.tagName === 'H3') {
                  // 精准屏蔽：避免误删聊天内容，重点删除左侧菜单和模态弹窗
                  if (el.closest('.sidebar') || el.closest('[class*="sidebar"]') || el.closest('.modal') || el.closest('[class*="modal"]') || el.closest('[class*="dialog"]') || el.textContent.includes('进入新')) {
                    el.style.setProperty('display', 'none', 'important');
                    el.remove(); // 直接从内存和HTML中彻底物理删除该节点
                  }
                }
              }
            });
          }

          // 1. 立即执行一次
          purgeTargetElements();

          // 2. 使用动态监听器（MutationObserver），防止单页应用（SPA）在路由切换或弹窗弹出时重新生成该按钮
          const observer = new MutationObserver((mutations) => {
            purgeTargetElements();
          });

          observer.observe(document.body, {
            childList: true,
            subtree: true
          });

          // 3. 定时器双重死锁保险
          setInterval(purgeTargetElements, 300);
        })();
      </script>
      <style>
        /* 暴力黑洞：万一JS慢了0.01秒，用全局最野蛮的选择器先隐藏可能出现的文本容器 */
        div:has(span:contains("房间")), div:has(button:contains("房间")), button:contains("房间") {
          display: none !important;
          opacity: 0 !important;
          visibility: hidden !important;
          pointer-events: none !important;
        }
      </style>
    `;
    
    // 把这套物理清除脚本和样式注入到 </body> 标签之前，确保在页面加载和渲染的每一个生命周期都在强制执行
    text = text.replace('</body>', `${killScriptInject}</body>`);
    
    // 文本字面量硬替换
    text = text.replace(/进入新的房间/g, '');
    text = text.replace(/进入新の房间/g, '');
  }

  const newHeaders = new Headers(response.headers);
  newHeaders.delete('Content-Length'); 

  return new Response(text, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

// =================【Durable Object 房间核心中枢】=================
export class ChatRoom {  
  constructor(state, env) {
    this.state = state;
    this.clients = {};
    this.channels = {};
    this.config = {
      seenTimeout: 60000,
      debug: false
    };
    this.initRSAKeyPair();
  }

  async initRSAKeyPair() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['sign', 'verify']
        );

        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
          crypto.subtle.exportKey('spki', keyPair.publicKey),
          crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
        ]);
        
        stored = {
          rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
          rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)),
          createdAt: Date.now()
        };
        
        await this.state.storage.put('rsaKeyPair', stored);
      }
      
      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);
        stored.rsaPrivate = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBuffer,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
          },
          false,
          ['sign']
        );      
      }
      this.keyPair = stored;
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
    }
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    this.handleSession(server, request);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }  

  async handleSession(connection, request) {    
    connection.accept();
    await this.cleanupOldConnections();

    const clientId = generateClientId();
    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection);
      return;
    }

    const cookieHeader = request.headers.get('Cookie') || '';
    const hasSecretToken = cookieHeader.includes('chat_auth=kamiko');

    this.clients[clientId] = {
      connection: connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null,
      isAuthorized: hasSecretToken 
    };

    try {
      this.sendMessage(connection, JSON.stringify({
        type: 'server-key',
        key: this.keyPair.rsaPublic
      }));
    } catch (error) {}    

    connection.addEventListener('message', async (event) => {
      const message = event.data;
      if (!isString(message) || !this.clients[clientId]) return;

      this.clients[clientId].seen = getTime();

      if (message === 'ping') {
        this.sendMessage(connection, 'pong');
        return;
      }

      if (!this.clients[clientId].shared && message.length < 2048) {
        try {
          const keys = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-384' },
            true,
            ['deriveBits', 'deriveKey']
          );

          const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);
          const signature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' },
            this.keyPair.rsaPrivate,
            publicKeyBuffer
          );

          const clientPublicKeyHex = message;
          const clientPublicKeyBytes = new Uint8Array(clientPublicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
          
          const clientPublicKey = await crypto.subtle.importKey(
            'raw',
            clientPublicKeyBytes,
            { name: 'ECDH', namedCurve: 'P-384' },
            false,
            []
          );

          const sharedSecretBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: clientPublicKey },
            keys.privateKey,
            384
          );          
          this.clients[clientId].shared = new Uint8Array(sharedSecretBits).slice(8, 40);

          const response = Array.from(new Uint8Array(publicKeyBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('') + 
            '|' + btoa(String.fromCharCode(...new Uint8Array(signature)));
          
          this.sendMessage(connection, response);

        } catch (error) {
          this.closeConnection(connection);
        }
        return;
      }

      if (this.clients[clientId].shared && message.length <= (8 * 1024 * 1024)) {
        this.processEncryptedMessage(clientId, message);
      }
    });    

    connection.addEventListener('close', async (event) => {
      const channel = this.clients[clientId].channel;
      if (channel && this.channels[channel]) {
        this.channels[channel].splice(this.channels[channel].indexOf(clientId), 1);
        if (this.channels[channel].length === 0) {
          delete(this.channels[channel]);
        } else {
          try {
            const members = this.channels[channel];
            for (const member of members) {
              const client = this.clients[member];              
              if (this.isClientInChannel(client, channel)) {
                this.sendMessage(client.connection, encryptMessage({
                  a: 'l',
                  p: members.filter((value) => value !== member)
                }, client.shared));
              }
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

      if (action === 'j') {
        const targetChannel = decrypted.p;
        const clientInfo = this.clients[clientId];

        if (!clientInfo.isAuthorized) {
          if (clientInfo.channel && clientInfo.channel !== targetChannel) {
             console.log(`[安全拦截] 拦截非法窜房: ${targetChannel}`);
             this.closeConnection(clientInfo.connection);
             return;
          }
          if (!this.channels[targetChannel]) {
             console.log(`[安全拦截] 拒绝无暗号用户创建新房间: ${targetChannel}`);
             this.closeConnection(clientInfo.connection);
             return;
          }
        }
        
        this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        this.handleChannelMessage(clientId, decrypted);
      }
    } catch (error) {
    } finally {
      decrypted = null;
    }
  }

  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) return;
    try {
      const channel = decrypted.p;
      this.clients[clientId].channel = channel;
      if (!this.channels[channel]) {
        this.channels[channel] = [clientId];
      } else {
        this.channels[channel].push(clientId);
      }
      this.broadcastMemberList(channel);
    } catch (error) {}
  }

  handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) return;
    try {
      const channel = this.clients[clientId].channel;
      const targetClient = this.clients[decrypted.c];
      if (this.isClientInChannel(targetClient, channel)) {
        const messageObj = { a: 'c', p: decrypted.p, c: clientId };
        this.sendMessage(targetClient.connection, encryptMessage(messageObj, targetClient.shared));
      }
    } catch (error) {}
  }  

  handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) return;
    try {
      const channel = this.clients[clientId].channel;
      const validMembers = Object.keys(decrypted.p).filter(member => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });
      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const messageObj = { a: 'c', p: decrypted.p[member], c: clientId };        
        this.sendMessage(targetClient.connection, encryptMessage(messageObj, targetClient.shared));
      }
    } catch (error) {}
  }

  broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];
      for (const member of members) {
        const client = this.clients[member];
        if (this.isClientInChannel(client, channel)) {
          this.sendMessage(client.connection, encryptMessage({
            a: 'l',
            p: members.filter((value) => value !== member)
          }, client.shared));
        }
      }
    } catch (error) {}
  }  

  isClientInChannel(client, channel) {
    return (client && client.connection && client.shared && client.channel && client.channel === channel);
  }

  sendMessage(connection, message) {
    try {
      if (connection.readyState === 1) connection.send(message);
    } catch (error) {}
  }  

  closeConnection(connection) {
    try { connection.close(); } catch (error) {}
  }
  
  async cleanupOldConnections() {
    const seenThreshold = getTime() - this.config.seenTimeout;
    const clientsToRemove = [];
    for (const clientId in this.clients) {
      if (this.clients[clientId].seen < seenThreshold) clientsToRemove.push(clientId);
    }
    for (const clientId of clientsToRemove) {
      try {
        this.clients[clientId].connection.close();
        delete this.clients[clientId];
      } catch (error) {}
    }
    return clientsToRemove.length;
  }
}
