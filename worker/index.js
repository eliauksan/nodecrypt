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

    // =================【第二步：带房间参数的请求（即已经在聊天窗口内），执行强力拦截替换】=================
    if (url.searchParams.has('r')) {
      const response = await env.ASSETS.fetch(request);
      return handleTextReplacement(response, true); // 传入 true，代表在房间内，开启拦截
    }

    // =================【第三步：精准拦截首页根目录（看门人守卫逻辑）】=================
    if (url.pathname === '/') {
      const cookieHeader = request.headers.get('Cookie') || '';
      
      // 检查 A：URL 后面带着固定暗号 kamiko
      if (url.searchParams.get('create') === 'kamiko') {
        const response = await env.ASSETS.fetch(request);
        // 首页不需要拦截弹窗，传入 false
        const replacedResponse = await handleTextReplacement(response, false);
        const newResponse = new Response(replacedResponse.body, replacedResponse);
        // 埋下通行证
        newResponse.headers.append('Set-Cookie', 'chat_auth=kamiko; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax');
        return newResponse;
      }

      // 检查 B：浏览器里已经有通行证（Cookie）了，放行首页
      if (cookieHeader.includes('chat_auth=kamiko')) {
        const response = await env.ASSETS.fetch(request);
        // 既然已经是通行首页，说明是登录前的主界面，不需要拦截内部弹窗，传入 false
        return handleTextReplacement(response, false);
      }

      // 检查 C：既没有暗号也没有 Cookie，直接拦截返回 403
      return new Response('Access Denied: Please use the correct creation link.', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // =================【第四步：处理其余静态资产和 API 请求】=================
    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }

    const response = await env.ASSETS.fetch(request);
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('text/html') || contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      // 只有明确在聊天房间相关的 JS 或页面中才根据状态拦截，通常静态资源文件统一处理
      return handleTextReplacement(response, false);
    }
    return response;
  }
};

// 💡【核心动态文本替换与定向拦截注入函数】
async function handleTextReplacement(response, shouldBlockInside) {
  if (!response.ok) return response;
  
  let text = await response.text();

  // 1. 全局基础文本替换
  text = text.replace(/NodeCrypt/g, '阅后即焚');
  text = text.replace(/nodecrypt/g, '阅后即焚');
  text = text.replace(/@shuaieplus/g, '爆改自@shuaieplus');

  // 2. 只有当明确处于房间内部（URL 带有 r 参数等触发 shouldBlockInside = true）时，才激活拦截代码
  if (shouldBlockInside) {
    const injection = `
      <style>
        /* 精准打击：只在侧边栏显示、且已经处于房间状态时，隐形掉那个“进入新房间”的菜单项 */
        div[class*="sidebar"] div:has(> svg):has(span),
        div[class*="sidebar"] div:contains("进入"),
        div[class*="menu"] div:contains("进入") {
          display: none !important;
          opacity: 0 !important;
          pointer-events: none !important;
        }
      </style>
      <script>
        // 定时守护脚本：如果用户在聊天室内部通过骚操作触发了本地路由弹窗
        // 只要当前链接里有 '?r=' 或 '#/room'，脚本就会自动把这个弹窗给无情移除
        setInterval(() => {
          if (window.location.search.includes('r=') || window.location.hash.includes('room')) {
            const elements = document.querySelectorAll('div, h2, h3, p');
            elements.forEach(el => {
              if (el.textContent && (el.textContent.includes('进入新') || el.textContent.includes('专属私密'))) {
                // 顺着它往上找最外层的弹窗遮罩盒子
                const modalBox = el.closest('div[class*="modal"], div[class*="dialog"], div[style*="position: fixed"]');
                if (modalBox) {
                  console.log('检测到室内违规弹窗，已自动粉碎。');
                  modalBox.remove(); 
                }
              }
            });
          }
        }, 50);
      </script>
    `;

    // 将拦截代码注入 HTML
    if (text.includes('</head>')) {
      text = text.replace('</head>', `${injection}</head>`);
    } else if (text.includes('<body>')) {
      text = text.replace('<body>', `<body>${injection}`);
    }
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

    this.handleSession(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }  

  async handleSession(connection) {    
    connection.accept();
    await this.cleanupOldConnections();

    const clientId = generateClientId();
    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection);
      return;
    }

    this.clients[clientId] = {
      connection: connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null
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
        // 如果当前客户端已经在一个活跃房间通道中，直接丢弃跨房/切房的 WebSocket 命令
        if (this.clients[clientId].channel && this.clients[clientId].channel !== targetChannel) {
           console.log(`拒绝用户 ${clientId} 室内窜房到: ${targetChannel}`);
           return;
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
