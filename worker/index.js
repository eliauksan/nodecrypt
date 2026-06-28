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
      // 这里的资源也需要经过文本替换，防止直接进房间链接时没换掉字
      const response = await env.ASSETS.fetch(request);
      return handleTextReplacement(response);
    }

    // =================【第三步：精准拦截首页根目录（看门人守卫逻辑）】=================
    if (url.pathname === '/') {
      const cookieHeader = request.headers.get('Cookie') || '';
      
      // 检查 A：URL 后面带着固定暗号 kamiko
      if (url.searchParams.get('create') === 'kamiko') {
        const response = await env.ASSETS.fetch(request);
        // 执行文本替换
        const replacedResponse = await handleTextReplacement(response);
        const newResponse = new Response(replacedResponse.body, replacedResponse);
        // 埋下通行证
        newResponse.headers.append('Set-Cookie', 'chat_auth=kamiko; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax');
        return newResponse;
      }

      // 检查 B：浏览器里已经有通行证（Cookie）了，直接放行首页
      if (cookieHeader.includes('chat_auth=kamiko')) {
        const response = await env.ASSETS.fetch(request);
        return handleTextReplacement(response);
      }

      // 检查 C：既没有暗号也没有 Cookie，直接拦截返回 403
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
    // 只对 HTML 和 JS 静态文件做可能的文本替换
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('text/html') || contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      return handleTextReplacement(response);
    }
    return response;
  }
};

// 💡【核心动态文本替换函数】
async function handleTextReplacement(response) {
  if (!response.ok) return response;
  
  let text = await response.text();

  // 1. 替换网页顶部或标签页标题中的 NodeCrypt 为 阅后即焚
  text = text.replace(/NodeCrypt/g, '阅后即焚');
  text = text.replace(/nodecrypt/g, '阅后即焚');

  // 2. 替换页脚的 Powered by 阅后即焚 (刚才上一步已经把NodeCrypt换成阅后即焚了，所以这里匹配 阅后即焚)
  // 如果前端写的是 Powered by NodeCrypt，会被转换为 Powered by 阅后即焚

  // 3. 将末尾的 @shuaieplus 更改为 爆改自@shuaieplus
  text = text.replace(/@shuaieplus/g, '爆改自@shuaieplus');

  // 重新构建响应返回给浏览器
  const newHeaders = new Headers(response.headers);
  newHeaders.delete('Content-Length'); // 文本长度变了，必须删掉让 Cloudflare 重新计算

  return new Response(text, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

// =================【以下为您原本完整的 ChatRoom Durable Object 逻辑，完好无损】=================
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
        console.log('Generating new RSA keypair...');
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
        console.log('RSA key pair generated and stored');
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
      
      if (stored.createdAt && (Date.now() - stored.createdAt > 24 * 60 * 60 * 1000)) {
        if (Object.keys(this.clients).length === 0) {
          console.log('密钥已使用24小时，进行轮换...');
          await this.state.storage.delete('rsaKeyPair');
          this.keyPair = null;
          await this.initRSAKeyPair();
        } else {
          await this.state.storage.put('pendingKeyRotation', true);
        }
      }
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
      throw error;
    }
  }

  async fetch(request) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const url = new URL(request.url);
    
    const isAuthorized = cookieHeader.includes('chat_auth=kamiko') || url.searchParams.get('create') === 'kamiko';
    
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    this.handleSession(server, isAuthorized);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }  

  async handleSession(connection, isAuthorized) {    
    connection.accept();
    await this.cleanupOldConnections();

    const clientId = generateClientId();

    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection);
      return;
    }

    logEvent('connection', clientId, 'debug');    
    this.clients[clientId] = {
      connection: connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null,
      isAuthorized: isAuthorized
    };

    try {
      logEvent('sending-public-key', clientId, 'debug');
      this.sendMessage(connection, JSON.stringify({
        type: 'server-key',
        key: this.keyPair.rsaPublic
      }));
    } catch (error) {
      logEvent('sending-public-key', error, 'error');
    }    

    connection.addEventListener('message', async (event) => {
      const message = event.data;

      if (!isString(message) || !this.clients[clientId]) {
        return;
      }

      this.clients[clientId].seen = getTime();

      if (message === 'ping') {
        this.sendMessage(connection, 'pong');
        return;
      }

      logEvent('message', [clientId, message], 'debug');      
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
          logEvent('message-key', [clientId, error], 'error');
          this.closeConnection(connection);
        }

        return;
      }

      if (this.clients[clientId].shared && message.length <= (8 * 1024 * 1024)) {
        this.processEncryptedMessage(clientId, message);
      }
    });    

    connection.addEventListener('close', async (event) => {
      logEvent('close', [clientId, event], 'debug');

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
                  p: members.filter((value) => {
                    return (value !== member ? true : false);
                  })
                }, client.shared));
              }
            }

          } catch (error) {
            logEvent('close-list', [clientId, error], 'error');
          }
        }
      }

      if (this.clients[clientId]) {
        delete(this.clients[clientId]);
      }
    });
  }

  processEncryptedMessage(clientId, message) {
    let decrypted = null;

    try {
      decrypted = decryptMessage(message, this.clients[clientId].shared);

      logEvent('message-decrypted', [clientId, decrypted], 'debug');

      if (!isObject(decrypted) || !isString(decrypted.a)) {
        return;
      }

      const action = decrypted.a;

      if (action === 'j') {
        if (!this.clients[clientId].isAuthorized) {
          console.log(`已拦截未授权的用户 ${clientId} 尝试创建/进入新房`);
          this.closeConnection(this.clients[clientId].connection);
          return;
        }
        this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        this.handleChannelMessage(clientId, decrypted);
      }

    } catch (error) {
      logEvent('process-encrypted-message', [clientId, error], 'error');
    } finally {
      decrypted = null;
    }
  }

  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = decrypted.p;

      this.clients[clientId].channel = channel;

      if (!this.channels[channel]) {
        this.channels[channel] = [clientId];
      } else {
        this.channels[channel].push(clientId);
      }

      this.broadcastMemberList(channel);

    } catch (error) {
      logEvent('message-join', [clientId, error], 'error');
    }
  }

  handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = this.clients[clientId].channel;
      const targetClient = this.clients[decrypted.c];

      if (this.isClientInChannel(targetClient, channel)) {
        const messageObj = {
          a: 'c',
          p: decrypted.p,
          c: clientId
        };

        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-client', [clientId, error], 'error');
    }
  }  

  handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) {
      return;
    }
    
    try {
      const channel = this.clients[clientId].channel;
      const validMembers = Object.keys(decrypted.p).filter(member => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });

      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const messageObj = {
          a: 'c',
          p: decrypted.p[member],
          c: clientId
        };        
        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-channel', [clientId, error], 'error');
    }
  }

  broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];

      for (const member of members) {
        const client = this.clients[member];

        if (this.isClientInChannel(client, channel)) {
          const messageObj = {
            a: 'l',
            p: members.filter((value) => {
              return (value !== member ? true : false);
            })
          };

          const encrypted = encryptMessage(messageObj, client.shared);
          this.sendMessage(client.connection, encrypted);

          messageObj.p = null;
        }
      }
    } catch (error) {
      logEvent('broadcast-member-list', error, 'error');
    }
  }  

  isClientInChannel(client, channel) {
    return (
      client &&
      client.connection &&
      client.shared &&
      client.channel &&
      client.channel === channel ?
      true :
      false
    );
  }

  sendMessage(connection, message) {
    try {
      if (connection.readyState === 1) {
        connection.send(message);
      }
    } catch (error) {
      logEvent('sendMessage', error, 'error');
    }
  }  

  closeConnection(connection) {
    try {
      connection.close();    
    } catch (error) {
      logEvent('closeConnection', error, 'error');
    }
  }
  
  async cleanupOldConnections() {
    const seenThreshold = getTime() - this.config.seenTimeout;
    const clientsToRemove = [];

    for (const clientId in this.clients) {
      if (this.clients[clientId].seen < seenThreshold) {
        clientsToRemove.push(clientId);
      }
    }

    for (const clientId of clientsToRemove) {
      try {
        logEvent('connection-seen', clientId, 'debug');
        this.clients[clientId].connection.close();
        delete this.clients[clientId];
      } catch (error) {
        logEvent('connection-seen', error, 'error');      
      }
    }
    
    if (Object.keys(this.clients).length === 0 && Object.keys(this.channels).length === 0) {
      const pendingRotation = await this.state.storage.get('pendingKeyRotation');
      if (pendingRotation) {
        console.log('没有活跃客户端或房间，执行密钥轮换...');
        await this.state.storage.delete('rsaKeyPair');        
        await this.state.storage.delete('pendingKeyRotation');
        this.keyPair = null;
        await this.initRSAKeyPair();
      }
    }
    
    return clientsToRemove.length;
  }
}
