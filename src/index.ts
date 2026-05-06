// Worker: chatik-api (исправленный)
// Деплой через Dashboard -> Workers & Pages -> Create application
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      let response;

      // Auth routes
      if (path === '/api/auth/register' && method === 'POST') {
        response = await handleRegister(request, env);
      } else if (path === '/api/auth/login' && method === 'POST') {
        response = await handleLogin(request, env);
      }
      // User routes
      else if (path === '/api/users/me' && method === 'GET') {
        response = await handleGetMe(request, env);
      } else if (path === '/api/users/search' && method === 'GET') {
        response = await handleSearchUsers(request, env);
      }
      // Chat routes
      else if (path === '/api/chats' && method === 'GET') {
        response = await handleGetChats(request, env);
      } else if (path === '/api/chats' && method === 'POST') {
        response = await handleCreateChat(request, env);
      } else if (path.match(/^\/api\/chats\/\d+$/) && method === 'GET') {
        const chatId = parseInt(path.split('/')[3]);
        response = await handleGetChat(chatId, request, env);
      } else if (path.match(/^\/api\/chats\/\d+\/read$/) && method === 'POST') {
        const chatId = parseInt(path.split('/')[4]);
        response = await handleReadAllMessages(chatId, request, env);
      }
      // Contacts
      else if (path === '/api/contacts' && method === 'GET') {
        response = await handleGetContacts(request, env);
      }
      // Message routes
      else if (path.match(/^\/api\/chats\/\d+\/messages$/) && method === 'GET') {
        const chatId = parseInt(path.split('/')[3]);
        response = await handleGetMessages(chatId, request, env);
      } else if (path.match(/^\/api\/chats\/\d+\/messages$/) && method === 'POST') {
        const chatId = parseInt(path.split('/')[3]);
        response = await handleSendMessage(chatId, request, env);
      }
      // Read status (single message)
      else if (path.match(/^\/api\/messages\/\d+\/read$/) && method === 'POST') {
        const messageId = parseInt(path.split('/')[3]);
        response = await handleMarkRead(messageId, request, env);
      }
      else {
        response = jsonResponse({ error: 'Not found' }, 404);
      }

      // Add CORS to response
      Object.entries(corsHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });
      return response;

    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ error: 'Internal server error', details: error.message }, 500, corsHeaders);
    }
  }
};

// Helper functions
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}

// Безопасное хэширование пароля через PBKDF2
async function hashPassword(password, env) {
  const encoder = new TextEncoder();
  const salt = encoder.encode(env.PASSWORD_SALT || 'chatik-salt-2024'); // Соль из переменной окружения
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100_000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// JWT с HMAC-SHA256
async function generateToken(userId, env) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    userId,
    exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60 // 30 дней
  };
  const headerB64 = btoa(JSON.stringify(header)).replace(/=+$/, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/=+$/, '');
  const signature = await sign(`${headerB64}.${payloadB64}`, env);
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=+$/, '');
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function verifyToken(authHeader, env) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7);
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const signatureBytes = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
    const isValid = await verifySignature(`${parts[0]}.${parts[1]}`, signatureBytes, env);
    if (!isValid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp * 1000 < Date.now()) return null;
    return payload.userId;
  } catch {
    return null;
  }
}

async function sign(data, env) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.JWT_SECRET || 'fallback-secret-change-me'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
}

async function verifySignature(data, signature, env) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.JWT_SECRET || 'fallback-secret-change-me'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(data));
}

// Auth handlers
async function handleRegister(request, env) {
  const { username, display_name, password } = await request.json();
  if (!username || !display_name || !password) {
    return jsonResponse({ error: 'Missing required fields' }, 400);
  }
  const passwordHash = await hashPassword(password, env);
  try {
    const result = await env.DB.prepare(
      `INSERT INTO users (username, display_name, password_hash) 
       VALUES (?, ?, ?) RETURNING id, username, display_name, created_at`
    ).bind(username, display_name, passwordHash).first();
    return jsonResponse({ success: true, user: result }, 201);
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return jsonResponse({ error: 'Username already exists' }, 409);
    }
    throw error;
  }
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  const user = await env.DB.prepare(
    'SELECT id, username, display_name, password_hash FROM users WHERE username = ?'
  ).bind(username).first();
  if (!user) return jsonResponse({ error: 'Invalid credentials' }, 401);
  const passwordHash = await hashPassword(password, env);
  if (user.password_hash !== passwordHash) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }
  await env.DB.prepare(
    'UPDATE users SET status = ?, last_seen = datetime("now") WHERE id = ?'
  ).bind('online', user.id).run();
  const token = await generateToken(user.id, env);
  return jsonResponse({
    success: true,
    token,
    user: { id: user.id, username: user.username, display_name: user.display_name }
  });
}

// User handlers
async function handleGetMe(request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const user = await env.DB.prepare(
    'SELECT id, username, display_name, avatar_url, status, last_seen FROM users WHERE id = ?'
  ).bind(userId).first();
  return jsonResponse({ user });
}

async function handleSearchUsers(request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const url = new URL(request.url);
  const query = url.searchParams.get('q') || '';
  const users = await env.DB.prepare(
    `SELECT id, username, display_name, avatar_url, status 
     FROM users 
     WHERE (username LIKE ? OR display_name LIKE ?) AND id != ?
     LIMIT 10`
  ).bind(`%${query}%`, `%${query}%`, userId).all();
  return jsonResponse({ users: users.results });
}

// Chat handlers (исправленный last_modified)
async function handleGetChats(request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const url = new URL(request.url);
  const since = parseInt(url.searchParams.get('since') || '0');

  let query = `SELECT c.id, c.name, c.type, c.avatar_url, 
                      c.last_message, c.last_message_at as last_message_time,
                      (SELECT COUNT(*) FROM messages m 
                       WHERE m.chat_id = c.id 
                         AND m.id NOT IN (SELECT mr.message_id FROM message_reads mr WHERE mr.user_id = ?)
                      ) as unread_count,
                      c.updated_at
               FROM chats c
               JOIN chat_members cm ON c.id = cm.chat_id
               WHERE cm.user_id = ?`;
  const params = [userId, userId];
  if (since > 0) {
    query += ` AND c.updated_at > datetime(?, 'unixepoch')`;
    params.push(since);
  }
  query += ` ORDER BY c.last_message_at DESC`;

  const result = await env.DB.prepare(query).bind(...params).all();
  const chats = result.results.map(c => ({
    id: c.id, name: c.name, type: c.type, avatar_url: c.avatar_url,
    last_message: c.last_message, last_message_time: c.last_message_time,
    unread_count: c.unread_count
  }));
  // Вычисляем максимальный updated_at среди вернувшихся чатов, или since, если ничего не изменилось
  const maxUpdated = result.results.reduce((max, c) => {
    const ts = Math.floor(new Date(c.updated_at + 'Z').getTime() / 1000);
    return Math.max(max, ts);
  }, since);
  return jsonResponse({ chats, last_modified: maxUpdated });
}

async function handleCreateChat(request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const { name, type, members } = await request.json();
  if (!type || !['private', 'group', 'channel'].includes(type)) {
    return jsonResponse({ error: 'Invalid chat type' }, 400);
  }

  if (type === 'private' && members && members.length === 2) {
    const existing = await env.DB.prepare(`
      SELECT c.id FROM chats c
      JOIN chat_members cm1 ON c.id = cm1.chat_id AND cm1.user_id = ?
      JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id = ?
      WHERE c.type = 'private'
    `).bind(members[0], members[1]).first();
    if (existing) return jsonResponse({ success: true, chatId: existing.id }, 200);
  }

  const chat = await env.DB.prepare(
    'INSERT INTO chats (name, type, created_by) VALUES (?, ?, ?) RETURNING id'
  ).bind(name, type, userId).first();

  const allMembers = [...new Set([...members, userId])];
  for (const memberId of allMembers) {
    await env.DB.prepare(
      'INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)'
    ).bind(chat.id, memberId, memberId === userId ? 'admin' : 'member').run();
  }
  return jsonResponse({ success: true, chatId: chat.id }, 201);
}

async function handleGetChat(chatId, request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const chat = await env.DB.prepare(
    `SELECT c.*, 
            (SELECT json_group_array(json_object(
              'id', u.id, 'username', u.username, 'display_name', u.display_name,
              'avatar_url', u.avatar_url, 'role', cm.role
            ))
             FROM chat_members cm
             JOIN users u ON cm.user_id = u.id
             WHERE cm.chat_id = c.id) as members
     FROM chats c
     JOIN chat_members cm ON c.id = cm.chat_id
     WHERE c.id = ? AND cm.user_id = ?`
  ).bind(chatId, userId).first();
  if (!chat) return jsonResponse({ error: 'Chat not found' }, 404);
  chat.members = JSON.parse(chat.members || '[]');
  return jsonResponse({ chat });
}

// Contacts (исправленный last_modified)
async function handleGetContacts(request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const url = new URL(request.url);
  const since = parseInt(url.searchParams.get('since') || '0');

  let query = `SELECT id, username, display_name, avatar_url, status, updated_at FROM users WHERE id != ?`;
  const params = [userId];
  if (since > 0) {
    query += ` AND updated_at > datetime(?, 'unixepoch')`;
    params.push(since);
  }
  query += ` ORDER BY display_name`;
  const result = await env.DB.prepare(query).bind(...params).all();
  const users = result.results.map(u => ({
    id: u.id, username: u.username, display_name: u.display_name,
    avatar_url: u.avatar_url, status: u.status
  }));
  const maxUpdated = result.results.reduce((max, u) => {
    const ts = Math.floor(new Date(u.updated_at + 'Z').getTime() / 1000);
    return Math.max(max, ts);
  }, since);
  return jsonResponse({ users, last_modified: maxUpdated });
}

// Message handlers (исправленный since + пагинация с before)
async function handleGetMessages(chatId, request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const member = await env.DB.prepare(
    'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
  ).bind(chatId, userId).first();
  if (!member) return jsonResponse({ error: 'Access denied' }, 403);

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
  const since = parseInt(url.searchParams.get('since') || '0');
  const before = url.searchParams.get('before'); // id сообщения, загрузить старше него

  let query = `SELECT m.*, u.username as sender_username, u.display_name as sender_display_name,
                      CASE WHEN mr.user_id IS NOT NULL THEN 1 ELSE 0 END as is_read
               FROM messages m
               JOIN users u ON m.sender_id = u.id
               LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id = ?
               WHERE m.chat_id = ?`;
  const params = [userId, chatId];

  if (before) {
    query += ` AND m.id < ?`;
    params.push(parseInt(before));
  } else if (since > 0) {
    query += ` AND m.created_at > datetime(?, 'unixepoch')`;
    params.push(since);
  }

  query += ` ORDER BY m.created_at DESC LIMIT ?`;
  params.push(limit);

  const result = await env.DB.prepare(query).bind(...params).all();
  // Возвращаем в прямом порядке
  const messages = result.results.reverse();
  // last_modified: максимум created_at среди возвращённых, или since
  const maxCreated = messages.reduce((max, m) => {
    const ts = Math.floor(new Date(m.created_at + 'Z').getTime() / 1000);
    return Math.max(max, ts);
  }, since);
  return jsonResponse({ messages, last_modified: maxCreated });
}

async function handleSendMessage(chatId, request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  const { content, type = 'text', reply_to } = await request.json();

  const member = await env.DB.prepare(
    'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
  ).bind(chatId, userId).first();
  if (!member) return jsonResponse({ error: 'Access denied' }, 403);

  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const message = await env.DB.prepare(
    `INSERT INTO messages (chat_id, sender_id, content, type, reply_to, created_at, updated_at) 
     VALUES (?, ?, ?, ?, ?, datetime(?), datetime(?)) RETURNING *`
  ).bind(chatId, userId, content, type, reply_to || null, now, now).first();

  await env.DB.prepare(
    `UPDATE chats SET last_message = ?, last_message_at = datetime(?), updated_at = datetime(?) WHERE id = ?`
  ).bind(content, now, now, chatId).run();

  // Увеличиваем unread_count всем, кроме отправителя
  await env.DB.prepare(
    `UPDATE chats SET unread_count = unread_count + 1 WHERE id = ? AND id IN (
       SELECT chat_id FROM chat_members WHERE chat_id = ? AND user_id != ?)`
  ).bind(chatId, chatId, userId).run();

  return jsonResponse({ success: true, message }, 201);
}

async function handleMarkRead(messageId, request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);
  await env.DB.prepare(
    `INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)`
  ).bind(messageId, userId).run();

  const chatRow = await env.DB.prepare(`SELECT chat_id FROM messages WHERE id = ?`).bind(messageId).first();
  if (chatRow) {
    await env.DB.prepare(
      `UPDATE chats SET unread_count = MAX(0, unread_count - 1) WHERE id = ?`
    ).bind(chatRow.chat_id).run();
  }
  return jsonResponse({ success: true });
}

// Новый endpoint: отметить все сообщения чата прочитанными для пользователя
async function handleReadAllMessages(chatId, request, env) {
  const userId = await verifyToken(request.headers.get('Authorization'), env);
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  // Получаем все сообщения чата, у которых нет записи в message_reads для этого пользователя
  const unread = await env.DB.prepare(
    `SELECT m.id FROM messages m
     WHERE m.chat_id = ? AND m.id NOT IN (
       SELECT message_id FROM message_reads WHERE user_id = ?
     )`
  ).bind(chatId, userId).all();

  if (unread.results.length > 0) {
    const stmt = env.DB.prepare(`INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)`);
    const batch = unread.results.map(r => stmt.bind(r.id, userId));
    await env.DB.batch(batch);
    await env.DB.prepare(
      `UPDATE chats SET unread_count = 0 WHERE id = ?`
    ).bind(chatId).run();
  }
  return jsonResponse({ success: true });
}