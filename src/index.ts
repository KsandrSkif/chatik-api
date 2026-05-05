// Worker: chatik-api
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
        const chatId = path.split('/')[3];
        response = await handleGetChat(chatId, request, env);
      }
      // Message routes
      else if (path.match(/^\/api\/chats\/\d+\/messages$/) && method === 'GET') {
        const chatId = path.split('/')[3];
        response = await handleGetMessages(chatId, request, env);
      } else if (path.match(/^\/api\/chats\/\d+\/messages$/) && method === 'POST') {
        const chatId = path.split('/')[3];
        response = await handleSendMessage(chatId, request, env);
      }
      // Read status
      else if (path.match(/^\/api\/messages\/\d+\/read$/) && method === 'POST') {
        const messageId = path.split('/')[3];
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

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'chatik-salt-2024');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken(userId) {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ 
    userId, 
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
  }));
  return `${header}.${payload}.signature`;
}

function verifyToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7);
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Date.now()) return null;
    return payload.userId;
  } catch {
    return null;
  }
}

// Auth handlers
async function handleRegister(request, env) {
  const { username, displayName, password } = await request.json();
  
  if (!username || !displayName || !password) {
    return jsonResponse({ error: 'Missing required fields' }, 400);
  }

  const passwordHash = await hashPassword(password);
  
  try {
    const result = await env.DB.prepare(
      `INSERT INTO users (username, display_name, password_hash) 
       VALUES (?, ?, ?) RETURNING id, username, display_name, created_at`
    ).bind(username, displayName, passwordHash).first();

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

  if (!user) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }

  const passwordHash = await hashPassword(password);
  if (user.password_hash !== passwordHash) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }

  // Update last seen
  await env.DB.prepare(
    'UPDATE users SET status = ?, last_seen = datetime("now") WHERE id = ?'
  ).bind('online', user.id).run();

  const token = generateToken(user.id);
  
  return jsonResponse({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name
    }
  });
}

// User handlers
async function handleGetMe(request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const user = await env.DB.prepare(
    'SELECT id, username, display_name, avatar_url, status, last_seen FROM users WHERE id = ?'
  ).bind(userId).first();

  return jsonResponse({ user });
}

async function handleSearchUsers(request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const url = new URL(request.url);
  const query = url.searchParams.get('q') || '';

  const users = await env.DB.prepare(
    `SELECT id, username, display_name, avatar_url, status 
     FROM users 
     WHERE username LIKE ? OR display_name LIKE ?
     LIMIT 20`
  ).bind(`%${query}%`, `%${query}%`).all();

  return jsonResponse({ users: users.results });
}

// Chat handlers
async function handleGetChats(request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const chats = await env.DB.prepare(
    `SELECT c.*, 
            (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id 
             AND m.id > COALESCE(
               (SELECT MAX(message_id) FROM message_reads mr 
                JOIN messages m2 ON mr.message_id = m2.id 
                WHERE m2.chat_id = c.id AND mr.user_id = ?), 0
             )) as unread_count,
            (SELECT content FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_time
     FROM chats c
     JOIN chat_members cm ON c.id = cm.chat_id
     WHERE cm.user_id = ?
     ORDER BY last_message_time DESC`
  ).bind(userId, userId).all();

  return jsonResponse({ chats: chats.results });
}

async function handleCreateChat(request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const { name, type, members } = await request.json();

  // Для приватных чатов проверяем, не существует ли уже чат с этими участниками
  if (type === 'private' && members && members.length === 2) {
    const existing = await env.DB.prepare(`
      SELECT c.id FROM chats c
      JOIN chat_members cm1 ON c.id = cm1.chat_id AND cm1.user_id = ?
      JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id = ?
      WHERE c.type = 'private'
    `).bind(members[0], members[1]).first();
    if (existing) {
      return jsonResponse({ success: true, chatId: existing.id }, 200);
    }
  }
  
  // Create chat
  const chat = await env.DB.prepare(
    'INSERT INTO chats (name, type, created_by) VALUES (?, ?, ?) RETURNING id'
  ).bind(name, type, userId).first();

  // Add members
  const allMembers = [...new Set([...members, userId])];
  for (const memberId of allMembers) {
    await env.DB.prepare(
      'INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)'
    ).bind(chat.id, memberId, memberId === userId ? 'admin' : 'member').run();
  }

  return jsonResponse({ success: true, chatId: chat.id }, 201);
}

async function handleGetChat(chatId, request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const chat = await env.DB.prepare(
    `SELECT c.*, 
            (SELECT json_group_array(json_object(
              'id', u.id, 'username', u.username, 'displayName', u.display_name,
              'avatarUrl', u.avatar_url, 'role', cm.role
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

// Message handlers
async function handleGetMessages(chatId, request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  // Verify membership
  const member = await env.DB.prepare(
    'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
  ).bind(chatId, userId).first();

  if (!member) return jsonResponse({ error: 'Access denied' }, 403);

  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit')) || 50;
  const offset = parseInt(url.searchParams.get('offset')) || 0;

  const messages = await env.DB.prepare(
    `SELECT m.*, 
            u.username as sender_username, 
            u.display_name as sender_display_name,
            EXISTS(SELECT 1 FROM message_reads WHERE message_id = m.id AND user_id = ?) as is_read
     FROM messages m
     JOIN users u ON m.sender_id = u.id
     WHERE m.chat_id = ?
     ORDER BY m.created_at DESC
     LIMIT ? OFFSET ?`
  ).bind(userId, chatId, limit, offset).all();

  return jsonResponse({ messages: messages.results.reverse() });
}

async function handleSendMessage(chatId, request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  const { content, type = 'text', replyTo } = await request.json();

  // Verify membership
  const member = await env.DB.prepare(
    'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?'
  ).bind(chatId, userId).first();

  if (!member) return jsonResponse({ error: 'Access denied' }, 403);

  const message = await env.DB.prepare(
    `INSERT INTO messages (chat_id, sender_id, content, type, reply_to) 
     VALUES (?, ?, ?, ?, ?) RETURNING *`
  ).bind(chatId, userId, content, type, replyTo || null).first();

  return jsonResponse({ success: true, message }, 201);
}

async function handleMarkRead(messageId, request, env) {
  const userId = verifyToken(request.headers.get('Authorization'));
  if (!userId) return jsonResponse({ error: 'Unauthorized' }, 401);

  await env.DB.prepare(
    `INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)`
  ).bind(messageId, userId).run();

  return jsonResponse({ success: true });
}
