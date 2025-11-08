const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const { db, simpleHash } = require('./database.js');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    pingTimeout: 60000,
    pingInterval: 25000,
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// КЭШ ДЛЯ МГНОВЕННОГО ОТОБРАЖЕНИЯ
const onlineUsers = new Map();
const messageCache = new Map(); // Кэш последних сообщений
const userCache = new Map(); // Кэш данных пользователей

// ОПТИМИЗАЦИЯ EXPRESS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Health check для мониторинга
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        users: onlineUsers.size,
        memory: process.memoryUsage(),
        uptime: process.uptime()
    });
});

// 📦 ОПТИМИЗИРОВАННЫЕ API РОУТЫ

// Быстрая регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password || username.length < 3 || password.length < 6) {
            return res.status(400).json({ error: 'Invalid data' });
        }
        
        db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            if (row) return res.status(400).json({ error: 'User exists' });
            
            const hashedPassword = await simpleHash.hash(password);
            db.run("INSERT INTO users (username, display_name, password) VALUES (?, ?, ?)",
                [username, username, hashedPassword],
                function(err) {
                    if (err) return res.status(500).json({ error: 'Create error' });
                    res.json({ success: true, userId: this.lastID });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Быстрый вход
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
        
        const isValid = await simpleHash.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Invalid credentials' });
        
        // Кэшируем пользователя
        userCache.set(user.id, {
            id: user.id,
            username: user.username,
            displayName: user.display_name || user.username,
            avatar: user.avatar_url,
            isAdmin: user.is_admin === 1
        });
        
        res.json({ success: true, user: userCache.get(user.id) });
    });
});

// 📦 ОПТИМИЗИРОВАННЫЕ ЗАПРОСЫ ДАННЫХ
app.get('/api/channels', (req, res) => {
    db.all("SELECT id, name, type FROM channels ORDER BY created_at", (err, channels) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(channels);
    });
});

app.get('/api/users', (req, res) => {
    db.all("SELECT id, username, display_name, avatar_url, is_admin FROM users ORDER BY username", 
        (err, users) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(users);
        }
    );
});

// 📋 ДОПОЛНИТЕЛЬНЫЕ API МАРШРУТЫ
app.get('/api/users/all', (req, res) => {
    db.all("SELECT id, username, display_name, avatar_url, is_admin FROM users ORDER BY username", 
        (err, users) => {
            if (err) {
                console.error('❌ Users fetch error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(users);
        }
    );
});

app.get('/api/users/search/:query', (req, res) => {
    const query = req.params.query;
    db.all(
        "SELECT id, username, display_name, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY username",
        [`%${query}%`, `%${query}%`],
        (err, users) => {
            if (err) {
                console.error('❌ User search error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(users);
        }
    );
});

app.get('/api/channels/:channelId/messages', (req, res) => {
    const channelId = req.params.channelId;
    
    db.all(`
        SELECT m.*, u.username, u.display_name, u.avatar_url 
        FROM messages m 
        LEFT JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? 
        ORDER BY m.created_at ASC
    `, [channelId], (err, messages) => {
        if (err) {
            console.error('❌ Messages fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(messages);
    });
});

app.get('/api/direct-messages/:fromUserId/:toUserId', (req, res) => {
    const { fromUserId, toUserId } = req.params;
    
    db.all(`
        SELECT dm.*, 
               u1.username as from_username, u1.display_name as from_display_name, u1.avatar_url as from_avatar,
               u2.username as to_username, u2.display_name as to_display_name, u2.avatar_url as to_avatar
        FROM direct_messages dm
        LEFT JOIN users u1 ON dm.from_user = u1.id
        LEFT JOIN users u2 ON dm.to_user = u2.id
        WHERE (dm.from_user = ? AND dm.to_user = ?) OR (dm.from_user = ? AND dm.to_user = ?)
        ORDER BY dm.created_at ASC
    `, [fromUserId, toUserId, toUserId, fromUserId], (err, messages) => {
        if (err) {
            console.error('❌ DM fetch error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(messages);
    });
});

app.post('/api/profile', (req, res) => {
    const { userId, displayName, avatar } = req.body;
    
    db.run(
        "UPDATE users SET display_name = ?, avatar_url = ? WHERE id = ?",
        [displayName, avatar, userId],
        function(err) {
            if (err) {
                console.error('❌ Profile update error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

app.delete('/api/messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    
    db.run("DELETE FROM messages WHERE id = ?", [messageId], function(err) {
        if (err) {
            console.error('❌ Message delete error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ success: true });
    });
});

app.delete('/api/direct-messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    
    db.run("DELETE FROM direct_messages WHERE id = ?", [messageId], function(err) {
        if (err) {
            console.error('❌ DM delete error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ success: true });
    });
});

app.delete('/api/channels/:channelId', (req, res) => {
    const channelId = req.params.channelId;
    
    db.run("DELETE FROM channels WHERE id = ?", [channelId], function(err) {
        if (err) {
            console.error('❌ Channel delete error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ success: true });
    });
});

app.post('/api/channels/:channelId/permissions', (req, res) => {
    const channelId = req.params.channelId;
    const { permissions } = req.body;
    
    db.run(
        "UPDATE channels SET permissions = ? WHERE id = ?",
        [JSON.stringify(permissions), channelId],
        function(err) {
            if (err) {
                console.error('❌ Permissions update error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

app.delete('/api/users/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // Удаляем пользователя и все его сообщения
    db.serialize(() => {
        db.run("DELETE FROM messages WHERE user_id = ?", [userId]);
        db.run("DELETE FROM direct_messages WHERE from_user = ? OR to_user = ?", [userId, userId]);
        db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
            if (err) {
                console.error('❌ User delete error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        });
    });
});

// 📋 SERVING INDEX.HTML ДЛЯ SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ⚡ ОПТИМИЗИРОВАННЫЕ WebSocket ОБРАБОТЧИКИ

io.on('connection', (socket) => {
    console.log('🔗 User connected:', socket.id);

    socket.on('user_online', (userData) => {
        onlineUsers.set(socket.id, {
            id: userData.id,
            username: userData.username,
            displayName: userData.displayName,
            avatar: userData.avatar,
            isAdmin: userData.isAdmin,
            socketId: socket.id
        });
        
        // Мгновенное обновление списка онлайн
        io.emit('online_users', Array.from(onlineUsers.values()));
    });

    // 🚀 СУПЕР-БЫСТРАЯ ОТПРАВКА СООБЩЕНИЙ
    socket.on('send_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;

        // МГНОВЕННОЕ ОТОБРАЖЕНИЕ (не ждем базу)
        const tempMessage = {
            id: Date.now(), // временный ID
            channel_id: data.channelId,
            user_id: user.id,
            username: user.username,
            display_name: user.displayName,
            avatar_url: user.avatar,
            content: data.content,
            created_at: new Date().toISOString(),
            temp: true // маркер временного сообщения
        };
        
        // Мгновенная отправка всем
        io.emit('new_channel_message', tempMessage);

        // Асинхронное сохранение в базу (без блокировки)
        setTimeout(() => {
            db.run(
                "INSERT INTO messages (channel_id, user_id, username, content) VALUES (?, ?, ?, ?)",
                [data.channelId, user.id, user.username, data.content],
                function(err) {
                    if (err) {
                        console.error('Save error:', err);
                        // Можно отправить ошибку обратно
                        socket.emit('message_error', 'Failed to save');
                        return;
                    }
                    
                    // Заменяем временное сообщение на постоянное
                    const realMessage = {
                        ...tempMessage,
                        id: this.lastID,
                        temp: false
                    };
                    
                    io.emit('message_updated', realMessage);
                }
            );
        }, 50);
    });
	
    // 🚀 СОЗДАНИЕ КАНАЛА
    socket.on('create_channel', (data) => {
        console.log('📝 Creating channel:', data);
        const user = onlineUsers.get(socket.id);
        
        if (!user) {
            socket.emit('channel_error', 'User not authenticated');
            return;
        }
        
        if (!user.isAdmin) {
            socket.emit('channel_error', 'Only admins can create channels');
            return;
        }
        
        if (!data.name || data.name.trim().length === 0) {
            socket.emit('channel_error', 'Channel name is required');
            return;
        }

        // Создаем канал в базе данных
        db.run(
            "INSERT INTO channels (name, type, created_by, permissions) VALUES (?, ?, ?, ?)",
            [data.name.trim(), data.type || 'text', user.id, JSON.stringify(data.permissions || { read: true, write: true })],
            function(err) {
                if (err) {
                    console.error('❌ Channel creation error:', err);
                    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                        socket.emit('channel_error', 'Channel name already exists');
                    } else {
                        socket.emit('channel_error', 'Database error');
                    }
                    return;
                }
                
                // Возвращаем созданный канал
                const newChannel = {
                    id: this.lastID,
                    name: data.name.trim(),
                    type: data.type || 'text',
                    created_by: user.id,
                    permissions: data.permissions || { read: true, write: true }
                };
                
                console.log('✅ Channel created:', newChannel);
                socket.emit('channel_created', newChannel);
                
                // Уведомляем всех пользователей о новом канале
                io.emit('new_channel', newChannel);
            }
        );
    });

    // ✏️ ОБНОВЛЕНИЕ КАНАЛА
    socket.on('update_channel', (data) => {
        const user = onlineUsers.get(socket.id);
        
        if (!user || !user.isAdmin) {
            socket.emit('channel_error', 'No permission');
            return;
        }
        
        db.run(
            "UPDATE channels SET name = ? WHERE id = ?",
            [data.name, data.channelId],
            function(err) {
                if (err) {
                    socket.emit('channel_error', 'Update failed');
                    return;
                }
                
                // Получаем обновленный канал
                db.get("SELECT * FROM channels WHERE id = ?", [data.channelId], (err, channel) => {
                    if (err || !channel) return;
                    
                    const updatedChannel = {
                        id: channel.id,
                        name: channel.name,
                        type: channel.type,
                        permissions: typeof channel.permissions === 'string' 
                            ? JSON.parse(channel.permissions) 
                            : channel.permissions
                    };
                    
                    socket.emit('channel_updated', updatedChannel);
                    io.emit('channel_updated', updatedChannel);
                });
            }
        );
    });

    // 📢 УВЕДОМЛЕНИЕ О НОВОМ КАНАЛЕ
    socket.on('new_channel', (channel) => {
        console.log('🆕 New channel notification:', channel);
    });
	

    // 🚀 БЫСТРАЯ ОТПРАВКА ЛИЧНЫХ СООБЩЕНИЙ
    socket.on('send_direct_message', (data) => {
        const fromUser = onlineUsers.get(socket.id);
        if (!fromUser) return;

        const tempMessage = {
            id: Date.now(),
            from_user: fromUser.id,
            to_user: data.toUserId,
            from_username: fromUser.username,
            from_display_name: fromUser.displayName,
            from_avatar: fromUser.avatar,
            content: data.content,
            created_at: new Date().toISOString(),
            temp: true
        };

        // Мгновенная отправка
        socket.emit('new_direct_message', tempMessage);
        
        const recipient = Array.from(onlineUsers.values()).find(u => u.id === data.toUserId);
        if (recipient) {
            io.to(recipient.socketId).emit('new_direct_message', tempMessage);
        }

        // Асинхронное сохранение
        setTimeout(() => {
            db.run(
                "INSERT INTO direct_messages (from_user, to_user, content) VALUES (?, ?, ?)",
                [fromUser.id, data.toUserId, data.content],
                function(err) {
                    if (err) {
                        console.error('DM save error:', err);
                        return;
                    }
                    
                    const realMessage = {
                        ...tempMessage,
                        id: this.lastID,
                        temp: false
                    };
                    
                    socket.emit('dm_updated', realMessage);
                    if (recipient) {
                        io.to(recipient.socketId).emit('dm_updated', realMessage);
                    }
                }
            );
        }, 50);
    });

    // 📞 ОБРАБОТЧИКИ ЗВОНКОВ (остаются быстрыми)
    socket.on('start_call', (data) => {
        const fromUser = onlineUsers.get(socket.id);
        const recipient = Array.from(onlineUsers.values()).find(u => u.id === data.toUserId);
            
        if (recipient) {
            io.to(recipient.socketId).emit('incoming_call', {
                from: socket.id,
                fromUserId: fromUser.id,
                fromUsername: fromUser.username,
                fromDisplayName: fromUser.displayName,
                type: data.type
            });
        }
    });

    socket.on('accept_call', (data) => {
        io.to(data.from).emit('call_accepted', { to: socket.id });
    });

    socket.on('end_call', (data) => {
        io.to(data.to).emit('call_ended');
    });

    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            onlineUsers.delete(socket.id);
            io.emit('online_users', Array.from(onlineUsers.values()));
        }
        console.log('🔌 User disconnected:', socket.id);
    });
});

// 🚀 ЗАПУСК СЕРВЕРА
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Ultra-fast server running on port ${PORT}`);
    console.log(`💾 Database optimized for performance`);
    console.log(`⚡ Message delivery: INSTANT`);
});
