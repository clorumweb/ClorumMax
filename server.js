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

// ОПТИМИЗАЦИЯ EXPRESS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// Health check для мониторинга
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        users: onlineUsers.size,
        uptime: process.uptime()
    });
});

// 📦 ОСНОВНЫЕ API РОУТЫ

// Регистрация
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

// Вход
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
        
        const isValid = await simpleHash.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Invalid credentials' });
        
        res.json({ 
            success: true, 
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name || user.username,
                avatar: user.avatar_url,
                isAdmin: user.is_admin === 1
            }
        });
    });
});

// 📦 API ДЛЯ ДАННЫХ

// Каналы
app.get('/api/channels', (req, res) => {
    db.all("SELECT id, name, type FROM channels ORDER BY created_at", (err, channels) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(channels);
    });
});

// Все пользователи
app.get('/api/users/all', (req, res) => {
    db.all("SELECT id, username, display_name, avatar_url, is_admin FROM users ORDER BY username", 
        (err, users) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(users);
        }
    );
});

// Сообщения канала
app.get('/api/channels/:channelId/messages', (req, res) => {
    const channelId = req.params.channelId;
    
    db.all(`
        SELECT m.*, u.username, u.display_name, u.avatar_url 
        FROM messages m 
        LEFT JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? 
        ORDER BY m.created_at ASC
    `, [channelId], (err, messages) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(messages);
    });
});

// Личные сообщения
app.get('/api/direct-messages/:fromUserId/:toUserId', (req, res) => {
    const { fromUserId, toUserId } = req.params;
    
    db.all(`
        SELECT dm.*, 
               u1.username as from_username, u1.display_name as from_display_name, u1.avatar_url as from_avatar
        FROM direct_messages dm
        LEFT JOIN users u1 ON dm.from_user = u1.id
        WHERE (dm.from_user = ? AND dm.to_user = ?) OR (dm.from_user = ? AND dm.to_user = ?)
        ORDER BY dm.created_at ASC
    `, [fromUserId, toUserId, toUserId, fromUserId], (err, messages) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(messages);
    });
});

// Поиск пользователей
app.get('/api/users/search/:query', (req, res) => {
    const query = req.params.query;
    db.all(
        "SELECT id, username, display_name, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY username",
        [`%${query}%`, `%${query}%`],
        (err, users) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(users);
        }
    );
});

// Обновление профиля
app.post('/api/profile', (req, res) => {
    const { userId, displayName, avatar } = req.body;
    
    db.run(
        "UPDATE users SET display_name = ?, avatar_url = ? WHERE id = ?",
        [displayName, avatar, userId],
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        }
    );
});

// Удаление сообщений
app.delete('/api/messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    
    db.run("DELETE FROM messages WHERE id = ?", [messageId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
    });
});

// Удаление личных сообщений
app.delete('/api/direct-messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    
    db.run("DELETE FROM direct_messages WHERE id = ?", [messageId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
    });
});

// Удаление канала
app.delete('/api/channels/:channelId', (req, res) => {
    const channelId = req.params.channelId;
    
    db.run("DELETE FROM channels WHERE id = ?", [channelId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
    });
});

// Обновление прав канала
app.post('/api/channels/:channelId/permissions', (req, res) => {
    const channelId = req.params.channelId;
    const { permissions } = req.body;
    
    db.run(
        "UPDATE channels SET permissions = ? WHERE id = ?",
        [JSON.stringify(permissions), channelId],
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        }
    );
});

// Удаление пользователя
app.delete('/api/users/:userId', (req, res) => {
    const userId = req.params.userId;
    
    db.serialize(() => {
        db.run("DELETE FROM messages WHERE user_id = ?", [userId]);
        db.run("DELETE FROM direct_messages WHERE from_user = ? OR to_user = ?", [userId, userId]);
        db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        });
    });
});

// ⚡ WEBSOCKET ОБРАБОТЧИКИ

io.on('connection', (socket) => {
    console.log('🔗 User connected:', socket.id);

    // Пользователь онлайн
    socket.on('user_online', (userData) => {
        onlineUsers.set(socket.id, {
            id: userData.id,
            username: userData.username,
            displayName: userData.displayName,
            avatar: userData.avatar,
            isAdmin: userData.isAdmin,
            socketId: socket.id
        });
        
        io.emit('online_users', Array.from(onlineUsers.values()));
    });

    // СОЗДАНИЕ КАНАЛА - ПРОСТАЯ ВЕРСИЯ
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
        
        const channelName = data.name ? data.name.trim() : '';
        if (!channelName) {
            socket.emit('channel_error', 'Channel name is required');
            return;
        }

        // ПРОСТОЙ ЗАПРОС
        db.run(
            "INSERT INTO channels (name, type) VALUES (?, ?)",
            [channelName, 'text'],
            function(err) {
                if (err) {
                    console.error('❌ Channel creation error:', err);
                    if (err.message && err.message.includes('UNIQUE')) {
                        socket.emit('channel_error', 'Channel name already exists');
                    } else {
                        socket.emit('channel_error', 'Database error');
                    }
                    return;
                }
                
                // УСПЕХ
                const newChannel = {
                    id: this.lastID,
                    name: channelName,
                    type: 'text'
                };
                
                console.log('✅ Channel created:', newChannel);
                socket.emit('channel_created', newChannel);
                io.emit('new_channel', newChannel);
            }
        );
    });

    // Отправка сообщения в канал
    socket.on('send_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;

        const tempMessage = {
            id: Date.now(),
            channel_id: data.channelId,
            user_id: user.id,
            username: user.username,
            display_name: user.displayName,
            avatar_url: user.avatar,
            content: data.content,
            created_at: new Date().toISOString(),
            temp: true
        };
        
        io.emit('new_channel_message', tempMessage);

        setTimeout(() => {
            db.run(
                "INSERT INTO messages (channel_id, user_id, username, content) VALUES (?, ?, ?, ?)",
                [data.channelId, user.id, user.username, data.content],
                function(err) {
                    if (err) {
                        console.error('Save error:', err);
                        socket.emit('message_error', 'Failed to save');
                        return;
                    }
                    
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

    // Отправка личного сообщения
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

        socket.emit('new_direct_message', tempMessage);
        
        const recipient = Array.from(onlineUsers.values()).find(u => u.id === data.toUserId);
        if (recipient) {
            io.to(recipient.socketId).emit('new_direct_message', tempMessage);
        }

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

    // Обновление канала
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
                
                db.get("SELECT * FROM channels WHERE id = ?", [data.channelId], (err, channel) => {
                    if (err || !channel) return;
                    
                    const updatedChannel = {
                        id: channel.id,
                        name: channel.name,
                        type: channel.type
                    };
                    
                    socket.emit('channel_updated', updatedChannel);
                    io.emit('channel_updated', updatedChannel);
                });
            }
        );
    });

    // Отключение
    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            onlineUsers.delete(socket.id);
            io.emit('online_users', Array.from(onlineUsers.values()));
        }
        console.log('🔌 User disconnected:', socket.id);
    });
});

// 📋 SERVING INDEX.HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 🚀 ЗАПУСК СЕРВЕРА
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
