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
const userCache = new Map();

// ОПТИМИЗАЦИЯ EXPRESS
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        users: onlineUsers.size,
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

// Получение сообщений канала
app.get('/api/channels/:channelId/messages', (req, res) => {
    const channelId = req.params.channelId;
    db.all(`
        SELECT m.*, u.display_name, u.avatar_url 
        FROM messages m 
        LEFT JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? 
        ORDER BY m.created_at DESC
        LIMIT 100
    `, [channelId], (err, messages) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(messages.reverse());
    });
});

// Получение личных сообщений
app.get('/api/direct-messages/:fromUserId/:toUserId', (req, res) => {
    const { fromUserId, toUserId } = req.params;
    db.all(`
        SELECT dm.*, u.username as from_username, u.display_name as from_display_name, u.avatar_url as from_avatar
        FROM direct_messages dm
        LEFT JOIN users u ON dm.from_user = u.id
        WHERE (dm.from_user = ? AND dm.to_user = ?) OR (dm.from_user = ? AND dm.to_user = ?)
        ORDER BY dm.created_at DESC
        LIMIT 100
    `, [fromUserId, toUserId, toUserId, fromUserId], (err, messages) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(messages.reverse());
    });
});

// Удаление сообщения
app.delete('/api/messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    db.run("DELETE FROM messages WHERE id = ?", [messageId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
    });
});

// Удаление личного сообщения
app.delete('/api/direct-messages/:messageId', (req, res) => {
    const messageId = req.params.messageId;
    db.run("DELETE FROM direct_messages WHERE id = ?", [messageId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
    });
});

// Обновление профиля
app.post('/api/profile', (req, res) => {
    const { userId, displayName, avatar } = req.body;
    db.run("UPDATE users SET display_name = ?, avatar_url = ? WHERE id = ?", 
        [displayName, avatar, userId], 
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        }
    );
});

// Удаление пользователя (только для админов)
app.delete('/api/users/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // Проверяем права администратора (в реальном приложении нужно добавить аутентификацию)
    db.serialize(() => {
        // Удаляем сообщения пользователя
        db.run("DELETE FROM messages WHERE user_id = ?", [userId]);
        // Удаляем личные сообщения пользователя
        db.run("DELETE FROM direct_messages WHERE from_user = ? OR to_user = ?", [userId, userId]);
        // Удаляем пользователя
        db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        });
    });
});

// Обновление прав канала
app.post('/api/channels/:channelId/permissions', (req, res) => {
    const channelId = req.params.channelId;
    const { permissions } = req.body;
    
    db.run("UPDATE channels SET permissions = ? WHERE id = ?", 
        [JSON.stringify(permissions), channelId], 
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        }
    );
});

// Поиск пользователей
app.get('/api/users/search/:query', (req, res) => {
    const query = `%${req.params.query}%`;
    db.all("SELECT id, username, display_name, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 10", 
        [query, query], 
        (err, users) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(users);
        }
    );
});

// Получение всех пользователей для ЛС
app.get('/api/users/all', (req, res) => {
    db.all("SELECT id, username, display_name, avatar_url, is_admin FROM users ORDER BY username", 
        (err, users) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(users);
        }
    );
});

// 📦 ОПТИМИЗИРОВАННЫЕ ЗАПРОСЫ ДАННЫХ
app.get('/api/channels', (req, res) => {
    console.log('📦 Loading channels...');
    db.all("SELECT id, name, type, permissions FROM channels ORDER BY created_at", (err, channels) => {
        if (err) {
            console.error('❌ Channels DB error:', err);
            // Возвращаем пустой массив вместо ошибки
            return res.json([]);
        }
        console.log('✅ Channels loaded:', channels?.length || 0);
        res.json(channels || []);
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

// Удаление канала
app.delete('/api/channels/:channelId', (req, res) => {
    const channelId = req.params.channelId;
    db.serialize(() => {
        db.run("DELETE FROM messages WHERE channel_id = ?", [channelId]);
        db.run("DELETE FROM channels WHERE id = ?", [channelId], function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true });
        });
    });
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

    // Создание канала
   socket.on('create_channel', (data) => {
    console.log('📢 Creating channel:', data);
    
    db.run("INSERT INTO channels (name, type, created_by, permissions) VALUES (?, ?, ?, ?)",
        [data.name, data.type, data.createdBy, JSON.stringify(data.permissions || {read: true, write: true})],
        function(err) {
            if (err) {
                console.error('❌ Channel creation error:', err);
                socket.emit('channel_error', 'Failed to create channel');
                return;
            }
            console.log('✅ Channel created with ID:', this.lastID);
            const newChannel = {
                id: this.lastID,
                name: data.name,
                type: data.type,
                permissions: data.permissions || {read: true, write: true}
            };
            io.emit('channel_created', newChannel);
        }
    );
});

    // Обновление канала
    socket.on('update_channel', (data) => {
        db.run("UPDATE channels SET name = ? WHERE id = ?",
            [data.name, data.channelId],
            function(err) {
                if (err) {
                    console.error('Channel update error:', err);
                    return;
                }
                const updatedChannel = {
                    id: data.channelId,
                    name: data.name,
                    type: 'text'
                };
                io.emit('channel_updated', updatedChannel);
            }
        );
    });

    // 🚀 СУПЕР-БЫСТРАЯ ОТПРАВКА СООБЩЕНИЙ
    socket.on('send_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;

        // Проверяем права на запись в канал
        db.get("SELECT permissions FROM channels WHERE id = ?", [data.channelId], (err, channel) => {
            if (err || !channel) {
                socket.emit('message_error', 'Channel not found');
                return;
            }

            const permissions = typeof channel.permissions === 'string' 
                ? JSON.parse(channel.permissions) 
                : channel.permissions;

            if (!permissions.write) {
                socket.emit('message_error', 'No write permissions in this channel');
                return;
            }

            // МГНОВЕННОЕ ОТОБРАЖЕНИЕ
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
            
            // Мгновенная отправка всем
            io.emit('new_channel_message', tempMessage);

            // Асинхронное сохранение в базу
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

    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            onlineUsers.delete(socket.id);
            io.emit('online_users', Array.from(onlineUsers.values()));
        }
        console.log('🔌 User disconnected:', socket.id);
    });
});

// Health check роут
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        onlineUsers: onlineUsers.size
    });
});

// Главная страница
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 🚀 ЗАПУСК СЕРВЕРА
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Ultra-fast server running on port ${PORT}`);
    console.log(`💾 Database optimized for performance`);
    console.log(`⚡ Message delivery: INSTANT`);
});






