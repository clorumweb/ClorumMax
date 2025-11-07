const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const { db, simpleHash } = require('./database.js');

const app = express();
const server = http.createServer(app);

// ОДНО объявление io - удалите другие объявления если есть
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const onlineUsers = new Map();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Юзернейм должен быть не менее 3 символов' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }
    
    try {
        db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка базы данных' });
            }
            
            if (row) {
                return res.status(400).json({ error: 'Юзернейм уже занят' });
            }
            
            const hashedPassword = await simpleHash.hash(password);
            db.run(
                "INSERT INTO users (username, display_name, password) VALUES (?, ?, ?)",
                [username, username, hashedPassword],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка при создании пользователя' });
                    }
                    
                    res.json({ 
                        success: true, 
                        message: 'Регистрация успешна',
                        userId: this.lastID 
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    
    db.get(
        "SELECT * FROM users WHERE username = ?", 
        [username],
        async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка базы данных' });
            }
            
            if (!user) {
                return res.status(400).json({ error: 'Неверный логин или пароль' });
            }
            
            const isValidPassword = await simpleHash.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(400).json({ error: 'Неверный логин или пароль' });
            }
            
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
        }
    );
});

app.post('/api/profile', (req, res) => {
    const { userId, displayName, avatar } = req.body;
    
    db.run(
        "UPDATE users SET display_name = ?, avatar_url = ? WHERE id = ?",
        [displayName, avatar, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка обновления профиля' });
            }
            res.json({ success: true });
        }
    );
});

app.get('/api/channels', (req, res) => {
    db.all("SELECT * FROM channels ORDER BY created_at", (err, channels) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json(channels);
    });
});

app.post('/api/channels', (req, res) => {
    const { name, type = 'text' } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Название канала обязательно' });
    }
    
    db.run(
        "INSERT INTO channels (name, type) VALUES (?, ?)",
        [name, type],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка создания канала' });
            }
            res.json({ 
                success: true, 
                channel: { id: this.lastID, name, type } 
            });
        }
    );
});

app.put('/api/channels/:channelId', (req, res) => {
    const { channelId } = req.params;
    const { name } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Название канала обязательно' });
    }
    
    db.run(
        "UPDATE channels SET name = ? WHERE id = ?",
        [name, channelId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка обновления канала' });
            }
            res.json({ success: true });
        }
    );
});

app.delete('/api/channels/:channelId', (req, res) => {
    const { channelId } = req.params;
    
    // Сначала удаляем все сообщения в канале
    db.run("DELETE FROM messages WHERE channel_id = ?", [channelId], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка удаления сообщений' });
        }
        
        // Затем удаляем сам канал
        db.run("DELETE FROM channels WHERE id = ?", [channelId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка удаления канала' });
            }
            res.json({ success: true });
        });
    });
});

app.get('/api/channels/:channelId/messages', (req, res) => {
    const { channelId } = req.params;
    
    db.all(`
        SELECT m.*, u.username, u.display_name, u.avatar_url 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? 
        ORDER BY m.created_at
    `, [channelId], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json(messages);
    });
});

app.delete('/api/messages/:messageId', (req, res) => {
    const { messageId } = req.params;
    
    db.run("DELETE FROM messages WHERE id = ?", [messageId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка удаления сообщения' });
        }
        res.json({ success: true });
    });
});

app.get('/api/users', (req, res) => {
    db.all("SELECT id, username, display_name, avatar_url, is_admin FROM users ORDER BY username", (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json(users);
    });
});

app.get('/api/users/search/:query', (req, res) => {
    const { query } = req.params;
    
    db.all(
        "SELECT id, username, display_name, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 10",
        [`%${query}%`, `%${query}%`],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка базы данных' });
            }
            res.json(users);
        }
    );
});

app.get('/api/direct-messages/:userId/:otherUserId', (req, res) => {
    const { userId, otherUserId } = req.params;
    
    db.all(`
        SELECT dm.*, u1.username as from_username, u1.display_name as from_display_name, u1.avatar_url as from_avatar,
               u2.username as to_username, u2.display_name as to_display_name, u2.avatar_url as to_avatar
        FROM direct_messages dm
        JOIN users u1 ON dm.from_user = u1.id
        JOIN users u2 ON dm.to_user = u2.id
        WHERE (dm.from_user = ? AND dm.to_user = ?) OR (dm.from_user = ? AND dm.to_user = ?)
        ORDER BY dm.created_at
    `, [userId, otherUserId, otherUserId, userId], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json(messages);
    });
});

app.delete('/api/direct-messages/:messageId', (req, res) => {
    const { messageId } = req.params;
    
    db.run("DELETE FROM direct_messages WHERE id = ?", [messageId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка удаления сообщения' });
        }
        res.json({ success: true });
    });
});

app.post('/api/delete-account', (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'ID пользователя обязателен' });
    }

    db.serialize(() => {
        db.run("BEGIN TRANSACTION;");

        db.run("DELETE FROM messages WHERE user_id = ?", [userId], (err) => {
            if (err) {
                db.run("ROLLBACK;");
                return res.status(500).json({ error: 'Ошибка при удалении сообщений пользователя' });
            }

            db.run("DELETE FROM direct_messages WHERE from_user = ? OR to_user = ?", [userId, userId], (err) => {
                if (err) {
                    db.run("ROLLBACK;");
                    return res.status(500).json({ error: 'Ошибка при удалении личных сообщений пользователя' });
                }

                db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
                    if (err) {
                        db.run("ROLLBACK;");
                        return res.status(500).json({ error: 'Ошибка при удалении пользователя' });
                    }
                    
                    if (this.changes === 0) {
                        db.run("ROLLBACK;");
                        return res.status(404).json({ error: 'Пользователь не найден' });
                    }

                    db.run("COMMIT;");
                    res.json({ success: true, message: 'Аккаунт успешно удален' });
                });
            });
        });
    });
});

// WebSocket соединения
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('user_online', (userData) => {
        onlineUsers.set(socket.id, {
            id: userData.id,
            username: userData.username,
            displayName: userData.displayName,
            avatar: userData.avatar,
            isAdmin: userData.isAdmin,
            socketId: socket.id
        });
        
        socket.broadcast.emit('user_connected', {
            id: userData.id,
            username: userData.username,
            displayName: userData.displayName
        });
        
        io.emit('online_users', Array.from(onlineUsers.values()));
    });

    // WebSocket обработчики для звонков
    socket.on('start_call', (data) => {
        const fromUser = onlineUsers.get(socket.id);
        const recipient = Array.from(onlineUsers.values())
            .find(u => u.id === data.toUserId);
            
        if (recipient) {
            io.to(recipient.socketId).emit('incoming_call', {
                from: socket.id,
                fromUserId: fromUser.id,
                fromUsername: fromUser.username,
                fromDisplayName: fromUser.displayName,
                type: data.type
            });
        } else {
            socket.emit('call_error', 'Пользователь не в сети');
        }
    });

    socket.on('accept_call', (data) => {
        io.to(data.from).emit('call_accepted', {
            to: socket.id
        });
    });

    socket.on('reject_call', (data) => {
        io.to(data.from).emit('call_rejected', {
            to: socket.id
        });
    });

    socket.on('end_call', (data) => {
        io.to(data.to).emit('call_ended');
    });

    socket.on('webrtc_offer', (data) => {
        io.to(data.to).emit('webrtc_offer', {
            offer: data.offer,
            from: socket.id
        });
    });

    socket.on('webrtc_answer', (data) => {
        io.to(data.to).emit('webrtc_answer', {
            answer: data.answer,
            from: socket.id
        });
    });

    socket.on('webrtc_ice_candidate', (data) => {
        io.to(data.to).emit('webrtc_ice_candidate', {
            candidate: data.candidate,
            from: socket.id
        });
    });

    socket.on('send_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;
        
        db.run(
            "INSERT INTO messages (channel_id, user_id, username, content) VALUES (?, ?, ?, ?)",
            [data.channelId, user.id, user.username, data.content],
            function(err) {
                if (err) {
                    console.error('Ошибка сохранения сообщения:', err);
                    return;
                }
                
                const message = {
                    id: this.lastID,
                    channel_id: data.channelId,
                    user_id: user.id,
                    username: user.username,
                    display_name: user.displayName,
                    avatar_url: user.avatar,
                    content: data.content,
                    created_at: new Date().toISOString()
                };
                
                io.emit('new_channel_message', message);
            }
        );
    });

    socket.on('send_direct_message', (data) => {
        const fromUser = onlineUsers.get(socket.id);
        if (!fromUser) return;
        
        db.run(
            "INSERT INTO direct_messages (from_user, to_user, content) VALUES (?, ?, ?)",
            [fromUser.id, data.toUserId, data.content],
            function(err) {
                if (err) {
                    console.error('Ошибка сохранения ЛС:', err);
                    return;
                }
                
                const message = {
                    id: this.lastID,
                    from_user: fromUser.id,
                    to_user: data.toUserId,
                    from_username: fromUser.username,
                    from_display_name: fromUser.displayName,
                    from_avatar: fromUser.avatar,
                    content: data.content,
                    created_at: new Date().toISOString()
                };
                
                // Отправляем отправителю
                socket.emit('new_direct_message', message);
                
                // Отправляем получателю если онлайн
                const recipient = Array.from(onlineUsers.values())
                    .find(u => u.id === data.toUserId);
                if (recipient) {
                    io.to(recipient.socketId).emit('new_direct_message', message);
                }
            }
        );
    });

    socket.on('create_channel', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user || !user.isAdmin) {
            socket.emit('channel_error', 'Недостаточно прав');
            return;
        }
        
        db.run(
            "INSERT INTO channels (name, type, created_by) VALUES (?, ?, ?)",
            [data.name, data.type || 'text', user.id],
            function(err) {
                if (err) {
                    socket.emit('channel_error', 'Ошибка создания канала');
                    return;
                }
                
                const channel = {
                    id: this.lastID,
                    name: data.name,
                    type: data.type || 'text',
                    created_by: user.id
                };
                
                io.emit('channel_created', channel);
            }
        );
    });

    socket.on('update_channel', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user || !user.isAdmin) {
            socket.emit('channel_error', 'Недостаточно прав');
            return;
        }
        
        db.run(
            "UPDATE channels SET name = ? WHERE id = ?",
            [data.name, data.channelId],
            function(err) {
                if (err) {
                    socket.emit('channel_error', 'Ошибка обновления канала');
                    return;
                }
                
                const channel = {
                    id: data.channelId,
                    name: data.name
                };
                
                io.emit('channel_updated', channel);
            }
        );
    });

    socket.on('delete_channel', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user || !user.isAdmin) {
            socket.emit('channel_error', 'Недостаточно прав');
            return;
        }
        
        // Удаляем сообщения канала
        db.run("DELETE FROM messages WHERE channel_id = ?", [data.channelId], (err) => {
            if (err) {
                socket.emit('channel_error', 'Ошибка удаления сообщений');
                return;
            }
            
            // Удаляем канал
            db.run("DELETE FROM channels WHERE id = ?", [data.channelId], function(err) {
                if (err) {
                    socket.emit('channel_error', 'Ошибка удаления канала');
                    return;
                }
                
                io.emit('channel_deleted', data.channelId);
            });
        });
    });

    socket.on('delete_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;
        
        // Проверяем права: админ или автор сообщения
        db.get("SELECT user_id FROM messages WHERE id = ?", [data.messageId], (err, message) => {
            if (err || !message) {
                socket.emit('message_error', 'Сообщение не найдено');
                return;
            }
            
            if (user.isAdmin || message.user_id === user.id) {
                db.run("DELETE FROM messages WHERE id = ?", [data.messageId], function(err) {
                    if (err) {
                        socket.emit('message_error', 'Ошибка удаления сообщения');
                        return;
                    }
                    
                    io.emit('message_deleted', { messageId: data.messageId });
                });
            } else {
                socket.emit('message_error', 'Недостаточно прав');
            }
        });
    });

    socket.on('delete_direct_message', (data) => {
        const user = onlineUsers.get(socket.id);
        if (!user) return;
        
        // Проверяем что пользователь является отправителем
        db.get("SELECT from_user FROM direct_messages WHERE id = ?", [data.messageId], (err, message) => {
            if (err || !message) {
                socket.emit('message_error', 'Сообщение не найдено');
                return;
            }
            
            if (message.from_user === user.id) {
                db.run("DELETE FROM direct_messages WHERE id = ?", [data.messageId], function(err) {
                    if (err) {
                        socket.emit('message_error', 'Ошибка удаления сообщения');
                        return;
                    }
                    
                    io.emit('message_deleted', { messageId: data.messageId });
                });
            } else {
                socket.emit('message_error', 'Недостаточно прав');
            }
        });
    });

    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            onlineUsers.delete(socket.id);
            io.emit('user_disconnected', user.id);
            io.emit('online_users', Array.from(onlineUsers.values()));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
