const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'messenger.db');
const db = new sqlite3.Database(dbPath);

// Простая функция хеширования пароля
const simpleHash = {
    hash: (password) => Promise.resolve('hashed_' + password),
    compare: (password, hash) => Promise.resolve(hash === 'hashed_' + password)
};

db.serialize(() => {
    // Пользователи с паролями и профилями
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        display_name TEXT,
        avatar_url TEXT,
        password TEXT,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Серверные каналы
    db.run(`CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT DEFAULT 'text',
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Сообщения в каналах (поддержка изображений)
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER,
        user_id INTEGER,
        username TEXT,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(channel_id) REFERENCES channels(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Личные сообщения (поддержка изображений)
    db.run(`CREATE TABLE IF NOT EXISTS direct_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_user) REFERENCES users(id),
        FOREIGN KEY(to_user) REFERENCES users(id)
    )`);
    
    console.log('✅ База данных готова!');
    
    // Создаем начальные каналы
    db.run("INSERT OR IGNORE INTO channels (name, type) VALUES ('general', 'text')");
    db.run("INSERT OR IGNORE INTO channels (name, type) VALUES ('help', 'text')");
    
    // Создаем админов с новыми паролями
    const createAdmin = async (username, password) => {
        const hashedPassword = await simpleHash.hash(password);
        db.run(
            `INSERT OR IGNORE INTO users (username, display_name, password, is_admin) 
             VALUES (?, ?, ?, TRUE)`,
            [username, username, hashedPassword]
        );
    };
    
    createAdmin('Lenkov', 'ClorumAdminNord');
    createAdmin('9nge', 'ClorumPrCreator9nge');
});

module.exports = { db, simpleHash };