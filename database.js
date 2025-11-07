const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'messenger.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Database error:', err);
    } else {
        console.log('✅ Database connected');
    }
});

// ВКЛЮЧАЕМ МАКСИМАЛЬНУЮ ПРОИЗВОДИТЕЛЬНОСТЬ
db.configure("busyTimeout", 3000);
db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA synchronous = NORMAL;"); 
db.run("PRAGMA cache_size = -10000;");
db.run("PRAGMA temp_store = MEMORY;");
db.run("PRAGMA mmap_size = 268435456;");

const simpleHash = {
    hash: (password) => Promise.resolve('hashed_' + password),
    compare: (password, hash) => Promise.resolve(hash === 'hashed_' + password)
};

// Создаем таблицы если их нет
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        display_name TEXT,
        avatar_url TEXT DEFAULT 'default',
        password TEXT,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT DEFAULT 'text',
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
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
    
    db.run(`CREATE TABLE IF NOT EXISTS direct_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_user) REFERENCES users(id),
        FOREIGN KEY(to_user) REFERENCES users(id)
    )`);
    
    // Создаем начальные данные
    db.run("INSERT OR IGNORE INTO channels (name, type) VALUES ('general', 'text')");
    db.run("INSERT OR IGNORE INTO channels (name, type) VALUES ('help', 'text')");
    
    // Создаем тестовых пользователей
    const createUser = async (username, password, isAdmin = false) => {
        const hashedPassword = await simpleHash.hash(password);
        db.run(
            `INSERT OR IGNORE INTO users (username, display_name, password, is_admin) VALUES (?, ?, ?, ?)`,
            [username, username, hashedPassword, isAdmin]
        );
    };
    
    createUser('Lenkov', 'ClorumAdminNord', true);
    createUser('9nge', 'ClorumPrCreator9nge', true);
});

module.exports = { db, simpleHash };

