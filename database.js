const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'messenger.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Database error:', err);
    } else {
        console.log('✅ Database connected');
        initializeDatabase();
    }
});

// ВКЛЮЧАЕМ МАКСИМАЛЬНУЮ ПРОИЗВОДИТЕЛЬНОСТЬ
db.configure("busyTimeout", 3000);
db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA synchronous = NORMAL;"); 
db.run("PRAGMA cache_size = -2000;");
db.run("PRAGMA temp_store = MEMORY;");
db.run("PRAGMA mmap_size = 268435456;");

const simpleHash = {
    hash: (password) => Promise.resolve('hashed_' + password),
    compare: (password, hash) => Promise.resolve(hash === 'hashed_' + password)
};

function initializeDatabase() {
    // Создаем таблицы последовательно
    db.run(`CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        type TEXT DEFAULT 'text',
        permissions TEXT DEFAULT '{"read": true, "write": true}',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('❌ Error creating channels table:', err);
        } else {
            console.log('✅ Channels table ready');
            
            // После создания channels создаем остальные таблицы
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                display_name TEXT,
                avatar_url TEXT DEFAULT 'default',
                password TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) {
                    console.error('❌ Error creating users table:', err);
                } else {
                    console.log('✅ Users table ready');
                    
                    db.run(`CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        channel_id INTEGER,
                        user_id INTEGER,
                        username TEXT,
                        content TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )`, (err) => {
                        if (err) {
                            console.error('❌ Error creating messages table:', err);
                        } else {
                            console.log('✅ Messages table ready');
                            
                            db.run(`CREATE TABLE IF NOT EXISTS direct_messages (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                from_user INTEGER,
                                to_user INTEGER,
                                content TEXT,
                                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                            )`, (err) => {
                                if (err) {
                                    console.error('❌ Error creating direct_messages table:', err);
                                } else {
                                    console.log('✅ Direct messages table ready');
                                    createInitialData();
                                    fixDatabaseSchema();
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

function fixDatabaseSchema() {
    console.log('🔧 Checking database schema...');
    
    // Проверяем структуру таблицы channels
    db.all("PRAGMA table_info(channels)", (err, columns) => {
        if (err) {
            console.error('❌ Error checking table structure:', err);
            return;
        }
        
        console.log('📊 Channels table structure:', columns);
        
        // Если есть created_by поле, которое вызывает проблемы, исправляем это
        const hasCreatedBy = columns.some(col => col.name === 'created_by');
        if (hasCreatedBy) {
            console.log('🔄 Fixing channels table structure...');
            
            // Создаем временную таблицу без created_by
            db.run(`CREATE TABLE IF NOT EXISTS channels_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                type TEXT DEFAULT 'text',
                permissions TEXT DEFAULT '{"read": true, "write": true}',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) {
                    console.error('Error creating temp table:', err);
                    return;
                }
                
                // Копируем данные из старой таблицы
                db.run(`INSERT OR IGNORE INTO channels_temp (id, name, type, permissions, created_at)
                        SELECT id, name, type, permissions, created_at FROM channels`, (err) => {
                    if (err) {
                        console.error('Error copying data:', err);
                        return;
                    }
                    
                    // Удаляем старую таблицу и переименовываем временную
                    db.run("DROP TABLE IF EXISTS channels", (err) => {
                        if (err) console.error('Error dropping old table:', err);
                        db.run("ALTER TABLE channels_temp RENAME TO channels", (err) => {
                            if (err) {
                                console.error('Error renaming table:', err);
                            } else {
                                console.log('✅ Channels table fixed successfully');
                            }
                        });
                    });
                });
            });
        } else {
            console.log('✅ Channels table structure is correct');
        }
    });
}

function createInitialData() {
    // Создаем начальные данные ТОЛЬКО если их нет
    const initialChannels = [
        { name: 'general', type: 'text', permissions: '{"read": true, "write": true}' },
        { name: 'help', type: 'text', permissions: '{"read": true, "write": true}' }
    ];
    
    initialChannels.forEach(channel => {
        db.get("SELECT id FROM channels WHERE name = ?", [channel.name], (err, row) => {
            if (err) return;
            if (!row) {
                db.run("INSERT INTO channels (name, type, permissions) VALUES (?, ?, ?)",
                    [channel.name, channel.type, channel.permissions], (err) => {
                        if (err) console.error('Error inserting channel:', err);
                    });
            }
        });
    });
    
    // Создаем тестовых пользователей
    const createUser = (username, password, isAdmin = false) => {
        const hashedPassword = 'hashed_' + password;
        db.run(
            `INSERT OR IGNORE INTO users (username, display_name, password, is_admin) VALUES (?, ?, ?, ?)`,
            [username, username, hashedPassword, isAdmin],
            (err) => {
                if (err) console.error('Error creating user:', err);
            }
        );
    };

    createUser('Lenkov', 'ClorumAdminNord', true);
    createUser('9nge', 'ClorumPrCreator9nge', true);
    createUser('test', 'test123', false);
    
    console.log('🎉 Database initialization complete!');
}

module.exports = { db, simpleHash };
