const express = require('express');
const session = require('express-session');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const useragent = require('useragent');
const sharp = require('sharp');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session
app.use(session({
    secret: 'super-secret-key-2024-face-swap',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 3600000 }
}));

// Database setup
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    // Tabel template gambar
    db.run(`CREATE TABLE IF NOT EXISTS image_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        file_path TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabel template video
    db.run(`CREATE TABLE IF NOT EXISTS video_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        file_path TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabel admin dengan password hash
    db.run(`CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    // Tabel activity logs
    db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        username TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        year INTEGER
    )`);

    // Insert default admin dengan password admin123 yang sudah di-hash
    const defaultHash = bcrypt.hashSync('admin123', 10);
    db.get("SELECT * FROM admin WHERE username = 'admin'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO admin (username, password) VALUES ('admin', ?)", [defaultHash]);
            console.log('Default admin created: admin / admin123');
        }
    });
});

// Fungsi logging aktivitas
function logActivity(action, username = 'anonymous', req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const agent = useragent.parse(req.headers['user-agent']).toString();
    const year = new Date().getFullYear();
    db.run("INSERT INTO activity_logs (action, username, ip_address, user_agent, year) VALUES (?, ?, ?, ?, ?)",
        [action, username, ip, agent, year]);
}

// Storage multer dengan validasi
const storageImage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/images/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const storageVideo = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/videos/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilterImage = (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/jpg'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format gambar tidak didukung'), false);
};

const fileFilterVideo = (req, file, cb) => {
    const allowed = ['video/mp4', 'video/webm'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format video tidak didukung'), false);
};

const uploadImage = multer({ storage: storageImage, fileFilter: fileFilterImage, limits: { fileSize: 10 * 1024 * 1024 } });
const uploadVideo = multer({ storage: storageVideo, fileFilter: fileFilterVideo, limits: { fileSize: 50 * 1024 * 1024 } });

// Middleware auth admin
const isAuthenticated = (req, res, next) => {
    if (req.session.isAdmin) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// Routes

// Login admin dengan bcrypt
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM admin WHERE username = ?", [username], async (err, row) => {
        if (row && await bcrypt.compare(password, row.password)) {
            req.session.isAdmin = true;
            req.session.username = username;
            logActivity('LOGIN_SUCCESS', username, req);
            res.json({ success: true });
        } else {
            logActivity('LOGIN_FAILED', username, req);
            res.json({ success: false, message: 'Username atau password salah' });
        }
    });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    if (req.session.isAdmin) logActivity('LOGOUT', req.session.username, req);
    req.session.destroy();
    res.json({ success: true });
});

// Check login status
app.get('/api/admin/check', (req, res) => {
    res.json({ isAdmin: req.session.isAdmin || false });
});

// Get activity logs (admin only)
app.get('/api/admin/logs', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 200", (err, rows) => {
        res.json(rows);
    });
});

// Template gambar
app.get('/api/templates/images', (req, res) => {
    db.all("SELECT * FROM image_templates ORDER BY created_at DESC", (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/templates/images/category/:category', (req, res) => {
    const category = req.params.category;
    db.all("SELECT * FROM image_templates WHERE category = ? ORDER BY created_at DESC", [category], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/admin/templates/image', isAuthenticated, uploadImage.single('image'), async (req, res) => {
    try {
        const { title, category } = req.body;
        const filePath = req.file.path;
        
        // Kompres gambar dengan sharp
        const outputPath = filePath.replace(/\.\w+$/, '-compressed.jpg');
        await sharp(filePath).resize(800, 800, { fit: 'inside' }).jpeg({ quality: 85 }).toFile(outputPath);
        fs.unlinkSync(filePath);
        
        db.run("INSERT INTO image_templates (title, category, file_path) VALUES (?, ?, ?)", 
            [title, category, outputPath], 
            function(err) {
                if (err) {
                    res.json({ success: false, error: err.message });
                } else {
                    logActivity('ADD_IMAGE_TEMPLATE', req.session.username, req);
                    res.json({ success: true, id: this.lastID });
                }
            });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.delete('/api/admin/templates/image/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.get("SELECT file_path FROM image_templates WHERE id = ?", [id], (err, row) => {
        if (row) {
            fs.unlink(row.file_path, () => {});
            db.run("DELETE FROM image_templates WHERE id = ?", [id], (err) => {
                logActivity('DELETE_IMAGE_TEMPLATE', req.session.username, req);
                res.json({ success: true });
            });
        } else {
            res.json({ success: false });
        }
    });
});

// Template video (sama seperti gambar, tanpa kompres video untuk sementara)
app.get('/api/templates/videos', (req, res) => {
    db.all("SELECT * FROM video_templates ORDER BY created_at DESC", (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/templates/videos/category/:category', (req, res) => {
    const category = req.params.category;
    db.all("SELECT * FROM video_templates WHERE category = ? ORDER BY created_at DESC", [category], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/admin/templates/video', isAuthenticated, uploadVideo.single('video'), (req, res) => {
    const { title, category } = req.body;
    const filePath = req.file.path;
    
    db.run("INSERT INTO video_templates (title, category, file_path) VALUES (?, ?, ?)", 
        [title, category, filePath], 
        function(err) {
            if (err) {
                res.json({ success: false, error: err.message });
            } else {
                logActivity('ADD_VIDEO_TEMPLATE', req.session.username, req);
                res.json({ success: true, id: this.lastID });
            }
        });
});

app.delete('/api/admin/templates/video/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.get("SELECT file_path FROM video_templates WHERE id = ?", [id], (err, row) => {
        if (row) {
            fs.unlink(row.file_path, () => {});
            db.run("DELETE FROM video_templates WHERE id = ?", [id], (err) => {
                logActivity('DELETE_VIDEO_TEMPLATE', req.session.username, req);
                res.json({ success: true });
            });
        } else {
            res.json({ success: false });
        }
    });
});

// Setup folder upload dan model
if (!fs.existsSync('uploads/images')) fs.mkdirSync('uploads/images', { recursive: true });
if (!fs.existsSync('uploads/videos')) fs.mkdirSync('uploads/videos', { recursive: true });

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
