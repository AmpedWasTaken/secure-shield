const express = require('express');
const { SecureShield } = require('../dist/index');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const session = require('express-session');
const config = require('./config');

const app = express();
const port = process.env.PORT || 3000;

// MySQL Connection Pool
const pool = mysql.createPool({
    ...config.mysql,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Initialize SecureShield
const shield = new SecureShield({
    enabled: true,
    xssOptions: {
        stripTags: true,
        allowedTags: ['b', 'i', 'em', 'strong']
    },
    rateLimit: {
        windowMs: 15 * 60 * 1000,
        maxRequests: 100
    },
    logging: {
        enabled: true,
        logLevel: 'info',
        logPath: './logs/security.log'
    },
    securityHeaders: {
        enabled: true
    }
});

// Middleware
app.use(bodyParser.json());
app.use(session({
    ...config.session,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(shield.middleware());

// Database setup function
async function setupDatabase() {
    try {
        const connection = await pool.getConnection();
        
        // Create users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create posts table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS posts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                title VARCHAR(255) NOT NULL,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        connection.release();
        console.log('Database setup completed');
    } catch (error) {
        console.error('Database setup error:', error);
        process.exit(1);
    }
}

// Test routes
app.get('/', (req, res) => {
    res.send('Security Test App Running with MySQL');
});

// User routes
app.post('/api/users/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        // Sanitize inputs
        const sanitizedUsername = shield.sanitize(username);
        const sanitizedEmail = shield.sanitize(email);
        
        // Hash password
        const hashedPassword = await shield.cryptoUtils.hashPassword(password);
        
        const [result] = await pool.query(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [sanitizedUsername, hashedPassword, sanitizedEmail]
        );

        res.json({ 
            message: 'User registered successfully',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/users/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const [users] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const isValid = await shield.cryptoUtils.verifyPassword(password, user.password);

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.userId = user.id;
        res.json({ message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Post routes
app.post('/api/posts', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { title, content } = req.body;
        
        // Sanitize inputs
        const sanitizedTitle = shield.sanitize(title);
        const sanitizedContent = shield.sanitize(content);
        
        const [result] = await pool.query(
            'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
            [req.session.userId, sanitizedTitle, sanitizedContent]
        );

        res.json({ 
            message: 'Post created successfully',
            postId: result.insertId
        });
    } catch (error) {
        console.error('Post creation error:', error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const [posts] = await pool.query(`
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        `);
        
        res.json(posts);
    } catch (error) {
        console.error('Posts fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch posts' });
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
if (require.main === module) {
    setupDatabase().then(() => {
        app.listen(port, () => {
            console.log(`Test app listening at http://localhost:${port}`);
            console.log('Available endpoints:');
            console.log('  POST /api/users/register');
            console.log('  POST /api/users/login');
            console.log('  POST /api/posts');
            console.log('  GET  /api/posts');
        });
    });
}

module.exports = app; 