const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const { createServer } = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);
const port = 8000;
const secretKey = 'your_secret_key'; // Use a secure key in production

// Store online users and their socket IDs
const onlineUsers = new Map(); // userId -> {socketId, username}
const userFriends = new Map(); // userId -> Set of friend userIds
const pendingFriendRequests = new Map(); // userId -> Set of pending friend request userIds

// Function to get client IP
const getClientIP = (req) => {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress;
};

// Function to log access
const logAccess = (fileToken, ip, action) => {
    const now = new Date().toISOString();
    const logEntry = {
        timestamp: now,
        fileToken: fileToken,
        ip: ip,
        action: action
    };

    const logFile = path.join(__dirname, 'access_logs.json');
    let logs = [];
    
    if (fs.existsSync(logFile)) {
        logs = JSON.parse(fs.readFileSync(logFile, 'utf8'));
    }
    
    logs.push(logEntry);
    fs.writeFileSync(logFile, JSON.stringify(logs, null, 2));
};

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Configure multer for file storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Serve static files from public directory
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(express.json());

// Initialize files.json if it doesn't exist
const filesDb = path.join(__dirname, 'files.json');
if (!fs.existsSync(filesDb)) {
    fs.writeFileSync(filesDb, '[]', 'utf8');
}

// Initialize users.json if it doesn't exist
const usersDb = path.join(__dirname, 'users.json');
if (!fs.existsSync(usersDb)) {
    fs.writeFileSync(usersDb, '[]', 'utf8');
}

// User registration
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(usersDb, 'utf8'));
    
    if (users.some(user => user.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = { id: uuidv4(), username, password_hash: passwordHash };
    users.push(newUser);
    fs.writeFileSync(usersDb, JSON.stringify(users, null, 2));

    res.status(201).json({ message: 'User registered successfully' });
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(usersDb, 'utf8'));

    const user = users.find(user => user.username === username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
});

// WebSocket connection handling
io.on('connection', (socket) => {
    let userId = null;

    socket.on('register', (username) => {
        userId = uuidv4();
        onlineUsers.set(userId, { socketId: socket.id, username });
        
        // Broadcast online status to all users
        io.emit('userList', Array.from(onlineUsers.entries()).map(([id, data]) => ({
            id,
            username: data.username,
            online: true
        })));

        socket.emit('registered', { userId, username });
    });

    socket.on('sendFriendRequest', ({ toUserId }) => {
        const fromUser = onlineUsers.get(userId);
        const toUser = onlineUsers.get(toUserId);
        
        if (!pendingFriendRequests.has(toUserId)) {
            pendingFriendRequests.set(toUserId, new Set());
        }
        pendingFriendRequests.get(toUserId).add(userId);

        if (toUser) {
            io.to(toUser.socketId).emit('friendRequest', {
                fromUserId: userId,
                fromUsername: fromUser.username
            });
        }
    });

    socket.on('acceptFriendRequest', ({ fromUserId }) => {
        if (!userFriends.has(userId)) {
            userFriends.set(userId, new Set());
        }
        if (!userFriends.has(fromUserId)) {
            userFriends.set(fromUserId, new Set());
        }

        userFriends.get(userId).add(fromUserId);
        userFriends.get(fromUserId).add(userId);

        pendingFriendRequests.get(userId)?.delete(fromUserId);

        const fromUser = onlineUsers.get(fromUserId);
        const toUser = onlineUsers.get(userId);

        if (fromUser) {
            io.to(fromUser.socketId).emit('friendRequestAccepted', {
                userId,
                username: toUser.username
            });
        }
    });

    socket.on('sendMessage', ({ toUserId, message }) => {
        const fromUser = onlineUsers.get(userId);
        const toUser = onlineUsers.get(toUserId);

        if (toUser && userFriends.get(userId)?.has(toUserId)) {
            const newMessage = {
                id: uuidv4(),
                from_user_id: userId,
                to_user_id: toUserId,
                message,
                timestamp: new Date().toISOString()
            };

            const messages = JSON.parse(fs.readFileSync(messagesDb, 'utf8'));
            messages.push(newMessage);
            fs.writeFileSync(messagesDb, JSON.stringify(messages, null, 2));

            io.to(toUser.socketId).emit('newMessage', {
                fromUserId: userId,
                fromUsername: fromUser.username,
                message
            });
        }
    });

    socket.on('disconnect', () => {
        if (userId) {
            onlineUsers.delete(userId);
            io.emit('userOffline', userId);
        }
    });
});

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const token = uuidv4();
        const uploaderIP = getClientIP(req);
        const uploaderId = req.body.userId;
        
        const fileData = {
            token,
            originalName: req.file.originalname,
            filename: req.file.filename,
            size: req.file.size,
            uploadDate: new Date().toISOString(),
            path: req.file.path,
            uploaderIP: uploaderIP,
            uploaderId: uploaderId,
            downloadCount: 0
        };

        const files = JSON.parse(fs.readFileSync(filesDb, 'utf8'));
        files.push(fileData);
        fs.writeFileSync(filesDb, JSON.stringify(files, null, 2));

        // Log upload action
        logAccess(token, uploaderIP, 'upload');

        res.json({
            success: true,
            token,
            downloadLink: `/d/${token}`
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to process upload' });
    }
});

// File download endpoint with friend request
app.get('/d/:token', (req, res) => {
    try {
        const files = JSON.parse(fs.readFileSync(filesDb, 'utf8'));
        const fileIndex = files.findIndex(f => f.token === req.params.token);

        if (fileIndex === -1) {
            return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
        }

        const file = files[fileIndex];
        const downloaderIP = getClientIP(req);

        // Increment download count
        files[fileIndex].downloadCount = (files[fileIndex].downloadCount || 0) + 1;
        fs.writeFileSync(filesDb, JSON.stringify(files, null, 2));

        // Log download action
        logAccess(req.params.token, downloaderIP, 'download');

        // If uploader is online, send them a notification about the download
        if (file.uploaderId) {
            const uploader = onlineUsers.get(file.uploaderId);
            if (uploader) {
                io.to(uploader.socketId).emit('fileAccessed', {
                    fileName: file.originalName,
                    accessIP: downloaderIP
                });
            }
        }

        res.download(file.path, file.originalName);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Failed to process download' });
    }
});

// Stats endpoint
app.get('/api/stats/:token', (req, res) => {
    try {
        const files = JSON.parse(fs.readFileSync(filesDb, 'utf8'));
        const file = files.find(f => f.token === req.params.token);
        
        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Get access logs for this file
        const logFile = path.join(__dirname, 'access_logs.json');
        let logs = [];
        if (fs.existsSync(logFile)) {
            logs = JSON.parse(fs.readFileSync(logFile, 'utf8'));
        }
        
        const fileStats = {
            originalName: file.originalName,
            uploadDate: file.uploadDate,
            size: file.size,
            downloadCount: file.downloadCount || 0,
            uploaderIP: file.uploaderIP,
            uploaderId: file.uploaderId,
            accessLog: logs.filter(log => log.fileToken === req.params.token)
        };

        res.json(fileStats);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

httpServer.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
