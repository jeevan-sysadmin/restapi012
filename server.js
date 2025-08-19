require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path'); // Add this for static file serving

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;
const AUTH_KEY = process.env.AUTH_KEY; // a server-side key you use to request token
const TOKEN_EXPIRY = '5m';

// Basic env check
if (!SECRET_KEY) {
    console.error('Missing JWT_SECRET in environment. Exiting.');
    process.exit(1);
}
if (!AUTH_KEY) {
    console.warn('No AUTH_KEY set in environment. Consider setting one to restrict token generation.');
}

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/eldercare', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Mongoose Models
const User = mongoose.model('User', new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}));

const Vital = mongoose.model('Vital', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    heartRate: { type: Number },
    movement: { type: String },
    status: { type: String },
    timestamp: { type: Date, default: Date.now }
}));

const FallAlert = mongoose.model('FallAlert', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, default: 'fall' },
    location: { type: String, default: 'unknown' },
    timestamp: { type: Date, default: Date.now },
    acknowledged: { type: Boolean, default: false }
}));

const DailyLog = mongoose.model('DailyLog', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    activities: { type: String },
    notes: { type: String },
    mood: { type: String }
}, { 
    // Create a unique compound index on userId and date
    timestamps: true,
    unique: true 
}));

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files if any (optional)
app.use(express.static(path.join(__dirname, 'public')));

// Add a root route handler to fix "Cannot GET /" error
app.get('/', (req, res) => {
    res.json({ 
        status: 'success', 
        message: 'ElderCare API Server is running',
        endpoints: {
            auth: ['/api/login', '/api/register', '/api/generate-token'],
            vitals: ['/api/vitals/real-time', '/api/vitals/history'],
            alerts: ['/api/alerts/fall'],
            logs: ['/api/logs/daily', '/api/logs/update']
        }
    });
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader || null;

    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Token missing' });
    }

    jwt.verify(token, SECRET_KEY, (err, payload) => {
        if (err) {
            return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
        }
        req.user = payload; // payload may include userName, role, etc.
        next();
    });
};

/**
 * 1. Token Generation API
 *    - Requires a server-side authKey to be passed in body to prevent public abuse
 *    - Returns JWT (payload includes userName and role)
 */
app.post('/api/generate-token', async (req, res) => {
    const { userName, password, authKey, role } = req.body;

    if (!userName || !password || !authKey) {
        return res.status(400).json({ status: 'error', message: 'Missing required fields (userName, password, authKey)' });
    }

    // validate authKey (simple shared-secret check)
    if (AUTH_KEY && authKey !== AUTH_KEY) {
        return res.status(403).json({ status: 'error', message: 'Invalid authKey' });
    }

    try {
        // NOTE: Here we don't validate password against DB; 
        // this endpoint just issues token if correct authKey is provided.
        const payload = { userName, role: role || 'user' };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
        res.json({ status: 'success', data: token, expiresIn: TOKEN_EXPIRY });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Token generation failed' });
    }
});

/**
 * Login (public) - verifies credentials, returns basic info
 * - This is public (no token required). Clients pass email & password in body
 */
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ status: 'error', message: 'Email and password required' });

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
        }

        // Optionally issue a JWT here if you want login to return tokens:
        const payload = { userId: user._id, email: user.email, role: 'user' };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

        res.json({
            status: 'success',
            message: 'Login successful',
            id: user._id,
            name: user.name,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

/**
 * Register (public)
 * - Registers new user. No token required by default.
 */
app.post('/api/register', async (req, res) => {
    const { name, email, phone, password, confirmPassword } = req.body;

    try {
        if (!name || !email || !phone || !password || !confirmPassword) {
            return res.status(400).json({ status: 'error', message: 'All fields are required' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ status: 'error', message: 'Passwords do not match' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ status: 'error', message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword
        });

        await user.save();

        res.json({
            status: 'success',
            message: 'User registered successfully',
            userId: user._id
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ status: 'error', message: 'Registration failed' });
    }
});

/**
 * Real-Time Vitals API (protected)
 * Body: { id: userId }
 */
app.post('/api/vitals/real-time', authenticateToken, async (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ status: 'error', message: 'user id required in body' });

    try {
        const latestVital = await Vital.findOne({ userId: id })
            .sort({ timestamp: -1 })
            .limit(1);

        if (!latestVital) {
            return res.status(404).json({ status: 'error', message: 'No vitals data found' });
        }

        res.json({
            heartRate: latestVital.heartRate,
            movement: latestVital.movement,
            status: latestVital.status,
            timestamp: latestVital.timestamp
        });
    } catch (error) {
        console.error('Vitals realtime error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch vitals' });
    }
});

/**
 * Vitals History API (protected)
 * Body: { startDate, endDate } (ISO date strings)
 */
app.post('/api/vitals/history', authenticateToken, async (req, res) => {
    const { userId, startDate, endDate } = req.body;
    if (!userId || !startDate || !endDate) return res.status(400).json({ status: 'error', message: 'userId, startDate and endDate required' });

    try {
        const vitals = await Vital.find({
            userId,
            timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) }
        }).sort({ timestamp: 1 }).select('timestamp heartRate -_id');

        res.json({ data: vitals });
    } catch (error) {
        console.error('Vitals history error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch vitals history' });
    }
});

/**
 * Fall Detection Alert API (protected)
 * Body must include userId
 */
app.post('/api/alerts/fall', authenticateToken, async (req, res) => {
    const { userId, type, location, timestamp } = req.body;

    if (!userId) return res.status(400).json({ status: 'error', message: 'userId is required' });

    try {
        const alert = new FallAlert({
            userId,
            type: type || 'fall',
            location: location || 'unknown',
            timestamp: timestamp || new Date()
        });

        await alert.save();

        res.json({ status: 'success', alert });
    } catch (error) {
        console.error('Fall alert error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create alert' });
    }
});

/**
 * Daily Logs API (protected)
 * Body: { userId, date }
 */
app.post('/api/logs/daily', authenticateToken, async (req, res) => {
    const { userId, date } = req.body;
    if (!userId || !date) return res.status(400).json({ status: 'error', message: 'userId and date required' });

    try {
        const log = await DailyLog.findOne({ 
            userId, 
            date: new Date(date) 
        });

        if (!log) {
            return res.status(404).json({ status: 'error', message: 'No logs found for this date' });
        }

        res.json(log);
    } catch (error) {
        console.error('Daily logs error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch daily logs' });
    }
});

/**
 * Create/Update Daily Log (protected)
 */
app.post('/api/logs/update', authenticateToken, async (req, res) => {
    const { userId, date, activities, notes, mood } = req.body;
    if (!userId || !date) return res.status(400).json({ status: 'error', message: 'userId and date required' });

    try {
        const log = await DailyLog.findOneAndUpdate(
            { userId, date: new Date(date) },
            { activities, notes, mood },
            { new: true, upsert: true }
        );

        res.json({
            status: 'success',
            message: 'Daily log updated',
            log
        });
    } catch (error) {
        console.error('Update daily log error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update daily log' });
    }
});

// Handle 404 for all other routes
app.use('*', (req, res) => {
    res.status(404).json({ 
        status: 'error', 
        message: 'Endpoint not found',
        availableEndpoints: {
            root: 'GET /',
            auth: ['POST /api/login', 'POST /api/register', 'POST /api/generate-token'],
            vitals: ['POST /api/vitals/real-time', 'POST /api/vitals/history'],
            alerts: ['POST /api/alerts/fall'],
            logs: ['POST /api/logs/daily', 'POST /api/logs/update']
        }
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});