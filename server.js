const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: 'gym-secret-key-change-later',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

const db = new Database('./gym.db');

db.exec(`CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  schedule TEXT NOT NULL,
  description TEXT NOT NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS trainers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  specialty TEXT NOT NULL,
  bio TEXT NOT NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  class_id INTEGER NOT NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS workouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  exercise TEXT NOT NULL,
  sets INTEGER NOT NULL,
  reps INTEGER NOT NULL,
  weight REAL,
  date TEXT NOT NULL
)`);

const classCount = db.prepare('SELECT COUNT(*) as count FROM classes').get();
if (classCount.count === 0) {
  const insertClass = db.prepare('INSERT INTO classes (name, schedule, description) VALUES (?, ?, ?)');
  const classes = [
    ['Yoga Flow', 'Mon, Wed, Fri — 7:00 AM', 'Improve flexibility and reduce stress with guided yoga sessions.'],
    ['HIIT Blast', 'Tue, Thu — 6:00 PM', 'High-intensity interval training to torch calories fast.'],
    ['Strength Training', 'Mon–Fri — 5:00 PM', 'Build muscle and power with guided weightlifting sessions.'],
    ['Spin Cycle', 'Sat — 9:00 AM', 'An energetic cardio workout on the bike, set to great music.'],
    ['Pilates', 'Wed, Fri — 8:00 AM', 'Core-focused workout to build strength and stability.'],
    ['Boxing Fundamentals', 'Tue, Thu — 7:00 PM', 'Learn boxing technique while getting a full-body workout.']
  ];
  classes.forEach(c => insertClass.run(...c));
}

const trainerCount = db.prepare('SELECT COUNT(*) as count FROM trainers').get();
if (trainerCount.count === 0) {
  const insertTrainer = db.prepare('INSERT INTO trainers (name, specialty, bio) VALUES (?, ?, ?)');
  const trainers = [
    ['Alex Johnson', 'Strength & Conditioning', '10+ years of experience helping clients build strength safely and effectively.'],
    ['Maria Lopez', 'Yoga & Pilates', 'Certified yoga instructor focused on flexibility, balance, and mindfulness.'],
    ['David Kim', 'HIIT & Cardio', 'Specializes in high-energy workouts that maximize calorie burn.']
  ];
  trainers.forEach(t => insertTrainer.run(...t));
}

app.get('/api/classes', (req, res) => {
  const rows = db.prepare('SELECT * FROM classes').all();
  res.json(rows);
});

app.get('/api/trainers', (req, res) => {
  const rows = db.prepare('SELECT * FROM trainers').all();
  res.json(rows);
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'You must be logged in.' });
  }
  next();
}

app.post('/api/bookings', requireLogin, (req, res) => {
  const { classId } = req.body;
  const info = db.prepare('INSERT INTO bookings (user_id, class_id) VALUES (?, ?)').run(req.session.userId, classId);
  res.json({ success: true, bookingId: info.lastInsertRowid });
});

app.get('/api/bookings', requireLogin, (req, res) => {
  const rows = db.prepare(`
    SELECT bookings.id, classes.name, classes.schedule
    FROM bookings
    JOIN classes ON bookings.class_id = classes.id
    WHERE bookings.user_id = ?
  `).all(req.session.userId);
  res.json(rows);
});

app.delete('/api/bookings/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM bookings WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  res.json({ success: true });
});

app.post('/api/workouts', requireLogin, (req, res) => {
  const { exercise, sets, reps, weight } = req.body;
  const date = new Date().toISOString().split('T')[0];
  db.prepare('INSERT INTO workouts (user_id, exercise, sets, reps, weight, date) VALUES (?, ?, ?, ?, ?, ?)')
    .run(req.session.userId, exercise, sets, reps, weight, date);
  res.json({ success: true });
});

app.get('/api/workouts', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC, id DESC').all(req.session.userId);
  res.json(rows);
});

app.delete('/api/workouts/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM workouts WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  res.json({ success: true });
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const info = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(name, email, hashedPassword);
    req.session.userId = info.lastInsertRowid;
    req.session.userName = name;
    res.json({ success: true, name });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Email already registered.' });
    }
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(400).json({ error: 'Invalid email or password.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid email or password.' });

  req.session.userId = user.id;
  req.session.userName = user.name;
  res.json({ success: true, name: user.name });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, name: req.session.userName });
  } else {
    res.json({ loggedIn: false });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
