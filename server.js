// Load environment variables
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const AES_SECRET = process.env.AES_SECRET || 'secret';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
app.set('trust proxy', true);

// Email transporter configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Generate verification token
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Send verification email
const sendVerificationEmail = async (email, token) => {
  const verificationLink = `https://be16-2404-160-8207-8fe6-7436-83d0-2505-932e.ngrok-free.app/verify-email?token=${encodeURIComponent(token)}`;
  
  const mailOptions = {
    from: EMAIL_USER,
    to: email,
    subject: 'Verify Your Email',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2d3748; text-align: center;">Email Verification</h1>
        <p style="color: #4a5568; font-size: 16px; line-height: 1.6;">
          Thank you for registering! Please click the button below to verify your email address:
        </p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationLink}" 
             style="background: linear-gradient(135deg, #00b09b, #96c93d);
                    color: white;
                    padding: 12px 30px;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 500;
                    display: inline-block;">
            Verify Email
          </a>
        </div>
        <p style="color: #718096; font-size: 14px; text-align: center;">
          This link will expire in 24 hours.
        </p>
        <p style="color: #718096; font-size: 14px; text-align: center;">
          If you didn't create an account, you can safely ignore this email.
        </p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Verification email sent successfully to:', email); // Debug log
    return true;
  } catch (error) {
    console.error('Error sending verification email:', error);
    return false;
  }
};

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: '*'
}));
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error('Database connection failed:', err);
  else console.log('Connected to SQLite database');
});

// Create Tables
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, is_verified BOOLEAN DEFAULT 0, verification_token TEXT)');
db.run('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, original_name TEXT, description TEXT, upload_ip TEXT, FOREIGN KEY(user_id) REFERENCES users(id))');

// Hash IP Function
const hashIp = (ip) => {
  // For IPv6 addresses, only use the first 3 blocks
  if (ip.includes(':')) {
    const blocks = ip.split(':');
    ip = blocks.slice(0, 3).join(':');
  }
  return crypto.createHash('sha256').update(ip).digest('hex');
};

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or Expired Token' });

    req.user = user;
    next();
  });
};

// File Storage Configuration
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    const randomName = crypto.randomBytes(16).toString("hex");
    const extension = path.extname(file.originalname);
    const secureFilename = `${randomName}${extension}`;
    cb(null, secureFilename);
  },
});
const upload = multer({ storage });

// AES Encryption Function
const encryptFile = (inputPath, outputPath) => {
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(AES_SECRET, "utf-8"), Buffer.alloc(16, 0));
  const input = fs.createReadStream(inputPath);
  const output = fs.createWriteStream(outputPath);
  input.pipe(cipher).pipe(output);
};

// AES Decryption Function
const decryptFile = (inputPath, outputPath) => {
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(AES_SECRET, "utf-8"), Buffer.alloc(16, 0));
  const input = fs.createReadStream(inputPath);
  const output = fs.createWriteStream(outputPath);
  input.pipe(decipher).pipe(output);
};

// 🟢 UPLOAD FILE (AES Encryption)
app.post("/upload", authenticateToken, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  const userId = req.user.id;
  const filename = req.file.filename;
  const filePath = `./uploads/${filename}`; //https://cdn.domain.com
  const encryptedPath = `./uploads/encrypted_${filename}`;
  const description = req.body.description;
  const uploadIpHash = hashIp(req.ip);

  encryptFile(filePath, encryptedPath);

  // Save to DB with description and upload IP
  db.run("INSERT INTO files (user_id, filename, original_name, description, upload_ip) VALUES (?, ?, ?, ?, ?)",
    [userId, `encrypted_${filename}`, req.file.originalname, description, uploadIpHash], (err) => {
      if (err) return res.status(500).json({ message: "Database error" });

      // Remove original file after encryption
      fs.unlink(filePath, () => res.json({
        message: "File uploaded and encrypted successfully",
        filename: `encrypted_${filename}`,
        description: description
      }));
    });
});

// 🟢 VIEW OR DOWNLOAD FILE (AES Decryption)
app.get("/file/:filename", authenticateToken, (req, res) => {
  const { filename } = req.params;
  const userId = req.user.id;
  const userIpHash = hashIp(req.ip);

  db.get("SELECT * FROM files WHERE filename = ? AND user_id = ?", [filename, userId], (err, file) => {
    if (err || !file) return res.status(404).json({ message: "File not found" });

    if (file.upload_ip !== userIpHash) return res.status(403).json({ message: "Your IP does not match the registered IP" });

    const encryptedPath = `./uploads/${filename}`;
    const decryptedPath = `./uploads/decrypted_${filename.replace("encrypted_", "")}`;

    decryptFile(encryptedPath, decryptedPath);

    setTimeout(() => {
      res.download(decryptedPath, file.original_name, (err) => {
        if (!err) fs.unlink(decryptedPath, () => { });
      });
    }, 1000);
  });
});

// 🟢 LOGOUT
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.clearCookie('name');
  res.json({ message: 'Logged out successfully' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.is_verified) {
      return res.status(403).json({ 
        message: 'Please verify your email before logging in',
        needsVerification: true
      });
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

      res.cookie('token', token, {secure: false, maxAge: 3600000});
      res.cookie('name', username, {secure: false, maxAge: 3600000});

      res.json({ message: 'Login successful' });
    });
  });
});

// 🟢 REGISTER
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  console.log('Registration attempt for:', { username, email }); // Debug log

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  // Check if email already exists
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('Database error checking email:', err); // Debug log
      return res.status(500).json({ message: 'Database error' });
    }
    if (user) {
      console.log('Email already registered:', email); // Debug log
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationToken();
    
    console.log('Generated verification token:', verificationToken); // Debug log

    // First, check if the token is unique
    db.get('SELECT * FROM users WHERE verification_token = ?', [verificationToken], async (err, existingToken) => {
      if (err) {
        console.error('Error checking token uniqueness:', err); // Debug log
        return res.status(500).json({ message: 'Database error' });
      }
      
      if (existingToken) {
        console.log('Token collision detected, generating new token'); // Debug log
        // If token exists, generate a new one
        const newToken = generateVerificationToken();
        insertUser(username, hashedPassword, email, newToken, res);
      } else {
        insertUser(username, hashedPassword, email, verificationToken, res);
      }
    });
  });
});

// Helper function to insert user
const insertUser = async (username, hashedPassword, email, verificationToken, res) => {
  console.log('Inserting user with token:', verificationToken); // Debug log
  
  const stmt = db.prepare('INSERT INTO users (username, password, email, verification_token) VALUES (?, ?, ?, ?)');
  
  stmt.run(username, hashedPassword, email, verificationToken, async function (err) {
    if (err) {
      console.error('Error inserting user:', err); // Debug log
      return res.status(500).json({ message: 'User registration failed' });
    }

    console.log('User inserted successfully with ID:', this.lastID); // Debug log

    // Verify the token was stored correctly
    db.get('SELECT verification_token FROM users WHERE id = ?', [this.lastID], async (err, user) => {
      if (err) {
        console.error('Error verifying token storage:', err); // Debug log
      } else {
        console.log('Stored verification token:', user.verification_token); // Debug log
      }

      // Send verification email
      const emailSent = await sendVerificationEmail(email, verificationToken);
      
      if (!emailSent) {
        return res.status(500).json({ message: 'Registration successful but failed to send verification email' });
      }

      res.status(201).json({ 
        message: 'User registered successfully',
        username,
        email,
        redirect: `/verify-status?username=${encodeURIComponent(username)}&email=${encodeURIComponent(email)}`
      });
    });
  });
};

// Email verification endpoint
app.get('/verify-email', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify-email.html'));
});

// Email verification API endpoint
app.get('/api/verify-email', (req, res) => {
  const { token } = req.query;

  if (!token) {
    console.log('No token provided'); // Debug log
    return res.status(400).json({ message: 'Verification token is required' });
  }

  console.log('Verifying token:', token); // Debug log

  // First, check if the token exists and is valid
  db.get('SELECT * FROM users WHERE verification_token = ?', [token], (err, user) => {
    if (err) {
      console.error('Database error:', err); // Debug log
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log('No user found with token:', token); // Debug log
      return res.status(400).json({ message: 'Invalid verification token' });
    }

    console.log('Found user:', user); // Debug log

    // Update user verification status
    db.run('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', [user.id], (err) => {
      if (err) {
        console.error('Update error:', err); // Debug log
        return res.status(500).json({ message: 'Failed to verify email' });
      }
      
      console.log('Successfully verified user:', user.id); // Debug log
      res.json({ 
        message: 'Email verified successfully',
        username: user.username
      });
    });
  });
});

app.delete('/file/:filename', authenticateToken, (req, res) => {
  const { filename } = req.params;
  const { id: userId } = req.user;
  const userIpHash = hashIp(req.ip);

  db.get('SELECT * FROM files WHERE filename = ? AND user_id = ?', [filename, userId], (err, file) => {
    if (err || !file) return res.status(404).json({ message: 'File not found or access denied' });

    if (file.upload_ip !== userIpHash) {
      return res.status(403).json({ message: 'Your IP does not match the registered IP' });
    }

    const encryptedFilePath = path.join(__dirname, 'uploads', `encrypted_${filename}`);
    const decryptedFilePath = path.join(__dirname, 'uploads', filename);

    fs.unlink(encryptedFilePath, (err) => {
      if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Failed to delete the encrypted file' });

      fs.unlink(decryptedFilePath, (err) => {
        if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Failed to delete the decrypted file' });

        db.run('DELETE FROM files WHERE filename = ? AND user_id = ?', [filename, userId], (err) => {
          if (err) return res.status(500).json({ message: 'Failed to delete file record from database' });
          res.json({ message: 'File deleted successfully' });
        });
      });
    });
  });
});

app.get('/files', authenticateToken, (req, res) => {
  const { id: userId } = req.user;
  const userIpHash = hashIp(req.ip);
  console.log(req.ip);

  db.all('SELECT filename, original_name, description, upload_ip FROM files WHERE user_id = ?', [userId], (err, files) => {
    if (err) return res.status(500).json({ message: 'Failed to retrieve files' });

    if (files.length === 0) return res.json({ message: 'No files found' });

    const responseFiles = files.map(file => ({
      filename: file.filename,
      original_name: file.original_name,
      description: file.description,
      ip_status: file.upload_ip === userIpHash ? 'same' : 'different'
    }));

    res.json({ files: responseFiles });
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/upload', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'upload.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Add new endpoint for verification status page
app.get('/verify-status', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify-status.html'));
});

// Check verification status endpoint
app.post('/check-verification', (req, res) => {
  const { username, email } = req.body;

  db.get('SELECT is_verified FROM users WHERE username = ? AND email = ?', [username, email], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ verified: user.is_verified === 1 });
  });
});

// Resend verification email endpoint
app.post('/resend-verification', async (req, res) => {
  const { username, email } = req.body;

  db.get('SELECT * FROM users WHERE username = ? AND email = ?', [username, email], async (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.is_verified === 1) {
      return res.json({ success: false, message: 'Email already verified' });
    }

    const verificationToken = generateVerificationToken();
    
    db.run('UPDATE users SET verification_token = ? WHERE id = ?', [verificationToken, user.id], async (err) => {
      if (err) return res.status(500).json({ success: false, message: 'Failed to update verification token' });

      const emailSent = await sendVerificationEmail(email, verificationToken);
      
      if (!emailSent) {
        return res.status(500).json({ success: false, message: 'Failed to send verification email' });
      }

      res.json({ success: true, message: 'Verification email sent successfully' });
    });
  });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});