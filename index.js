require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
const cors = require('cors');

const corsOptions = {
    origin: ['http://localhost:3000', 
        'http://127.0.0.1:5500'
    ], 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  };

app.use(cors(corsOptions));

const client = new Client({
    connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: 70000
});

client.connect()
    .then(() => console.log('Connected to PostgreSQL database'))
    .catch(err => console.error('Connection error', err.stack));

let verificationCodes = {};

const transporter = nodemailer.createTransport({
    host: 'mail.privateemail.com',
    port: 465,
    secure: true, 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, 
    },
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Login error', details: err.message });
    }
});


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const resetCode = Math.floor(100000 + Math.random() * 900000); 

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Your password reset code: ${resetCode}`,
        });

        verificationCodes[email] = resetCode;

        return res.status(200).json({ message: 'Password reset code sent to your email.' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Error sending the code.' });
    }
});


app.post('/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;

    if (verificationCodes[email] && verificationCodes[email].toString() === code.toString()) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        try {
            await client.query(
                'UPDATE users SET password = $1 WHERE email = $2',
                [hashedPassword, email]
            );

            delete verificationCodes[email]; 
            return res.status(200).json({ message: 'Password successfully reset!' });
        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: 'Error resetting password.' });
        }
    } else {
        return res.status(400).json({ error: 'Invalid password reset code.' });
    }
});

app.get('/users', async (req, res) => {
    try {
        const result = await client.query('SELECT * FROM users');
        res.status(200).json(result.rows); 
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error fetching users.' });
    }
});

app.get('/text', async (req, res) => { 
    try {

        res.status(200).send("text"); 
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error fetching users.' });
    }
});


app.post('/calculateGValues', (req, res) => {
    const { dValues, rateValue } = req.body;
  
    if (!Array.isArray(dValues) || !Array.isArray(rateValue) || dValues.length !== rateValue.length) {
      return res.status(400).json({ error: 'Invalid input or mismatched arrays' });
    }
  
    const gValues = [];
    const interestValues = [];
    let previousGValue = 0;
  
    dValues.forEach((dValue, index) => {
      let rate = rateValue[index];
  
      if (rate >= 1) {
        rate = rate / 100;
      }
  
      const interest = (previousGValue + dValue) * rate;
      const gValue = previousGValue + dValue + interest;
  
      interestValues.push(interest);
      gValues.push(gValue);
  
      previousGValue = gValue;
    });
  
    res.json({ gValues, interestValues });
  });
  




  app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        let result = await client.query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await client.query(
                'INSERT INTO users (email, password) VALUES ($1, $2)',
                [email, hashedPassword]
            );

            result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Login error', details: err.message });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
