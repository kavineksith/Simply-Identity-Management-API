const express = require('express');
const app = express();
const { request, response } = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const db = require('./database.js');

// Cross Origin Resource Sharing
const cors = require('cors');
// middleware for cors
app.use(cors({ origin: '*' }));

// middleware to handle urlencoded data
// 'content-type: application/x-www-form-urlencoded'
app.use(bodyParser.urlencoded({ extended: false }));
// middleware for json
app.use(bodyParser.json());

const port = process.env.PORT || 8080;
const hostname = '127.0.0.1';
// const ENV_FILE_PATH = '/path/to/your/custom/env/file'; // Change this to your custom file path

// Load environment variables from custom-named file
// require('dotenv').config({ path: ENV_FILE_PATH });

// Set JWT secret key
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');

// Middleware to enable basic security headers
app.use(helmet());

// Middleware to limit request rate
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);

// Middleware to generate API key and secret key
const generateApiKeyAndSecret = (req, res, next) => {
    const apiKey = crypto.randomBytes(16).toString('hex');
    const secretKey = crypto.randomBytes(32).toString('hex');
    req.apiKey = apiKey;
    req.secretKey = secretKey;

    // Save generated keys to the database
    const insertQuery = 'INSERT INTO api_keys (api_key, secret_key) VALUES (?, ?)';
    db.run(insertQuery, [apiKey, secretKey], function (err) {
        if (err) {
            console.error('Error inserting keys into database:', err.message);
            return res.status(500).json({ error: 'Internal server error.' });
        }
        next();
    });
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'Authorization header is required.' });
    }

    // Decode the JWT token to obtain the API key
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ error: 'Token has expired. Please log in again.' });
            }
            return res.status(403).json({ error: 'Failed to authenticate token.' });
        }
        const apiKey = decoded.apiKey;

        // Query the database for the API key
        const selectQuery = 'SELECT secret_key FROM api_keys WHERE api_key = ?';
        db.get(selectQuery, [apiKey], (err, row) => {
            if (err) {
                console.error('Error querying database:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }
            if (!row) {
                return res.status(403).json({ error: 'Invalid API key.' });
            }

            // Verify the secret key against the stored value
            const storedSecretKey = row.secret_key;
            const providedSecretKey = req.headers['secretkey'];
            if (providedSecretKey !== storedSecretKey) {
                return res.status(403).json({ error: 'Invalid secret key.' });
            }

            next();
        });
    });
};

// Generate API keys and secret keys
app.get('/generate-keys', generateApiKeyAndSecret, (req, res) => {
    res.json({ apiKey: req.apiKey, secretKey: req.secretKey });
});

// Login endpoint to issue JWT tokens
app.post('/login', (req, res) => {
    const { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ error: 'API key and secret key are required.' });
    }

    // Query the database to verify API key and secret key
    const selectQuery = 'SELECT * FROM api_keys WHERE api_key = ? AND secret_key = ?';
    db.get(selectQuery, [apiKey, secretKey], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            return res.status(500).json({ error: 'Internal server error.' });
        }
        if (!row) {
            return res.status(403).json({ error: 'Invalid API key or secret key.' });
        }

        // Issue a JWT token containing the API key
        const token = jwt.sign({ apiKey }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Create an user
app.post('/users/insert/', verifyToken, (req, res) => {
    try {
        const { 
            fname,
            lname,
            dateOfBirth,
            address,
            emailAddress,
            contactNumber,
            country } = req.body;

        if (!(fname, lname, dateOfBirth, address, emailAddress, contactNumber, country)) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        const insertQuery = 'INSERT INTO users (fname, lname, dateOfBirth, address, emailAddress, contactNumber, country)VALUES(?,?,?,?,?,?,?)';
        const params = [fname, lname, dateOfBirth, address, emailAddress, contactNumber, country];
        db.run(insertQuery, params, function (err) {
            if (err) {
                console.error('Error inserting item:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }

            res.status(201).json({ message: 'User created successfully.', itemId: this.lastID });
        });
    } catch (E) {
        console.error(E);
        res.status(400).send("Bad Request.");
    }
});

// Read all users
app.get('/users/view/', verifyToken, (req, res) => {
    try {
        const selectQuery = 'SELECT * FROM users';
        db.all(selectQuery, (err, rows) => {
            if (err) {
                console.error('Error fetching users:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }
            res.status(201).json({ "data": rows });
        });
    } catch (E) {
        console.error(E);
        res.status(400).send("Bad Request.");
    }
});

// Read an user
app.get('/users/view/:id', verifyToken, (req, res) => {
    try {
        const { id } = req.params;
        if (!id) {
            return res.status(400).json({ error: 'User ID is required.' });
        }

        const selectQuery = 'SELECT * FROM users WHERE UserID = ?';
        const params = [id];
        db.all(selectQuery, params, function (err, rows) {
            if (err) {
                console.error('Error fetching user:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }

            res.json({ "data": rows });
        });
    } catch (E) {
        console.error(E);
        res.status(400).send("Bad Request.");
    }
});

// Update an user
app.put('/users/modify/:id', verifyToken, (req, res) => {
    try {
        const { id } = req.params;
        const { 
            fname,
            lname,
            dateOfBirth,
            address,
            emailAddress,
            contactNumber,
            country } = req.body;

        if (!(fname, lname, dateOfBirth, address, emailAddress, contactNumber, country)) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        const updateQuery = 'UPDATE users SET fname=?, lname=?, dateOfBirth=?, address=?, emailAddress=?, contactNumber=?, country=? WHERE userID=?';
        const params = [fname, lname, dateOfBirth, address, emailAddress, contactNumber, country, id]

        db.run(updateQuery, params, function (err) {
            if (err) {
                console.error('Error updating user:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.json({ message: 'User updated successfully.', itemId: id });
        });
    } catch (E) {
        res.status(400).send(E);
    }
});

// Delete an user
app.delete('/items/:id', verifyToken, (req, res) => {
    try {
        const { id } = req.params;
        if (!id) {
            return res.status(400).json({ error: 'User ID is required.' });
        }

        const deleteQuery = 'DELETE FROM users WHERE UserID = ?';
        const params = [id];
        db.run(deleteQuery, params, function (err) {
            if (err) {
                console.error('Error deleting user:', err.message);
                return res.status(500).json({ error: 'Internal server error.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.json({ message: 'User deleted successfully.', itemId: id });
        });
    } catch (E) {
        console.error('Exception in DELETE /items/:id:', E);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// server initializing and starting with custom hostname and port
app.listen(port, hostname, () => {
    console.log(`Server is running on http://${hostname}:${port}/`);
});
