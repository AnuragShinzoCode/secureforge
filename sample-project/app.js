// ============================================================
// SAMPLE VULNERABLE APPLICATION — for demo/testing purposes
// This file contains intentional security anti-patterns.
// ============================================================

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// ❌ Hardcoded secrets
const API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678";
const DB_PASSWORD = "SuperSecret123!";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

// ❌ Insecure database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: DB_PASSWORD,
  database: 'myapp',
});

// ❌ CORS wildcard
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

// ❌ SQL Injection — string concatenation in query
app.get('/users', (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = '" + userId + "'", (err, results) => {
    res.json(results);
  });
});

// ❌ SQL Injection — template literal in query
app.get('/search', (req, res) => {
  const term = req.body.searchTerm;
  db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, (err, results) => {
    res.json(results);
  });
});

// ❌ XSS — innerHTML
app.get('/profile', (req, res) => {
  const html = `<div id="bio"></div>
    <script>document.getElementById('bio').innerHTML = "${req.query.bio}";</script>`;
  res.send(html);
});

// ❌ Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// ❌ Path Traversal
app.get('/file', (req, res) => {
  const filename = req.query.name;
  fs.readFile('/uploads/' + filename, (err, data) => {
    res.send(data);
  });
});

// ❌ Insecure hashing (MD5)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ❌ Insecure random for token generation
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// ❌ eval usage
app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// ❌ TLS verification disabled
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

// ❌ Sensitive data logging
app.post('/login', (req, res) => {
  console.log("Login attempt with password: " + req.body.password);
  const token = generateToken();
  console.log("Generated token: " + token);
  res.json({ token });
});

// ❌ Dangerous unescaped template
app.get('/template', (req, res) => {
  const template = `{{{userInput}}}`;
  res.send(template);
});

// ❌ Private key in source
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF...(truncated)
-----END RSA PRIVATE KEY-----`;

app.listen(3000);
