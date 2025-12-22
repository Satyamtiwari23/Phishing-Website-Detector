// server.js
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const users = [];

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ message: 'Name, email and password required' });
  if (users.find(u => u.email === email)) return res.status(409).json({ message: 'User exists' });
  users.push({ name, email, password });
  return res.json({ message: 'Account created successfully' });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
  const u = users.find(x => x.email === email && x.password === password);
  if (!u) return res.status(401).json({ message: 'Invalid credentials' });
  return res.json({ message: 'Login successful', token: 'demo-token' });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));

  const toggle = document.getElementById("accountToggle");
  const menu = document.getElementById("accountMenu");

  toggle.addEventListener("click", () => {
    menu.style.display = menu.style.display === "block" ? "none" : "block";
  });

  document.addEventListener("click", (e) => {
    if (!toggle.contains(e.target) && !menu.contains(e.target)) {
      menu.style.display = "none";
    }
  });

  const accountBtn = document.getElementById("accountBtn");
  const accountMenu = document.getElementById("accountMenu");

  accountBtn.addEventListener("click", () => {
    accountMenu.classList.toggle("show");
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".account-wrapper")) {
      accountMenu.classList.remove("show");
    }
  });
