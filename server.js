require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new Database(path.join(dataDir, "bondhu-bitto.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','member')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL CHECK(amount > 0),
  kisti_month TEXT NOT NULL,
  paid_date TEXT NOT NULL,
  method TEXT DEFAULT 'Cash',
  reference TEXT DEFAULT '',
  note TEXT DEFAULT '',
  recorded_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_member ON payments(member_id);
CREATE INDEX IF NOT EXISTS idx_payments_month ON payments(kisti_month);
`);

const adminEmail = process.env.ADMIN_EMAIL || "admin@bondhubitto.local";
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 10) {
  console.error("Set ADMIN_PASSWORD in .env (minimum 10 characters).");
  process.exit(1);
}
const existingAdmin = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run(process.env.ADMIN_NAME || "BonDhu Bitto Admin", adminEmail, hash);
  console.log("Initial administrator created:", adminEmail);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
function auth(req, res, next) {
  const token = req.cookies.bb_session;
  if (!token) return res.status(401).json({ error: "Please sign in." });
  try {
    const payload = jwt.verify(token, SECRET);
    const user = db.prepare("SELECT id,name,email,phone,role,active FROM users WHERE id=?").get(payload.id);
    if (!user || !user.active) return res.status(401).json({ error: "Account unavailable." });
    req.user = user;
    next();
  } catch { res.status(401).json({ error: "Session expired. Please sign in again." }); }
}
const adminOnly = (req,res,next) => req.user.role === "admin" ? next() : res.status(403).json({error:"Administrator access required."});
const clean = (v, max=200) => String(v ?? "").trim().slice(0,max);
const validMonth = v => /^\d{4}-(0[1-9]|1[0-2])$/.test(String(v));
const validDate = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v)) && !Number.isNaN(Date.parse(v));
const emailOk = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

app.post("/api/login", loginLimiter, (req,res) => {
  const email = clean(req.body.email,254).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !user.active || !bcrypt.compareSync(password,user.password_hash))
    return res.status(401).json({error:"Email or password is incorrect."});
  const token = jwt.sign({id:user.id}, SECRET, {expiresIn:"12h"});
  res.cookie("bb_session", token, {httpOnly:true, sameSite:"strict", secure:process.env.NODE_ENV==="production", maxAge:12*60*60*1000});
  res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});
app.post("/api/logout", (req,res) => { res.clearCookie("bb_session",{httpOnly:true,sameSite:"strict",secure:process.env.NODE_ENV==="production"}); res.json({ok:true}); });
app.get("/api/me", auth, (req,res) => res.json({user:req.user}));

app.get("/api/dashboard", auth, (req,res) => {
  if (req.user.role === "member") {
    const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=?").get(req.user.id).total;
    const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE member_id=? AND kisti_month=?").get(req.user.id,new Date().toISOString().slice(0,7)).total;
    const payments = db.prepare("SELECT * FROM payments WHERE member_id=? ORDER BY paid_date DESC,id DESC LIMIT 100").all(req.user.id);
    return res.json({member:true,total,current,payments});
  }
  const total = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments").get().total;
  const current = db.prepare("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE kisti_month=?").get(new Date().toISOString().slice(0,7)).total;
  const members = db.prepare("SELECT COUNT(*) count FROM users WHERE role='member' AND active=1").get().count;
  const recent = db.prepare(`SELECT p.*,u.name member_name FROM payments p JOIN users u ON u.id=p.member_id ORDER BY p.paid_date DESC,p.id DESC LIMIT 8`).all();
  res.json({member:false,total,current,members,average:members?total/members:0,recent});
});

app.get("/api/members", auth, adminOnly, (req,res) => {
  const rows = db.prepare(`SELECT u.id,u.name,u.email,u.phone,u.active,u.created_at,
    COALESCE(SUM(p.amount),0) total_saved FROM users u LEFT JOIN payments p ON p.member_id=u.id
    WHERE u.role='member' GROUP BY u.id ORDER BY u.name COLLATE NOCASE`).all();
  res.json({members:rows});
});
app.post("/api/members", auth, adminOnly, (req,res) => {
  const name=clean(req.body.name,100), email=clean(req.body.email,254).toLowerCase();
  const phone=clean(req.body.phone,30), password=String(req.body.password||"");
  if (!name || !emailOk(email) || password.length<10) return res.status(400).json({error:"Enter a name, valid email and a password of at least 10 characters."});
  try {
    const hash=bcrypt.hashSync(password,12);
    const info=db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'member')").run(name,email,phone,hash);
    res.status(201).json({id:info.lastInsertRowid});
  } catch(e) { res.status(409).json({error:e.code==="SQLITE_CONSTRAINT_UNIQUE"?"This email is already registered.":"Could not create member."}); }
});
app.patch("/api/members/:id/status", auth, adminOnly, (req,res) => {
  const active=req.body.active ? 1 : 0;
  const info=db.prepare("UPDATE users SET active=? WHERE id=? AND role='member'").run(active,Number(req.params.id));
  if (!info.changes) return res.status(404).json({error:"Member not found."});
  res.json({ok:true});
});
app.get("/api/payments", auth, (req,res) => {
  const sql=`SELECT p.*,u.name member_name FROM payments p JOIN users u ON u.id=p.member_id`;
  const rows=req.user.role==="admin"
    ? db.prepare(sql+" ORDER BY p.paid_date DESC,p.id DESC LIMIT 500").all()
    : db.prepare(sql+" WHERE p.member_id=? ORDER BY p.paid_date DESC,p.id DESC LIMIT 500").all(req.user.id);
  res.json({payments:rows});
});
app.post("/api/payments", auth, adminOnly, (req,res) => {
  const memberId=Number(req.body.memberId), amount=Number(req.body.amount);
  const month=clean(req.body.month,7), date=clean(req.body.date,10);
  const method=clean(req.body.method,30)||"Cash", reference=clean(req.body.reference,80), note=clean(req.body.note,250);
  const member=db.prepare("SELECT id FROM users WHERE id=? AND role='member' AND active=1").get(memberId);
  if (!member || !Number.isFinite(amount) || amount<=0 || amount>100000000 || !validMonth(month) || !validDate(date))
    return res.status(400).json({error:"Check member, amount, kisti month and payment date."});
  const info=db.prepare("INSERT INTO payments(member_id,amount,kisti_month,paid_date,method,reference,note,recorded_by) VALUES(?,?,?,?,?,?,?,?)")
    .run(memberId,amount,month,date,method,reference,note,req.user.id);
  res.status(201).json({id:info.lastInsertRowid});
});
app.delete("/api/payments/:id", auth, adminOnly, (req,res) => {
  const info=db.prepare("DELETE FROM payments WHERE id=?").run(Number(req.params.id));
  if(!info.changes) return res.status(404).json({error:"Payment not found."});
  res.json({ok:true});
});
app.get("/api/report.csv", auth, adminOnly, (req,res) => {
  const rows=db.prepare(`SELECT u.name,u.email,u.phone,p.kisti_month,p.paid_date,p.amount,p.method,p.reference,p.note
    FROM payments p JOIN users u ON u.id=p.member_id ORDER BY p.paid_date DESC,p.id DESC`).all();
  const q=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const csv=[["Member","Email","Phone","Kisti month","Paid date","Amount BDT","Method","Reference","Note"],...rows.map(r=>[r.name,r.email,r.phone,r.kisti_month,r.paid_date,r.amount,r.method,r.reference,r.note])]
    .map(row=>row.map(q).join(",")).join("\r\n");
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="bondhu-bitto-report.csv"');
  res.send("\ufeff"+csv);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`BonDhu Bitto running at http://localhost:${PORT}`));
