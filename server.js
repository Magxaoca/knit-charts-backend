"use strict";
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");

const app = express();
app.use(cors());                       // разрешаем запросы с фронта (Vercel)
app.use(express.json({ limit: "8mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "please-change-this-secret";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS projects(
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    data JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, name)
  )`);
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT");
  console.log("DB ready");
}

// Отправка письма. Если заданы SMTP_* — шлём через SMTP (Gmail и т.п.),
// иначе через Resend (RESEND_API_KEY). Адрес отправителя — EMAIL_FROM / MAIL_FROM / SMTP_USER.
let mailer = null;
function getMailer() {
  if (mailer) return mailer;
  if (process.env.SMTP_HOST) {
    const port = Number(process.env.SMTP_PORT || 587);
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
  }
  return mailer;
}
async function sendEmail(to, subject, html) {
  const from = process.env.EMAIL_FROM || process.env.MAIL_FROM || process.env.SMTP_USER || "noreply@kateknit.com";
  const provider = (process.env.EMAIL_PROVIDER || "").toLowerCase();
  const key = process.env.RESEND_API_KEY;
  // Если выбран Resend (или нет SMTP) и есть ключ — шлём через Resend (домен kateknit.com подтверждён)
  const useResend = key && (provider === "resend" || !process.env.SMTP_HOST);
  if (useResend) {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject, html })
    });
    if (!r.ok) throw new Error("Resend error: " + (await r.text()));
    return;
  }
  // Иначе — через SMTP (Gmail и т.п.)
  const m = getMailer();
  if (m) { await m.sendMail({ from, to, subject, html }); return; }
  throw new Error("Почта не настроена: задайте RESEND_API_KEY (+EMAIL_PROVIDER=resend) или SMTP_*");
}
init().catch((e) => console.error("DB init error:", e));

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "Нужен вход" });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: "Сессия истекла, войдите снова" }); }
}
const norm = (e) => String(e || "").trim().toLowerCase();
const tokenFor = (u) => jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: "60d" });

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/register", async (req, res) => {
  const email = norm(req.body.email), password = String(req.body.password || "");
  if (!email || !email.includes("@") || password.length < 6)
    return res.status(400).json({ error: "Введите email и пароль (минимум 6 символов)" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query("INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email", [email, hash]);
    const u = r.rows[0];
    res.json({ token: tokenFor(u), email: u.email });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Такой email уже зарегистрирован" });
    console.error(e); res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/login", async (req, res) => {
  const email = norm(req.body.email), password = String(req.body.password || "");
  try {
    const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!r.rows.length) return res.status(401).json({ error: "Неверный email или пароль" });
    const u = r.rows[0];
    if (!(await bcrypt.compare(password, u.password_hash)))
      return res.status(401).json({ error: "Неверный email или пароль" });
    res.json({ token: tokenFor(u), email: u.email });
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); }
});

app.get("/api/me", auth, (req, res) => res.json({ email: req.user.email }));

// Запрос восстановления пароля — отправляем письмо со ссылкой
app.post("/api/forgot", async (req, res) => {
  const email = norm(req.body.email);
  try {
    const r = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (r.rows.length) {
      const raw = crypto.randomBytes(32).toString("hex");
      const hash = crypto.createHash("sha256").update(raw).digest("hex");
      const exp = Date.now() + 3600 * 1000; // 1 час
      await pool.query("UPDATE users SET reset_token=$1, reset_expires=$2 WHERE id=$3", [hash, exp, r.rows[0].id]);
      const url = (process.env.APP_URL || "https://knit-charts.vercel.app") + "/?reset=" + raw;
      try {
        await sendEmail(email, "Восстановление пароля — Схемы",
          `<div style="font-family:Arial,sans-serif;font-size:15px;color:#2c2722">
            <p>Вы запросили смену пароля в приложении «Схемы».</p>
            <p><a href="${url}" style="display:inline-block;background:#9a6a4f;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Задать новый пароль</a></p>
            <p style="color:#777;font-size:13px">Ссылка действует 1 час. Если это были не вы — просто проигнорируйте письмо.</p>
          </div>`);
      } catch (e) { console.error("mail error:", e.message); }
    }
    res.json({ ok: true }); // не раскрываем, существует ли email
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); }
});

// Установка нового пароля по токену из письма
app.post("/api/reset", async (req, res) => {
  const token = String(req.body.token || ""), password = String(req.body.password || "");
  if (password.length < 6) return res.status(400).json({ error: "Пароль минимум 6 символов" });
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  try {
    const r = await pool.query("SELECT id, reset_expires FROM users WHERE reset_token=$1", [hash]);
    if (!r.rows.length || Number(r.rows[0].reset_expires) < Date.now())
      return res.status(400).json({ error: "Ссылка недействительна или истекла" });
    const ph = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2", [ph, r.rows[0].id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); }
});

app.get("/api/projects", auth, async (req, res) => {
  const r = await pool.query("SELECT id,name,updated_at FROM projects WHERE user_id=$1 ORDER BY updated_at DESC", [req.user.id]);
  res.json(r.rows);
});
app.get("/api/projects/:id", auth, async (req, res) => {
  const r = await pool.query("SELECT id,name,data FROM projects WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!r.rows.length) return res.status(404).json({ error: "Не найдено" });
  res.json(r.rows[0]);
});
app.put("/api/projects", auth, async (req, res) => {
  const name = String(req.body.name || "").trim(), data = req.body.data;
  if (!name || !data) return res.status(400).json({ error: "Нужны название и данные" });
  const r = await pool.query(
    `INSERT INTO projects(user_id,name,data,updated_at) VALUES($1,$2,$3,now())
     ON CONFLICT(user_id,name) DO UPDATE SET data=EXCLUDED.data, updated_at=now()
     RETURNING id,name,updated_at`,
    [req.user.id, name, data]
  );
  res.json(r.rows[0]);
});
app.delete("/api/projects/:id", auth, async (req, res) => {
  await pool.query("DELETE FROM projects WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("API listening on " + PORT));
