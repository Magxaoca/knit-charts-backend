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
app.use(express.urlencoded({ extended: true, limit: "8mb" }));

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
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_ends BIGINT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS pro_until BIGINT");
  // выдать пробный период тем, у кого его ещё нет (старые аккаунты)
  await pool.query("UPDATE users SET trial_ends=$1 WHERE trial_ends IS NULL AND pro_until IS NULL", [Date.now() + Number(process.env.TRIAL_DAYS || 3) * 86400 * 1000]);
  console.log("DB ready");
}

const TRIAL_DAYS = Number(process.env.TRIAL_DAYS || 3);
const DAY = 86400 * 1000;
function accessInfo(u) {
  const now = Date.now();
  const proUntil = Number(u.pro_until || 0);
  const trialEnds = Number(u.trial_ends || 0);
  const pro = proUntil > now;
  const trialActive = trialEnds > now;
  return { pro, proUntil, trialEnds, trialActive, access: pro || trialActive };
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
    const trialEnds = Date.now() + TRIAL_DAYS * DAY;
    const r = await pool.query("INSERT INTO users(email,password_hash,trial_ends) VALUES($1,$2,$3) RETURNING id,email", [email, hash, trialEnds]);
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

app.get("/api/me", auth, async (req, res) => {
  try {
    const r = await pool.query("SELECT email, pro_until, trial_ends FROM users WHERE id=$1", [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Пользователь не найден" });
    res.json(Object.assign({ email: r.rows[0].email }, accessInfo(r.rows[0])));
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); }
});

// Ссылки на оплату (публичные страницы офферов LavaTop) и длина пробного
app.get("/api/config", (req, res) => res.json({
  payMonth: process.env.LAVA_URL_MONTH || "",
  payYear: process.env.LAVA_URL_YEAR || "",
  priceMonth: process.env.PRICE_MONTH || "400 ₽",
  priceYear: process.env.PRICE_YEAR || "3500 ₽",
  trialDays: TRIAL_DAYS
}));

// Создание счёта в LavaTop (по API). Только валюта и цена, без выбора метода оплаты.
app.post("/api/pay", auth, async (req, res) => {
  const period = req.body.period === "year" ? "year" : "month";
  const currency = String(req.body.currency || "RUB").toUpperCase();
  const apiKey = process.env.LAVA_API_KEY || process.env.LAVATOP_API_KEY;
  // offerId = «идентификатор цены» оффера в LavaTop (цена берётся из оффера, в запросе суммы НЕТ)
  const offerId = period === "year"
    ? (process.env.LAVA_OFFER_YEAR || process.env.LAVA_OFFER_ID)
    : (process.env.LAVA_OFFER_MONTH || process.env.LAVA_OFFER_ID);
  const base = (process.env.LAVA_API_BASE || process.env.LAVATOP_API_BASE || "https://gate.lava.top").replace(/\/+$/, "");
  if (!apiKey || !offerId) return res.status(500).json({ error: "Оплата не настроена (нужны LAVA_API_KEY и LAVA_OFFER_MONTH/LAVA_OFFER_YEAR)" });
  try {
    // По схеме LavaTop (InvoiceRequestDto) поля amount/price отсутствуют — цена в оффере
    const body = { email: req.user.email, offerId, currency, periodicity: "ONE_TIME", buyerLanguage: "RU" };
    const r = await fetch(base + "/api/v2/invoice", {
      method: "POST",
      headers: { "X-Api-Key": apiKey, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    });
    const j = await r.json().catch(() => ({}));
    console.log("LAVA invoice:", r.status, JSON.stringify(j));
    if (!r.ok) return res.status(502).json({ error: "LavaTop: " + (j.error || j.message || ("код " + r.status)) });
    const url = j.paymentUrl || j.url || j.invoiceUrl || (j.data && (j.data.paymentUrl || j.data.url)) || "";
    if (!url) return res.status(502).json({ error: "LavaTop не вернул ссылку оплаты (см. логи)" });
    res.json({ url });
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка создания оплаты" }); }
});

// Вебхук LavaTop: после оплаты включаем Pro нужному пользователю
app.post("/api/lava/webhook", async (req, res) => {
  try { console.log("LAVA webhook:", JSON.stringify(req.body)); } catch (e) {}
  const key = process.env.LAVA_WEBHOOK_KEY || process.env.LAVATOP_WEBHOOK_KEY;
  const b = req.body || {};
  const got = req.headers["x-api-key"] || req.headers["authorization"] || b.webhookKey || b.secret || b.apiKey;
  if (key && (!got || String(got).replace(/^Bearer\s+/i, "") !== key)) return res.status(401).json({ error: "bad key" });
  const email = norm(b.email || b.buyerEmail || (b.buyer && b.buyer.email) || b.clientEmail || (b.data && b.data.email) || (b.buyer && b.buyer.buyerEmail) || "");
  if (!email) return res.status(200).json({ ok: true, note: "no email in payload" });
  const status = String(b.status || b.eventType || b.event || (b.data && b.data.status) || "").toLowerCase();
  if (status && !/success|complete|paid|active|subscription/.test(status)) return res.status(200).json({ ok: true, note: "ignored status: " + status });
  const offer = String(b.offerId || b.productId || b.offer_id || (b.product && b.product.id) || (b.data && (b.data.offerId || b.data.productId)) || "");
  const mine = [process.env.LAVA_OFFER_ID, process.env.LAVA_OFFER_MONTH, process.env.LAVA_OFFER_YEAR].filter(Boolean);
  if (mine.length && offer && !mine.includes(offer)) return res.status(200).json({ ok: true, note: "other product, ignored" });
  const amount = Number(b.amount || b.sum || b.total || (b.data && b.data.amount) || (b.product && b.product.price) || 0);
  const currency = String(b.currency || b.curr || (b.data && b.data.currency) || "RUB").toUpperCase();
  const yearId = process.env.LAVA_OFFER_YEAR || "", monthId = process.env.LAVA_OFFER_MONTH || "";
  let days = 30;
  if (yearId && offer === yearId) days = 365;
  else if (monthId && offer === monthId) days = 30;
  else { const thr = (currency.includes("USD") || currency.includes("EUR")) ? 20 : 2000; if (amount >= thr) days = 365; }
  try {
    const r = await pool.query("SELECT id, pro_until FROM users WHERE email=$1", [email]);
    if (r.rows.length) {
      const base = Math.max(Date.now(), Number(r.rows[0].pro_until || 0));
      await pool.query("UPDATE users SET pro_until=$1 WHERE id=$2", [base + days * DAY, r.rows[0].id]);
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); }
});

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
