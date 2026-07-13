// ── RecruitAI Backend (Lemon Squeezy Billing) ──────
// Lemon Squeezy is the Merchant of Record. It handles checkout,
// payment methods, taxes, VAT, subscriptions, failed payments, and
// cancellations. This server only does three things:
//   1. User accounts (signup / login)
//   2. Daily usage tracking and limits
//   3. Listening for Lemon Squeezy webhooks to update plan status
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { stmts } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────
app.use(helmet());

// CORS: allow our own site and any Chrome extension to call the API.
// The cors library doesn't support wildcard patterns like
// "chrome-extension://*", so we check the origin with a function instead.
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, health checks, curl)
    if (!origin) return callback(null, true);
    // Allow any Chrome/Edge extension
    if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://')) {
      return callback(null, true);
    }
    // Allow our own frontend
    if (origin === (process.env.FRONTEND_URL || 'http://localhost:5173')) {
      return callback(null, true);
    }
    // Allow our production domain explicitly
    if (origin === 'https://recruitglobal.work' || origin === 'https://www.recruitglobal.work') {
      return callback(null, true);
    }
    // Otherwise block
    return callback(null, false);
  },
  credentials: true
}));

// Capture the raw body for webhook signature verification,
// but parse JSON normally for every other route.
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhook/lemonsqueezy') {
    express.raw({ type: 'application/json' })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true });
app.use('/api/', limiter);

// ── Auth Helpers ───────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.user = stmts.getUserById.get(decoded.userId);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

const generateToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '30d' });

// ── Plan Limits ───────────────────────────────────
const PLAN_LIMITS = { free: 10, pro: 100, team: 500 };

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AUTH
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, company } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (stmts.getUserByEmail.get(email)) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const result = stmts.createUser.run(email, hash, name || null, company || null);
    res.status(201).json({ token: generateToken(result.lastInsertRowid), userId: result.lastInsertRowid, plan: 'free' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = stmts.getUserByEmail.get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: generateToken(user.id), userId: user.id, plan: user.plan });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SUBSCRIPTION STATUS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.get('/api/subscription/status', auth, (req, res) => {
  const usage = stmts.getTodayUsage.get(req.userId);
  const plan = req.user.plan || 'free';
  res.json({
    plan,
    usage: usage.count,
    limit: PLAN_LIMITS[plan] || 10,
    renewsAt: req.user.plan_renews_at || null,
    // The extension/landing page sends users here to upgrade.
    // Lemon Squeezy hosts the entire checkout - no code needed.
    checkoutUrl: process.env.LEMONSQUEEZY_CHECKOUT_URL || null,
  });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// USAGE TRACKING
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.post('/api/usage/log', auth, (req, res) => {
  const plan = req.user.plan || 'free';
  const limit = PLAN_LIMITS[plan] || 10;
  const usage = stmts.getTodayUsage.get(req.userId);

  if (usage.count >= limit) {
    return res.status(429).json({
      error: 'Daily limit reached',
      used: usage.count,
      limit,
      plan,
      checkoutUrl: plan === 'free' ? process.env.LEMONSQUEEZY_CHECKOUT_URL : null,
    });
  }

  stmts.logUsage.run(req.userId, req.body.action || 'generation');
  res.json({ logged: true, used: usage.count + 1, limit, remaining: limit - usage.count - 1 });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LEMON SQUEEZY WEBHOOK
// One endpoint. Lemon Squeezy calls this when a subscription is
// created, updated, paused, resumed, or cancelled. We just flip the
// user's plan between 'pro' and 'free' based on what they tell us.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.post('/api/webhook/lemonsqueezy', (req, res) => {
  try {
    // 1. Verify the request really came from Lemon Squeezy
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
    const signature = req.headers['x-signature'];
    const hmac = crypto.createHmac('sha256', secret);
    const digest = hmac.update(req.body).digest('hex');

    if (!signature || signature !== digest) {
      console.warn('Invalid webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // 2. Parse the event
    const event = JSON.parse(req.body.toString());
    const eventName = event.meta?.event_name;
    const data = event.data;
    const attrs = data?.attributes || {};

    // The customer's email - the link between Lemon Squeezy and our user
    const email = attrs.user_email;
    const subscriptionId = String(data?.id || '');
    const customerId = String(attrs.customer_id || '');
    const renewsAt = attrs.renews_at || null;

    console.log(`Webhook: ${eventName} for ${email}`);

    // 3. Update the user's plan
    switch (eventName) {
      case 'subscription_created':
      case 'subscription_resumed':
      case 'subscription_unpaused':
        if (email) stmts.setPlanByEmail.run('pro', subscriptionId, customerId, renewsAt, email);
        break;

      case 'subscription_updated': {
        // 'active' or 'on_trial' = pro; anything else = downgrade
        const status = attrs.status;
        const plan = (status === 'active' || status === 'on_trial') ? 'pro' : 'free';
        if (email) stmts.setPlanByEmail.run(plan, subscriptionId, customerId, renewsAt, email);
        break;
      }

      case 'subscription_cancelled':
      case 'subscription_expired':
      case 'subscription_paused':
        // Keep pro until period end on cancel; Lemon Squeezy sends
        // subscription_expired when access should actually end.
        if (eventName === 'subscription_expired') {
          if (subscriptionId) stmts.setPlanBySubscriptionId.run('free', null, subscriptionId);
        }
        break;

      default:
        console.log(`Unhandled event: ${eventName}`);
    }

    res.status(200).json({ received: true });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(200).json({ received: true }); // Always 200 to avoid retries
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AI GENERATION PROXY
// The extension sends a prompt here. We check the user's daily limit,
// call Anthropic with OUR server key, log the usage, and return text.
// The user never needs their own API key.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const SYSTEM_PROMPT = `You are RecruitAI, an assistant for professional recruiters. You help write personalized candidate outreach, structured candidate briefs, role-match assessments, and improved job descriptions.

Rules:
- Always personalize using specific details from the provided profile or posting.
- Keep outreach messages under 150 words.
- Highlight concrete achievements, not generic praise.
- Use inclusive language for job descriptions.
- Never fabricate information — only use what is provided.
- Be specific about match strengths and concerns.
- Output clean, copy-ready plain text. Do NOT use markdown formatting like **bold**, headers, or asterisks. Do not use emoji.
- If the provided data looks sparse or includes navigation/menu text, extract the relevant professional details and proceed anyway. Do not ask the user for more information — work with what is available.`;

app.post('/api/generate', auth, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'A prompt is required' });
    }

    // 1. Enforce the daily limit for this user's plan
    const plan = req.user.plan || 'free';
    const limit = PLAN_LIMITS[plan] || 10;
    const usage = stmts.getTodayUsage.get(req.userId);
    if (usage.count >= limit) {
      return res.status(429).json({
        error: plan === 'free'
          ? 'You have reached your daily free limit. Upgrade to Pro for more.'
          : 'Daily limit reached. It resets tomorrow.',
        used: usage.count,
        limit,
        plan,
        checkoutUrl: plan === 'free' ? process.env.LEMONSQUEEZY_CHECKOUT_URL : null,
      });
    }

    // 2. Call Anthropic with the SERVER's key
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      console.error('ANTHROPIC_API_KEY not set on server');
      return res.status(500).json({ error: 'AI service not configured. Please contact support.' });
    }

    const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6',
        max_tokens: 1024,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!aiResp.ok) {
      const errBody = await aiResp.json().catch(() => ({}));
      console.error('Anthropic error:', aiResp.status, errBody);
      return res.status(502).json({ error: 'The AI service had a problem. Please try again in a moment.' });
    }

    const aiData = await aiResp.json();
    const text = aiData.content?.[0]?.text || '';

    // 3. Log the usage (counts against the daily limit)
    stmts.logUsage.run(req.userId, 'generation');

    // 4. Return the result plus updated usage
    res.json({
      result: text,
      usage: { used: usage.count + 1, limit, remaining: limit - usage.count - 1, plan },
    });
  } catch (err) {
    console.error('Generate error:', err);
    res.status(500).json({ error: 'Something went wrong generating your result. Please try again.' });
  }
});

// ── Health Check ───────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', billing: 'lemonsqueezy', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`\n  RecruitAI Backend running on port ${PORT}`);
  console.log(`  Billing: Lemon Squeezy (Merchant of Record)`);
  console.log(`  Environment: ${process.env.NODE_ENV || 'development'}\n`);
});

module.exports = app;
