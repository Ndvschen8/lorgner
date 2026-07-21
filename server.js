/**
 * ══════════════════════════════════════════════
 * LORGNER — BACKEND PROXY
 * Node.js · Express · Railway
 *
 * ALL 7 PROTECTION LAYERS + JWT VERIFICATION
 *
 * THE CLAUDE API KEY LIVES HERE ONLY.
 * It is set as a Railway environment variable.
 * It never appears in frontend code.
 * It never appears in browser network requests.
 * The browser sends a request to this proxy.
 * This proxy adds the key and calls Anthropic.
 *
 * DEPLOY TO RAILWAY:
 * 1. Create new Railway project
 * 2. Upload server.js and package.json
 * 3. Set environment variables (see CONFIG below)
 * 4. Railway auto-detects Node and deploys
 * 5. Copy the Railway URL into frontend CONFIG.PROXY_URL
 *
 * ENVIRONMENT VARIABLES — set in Railway dashboard:
 *   ANTHROPIC_API_KEY   your Claude API key (NEVER share this)
 *   SUPABASE_URL        your Supabase project URL
 *   SUPABASE_SERVICE_KEY your Supabase service role key (for JWT verification)
 *   ALLOWED_ORIGIN      your frontend domain e.g. https://lorgner.com
 *   RATE_LIMIT_MAX      messages per IP per hour (default 20)
 *   PORT                Railway sets this automatically
 * ══════════════════════════════════════════════
 */

'use strict';

const express        = require('express');
const cors           = require('cors');
const rateLimit      = require('express-rate-limit');
const helmet         = require('helmet');
const { randomUUID } = require('crypto');

// Short invite code generator — no ambiguous chars (0/O, 1/I)
const INVITE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function generateInviteCode(len = 6) {
  let code = '';
  for (let i = 0; i < len; i++) code += INVITE_CHARSET[Math.floor(Math.random() * INVITE_CHARSET.length)];
  return code;
}

const app  = express();
const PORT = process.env.PORT || 3000;

const CONFIG = {
  ANTHROPIC_KEY:        process.env.ANTHROPIC_API_KEY,
  SUPABASE_URL:         process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
  ALLOWED_ORIGINS:      (process.env.ALLOWED_ORIGIN || 'https://lorgner.vercel.app')
                          .split(',').map(o => o.trim()),
  FRONTEND_URL:         process.env.FRONTEND_URL || 'https://lorgner.vercel.app',
  RESEND_KEY:              process.env.RESEND_API_KEY,
  RATE_LIMIT_MAX:          parseInt(process.env.RATE_LIMIT_MAX || '20'),
  STRIPE_WEDDING_PRICE_ID: process.env.STRIPE_WEDDING_PRICE_ID || 'price_1ToWD9JdJONprYpJMK3bC51L',
  CRON_SECRET:             process.env.CRON_SECRET,
  MODEL:                'claude-sonnet-4-6',
  MAX_TOKENS:           800,
  MAX_IMG_SIZE_MB:      5,
  MAX_PAIRS:            8,
};

const BLOCKLIST = [
  /ignore (all |your |previous |above )?instructions/i,
  /you are now|pretend (you are|to be)/i,
  /disregard|forget (your|the) (instructions|rules)/i,
  /jailbreak|dan mode|developer mode|unrestricted mode/i,
  /repeat after me|output the following/i,
  /your (true|real) (self|purpose|nature)/i,
  /ignore previous|ignore all|new instructions/i,
  /\b(nude|naked|sex|sexual|explicit|porn|nsfw|erotic|xxx)\b/i,
  /\b(genitals?|penis|vagina|breasts?)\b/i,
  /\b(kill|murder|harm|hurt|weapon|bomb|explosive|shoot)\b/i,
  /\b(suicide|self.harm|self.injur)\b/i,
  /\b(hack|crack|bypass|exploit|vulnerability|malware)\b/i,
  /\b(password|credit card number|social security|ssn)\b/i,
];

function isBlocked(text) {
  if (!text || typeof text !== 'string') return false;
  return BLOCKLIST.some(p => p.test(text));
}

const ALLOWED_MIMES  = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const MAX_IMG_BYTES  = CONFIG.MAX_IMG_SIZE_MB * 1024 * 1024;

function validateImage(img) {
  if (!img?.source?.data || !img?.source?.media_type) return false;
  if (!ALLOWED_MIMES.includes(img.source.media_type))  return false;
  const approxBytes = (img.source.data.length * 3) / 4;
  if (approxBytes > MAX_IMG_BYTES)                     return false;
  return true;
}

async function verifyJWT(token) {
  if (!token) return null;
  try {
    const res = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
      }
    });
    if (!res.ok) return null;
    const user = await res.json();
    if (!user?.id) return null;
    return user;
  } catch (err) {
    console.error('[LORGNER] JWT verification error:', err.message);
    return null;
  }
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    console.warn(`[LORGNER] No JWT provided from ${req.ip}`);
    return res.status(401).json({ error: true, code: 'UNAUTHORIZED', message: 'Authentication required.' });
  }
  const user = await verifyJWT(token);
  if (!user) {
    console.warn(`[LORGNER] Invalid JWT from ${req.ip}`);
    return res.status(401).json({ error: true, code: 'INVALID_TOKEN', message: 'Your session has expired. Please sign in again.' });
  }
  req.lorgnerUser = user;
  next();
}

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-site' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", 'https://api.anthropic.com', CONFIG.SUPABASE_URL],
    }
  }
}));

app.use(express.json({ limit: '50mb' }));

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || CONFIG.ALLOWED_ORIGINS.includes(origin)) {
      cb(null, true);
    } else {
      console.warn(`[LORGNER] CORS blocked: ${origin}`);
      cb(new Error('Not allowed by CORS'));
    }
  },
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const chatLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: CONFIG.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`[LORGNER] Rate limited: ${req.ip}`);
    res.status(429).json({ error: true, code: 'RATE_LIMITED', message: 'Lorgner is here for your collection. What are we styling today?' });
  }
});

async function sendMagicLinkEmail(email, name = '') {
  const magicRes = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/admin/generate_link`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
    },
    body: JSON.stringify({
      type:  'magiclink',
      email,
      options: { redirect_to: `${CONFIG.FRONTEND_URL}/?signin=1` }
    })
  });

  const magicData  = await magicRes.json();
  const actionLink = magicData.action_link || magicData.properties?.action_link;

  if (!actionLink) {
    console.error('[LORGNER] generate_link failed:', JSON.stringify(magicData).slice(0, 300));
    return false;
  }

  const { Resend } = require('resend');
  const resend = new Resend(CONFIG.RESEND_KEY);

  await resend.emails.send({
    from:    'Lorgner <hello@lorgner.co>',
    to:      email,
    subject: 'Your Lorgner access link',
    html: `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#000000;font-family:Georgia,serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#000000;padding:60px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">
        <tr><td align="center" style="padding-bottom:48px;">
          <span style="font-family:Georgia,serif;font-size:28px;letter-spacing:0.15em;color:#9a7d3a;text-transform:uppercase;">Lorgner</span>
        </td></tr>
        <tr><td style="background:#0a0a0a;border:1px solid #1a1a1a;padding:48px 40px;">
          <p style="margin:0 0 24px;font-size:16px;line-height:1.7;color:#c8b87a;">${name ? `Dear ${name},` : 'Welcome,'}</p>
          <p style="margin:0 0 24px;font-size:15px;line-height:1.8;color:#888888;">Your membership is confirmed. Use the link below to access your private intelligence service for your glasses collection.</p>
          <p style="margin:0 0 40px;font-size:13px;line-height:1.8;color:#555555;">This link expires in 24 hours and may only be used once.</p>
          <table cellpadding="0" cellspacing="0" style="margin:0 auto 40px;">
            <tr><td align="center" style="background:#9a7d3a;padding:14px 40px;">
              <a href="${actionLink}" style="color:#000000;text-decoration:none;font-family:Georgia,serif;font-size:13px;letter-spacing:0.1em;text-transform:uppercase;">Enter Lorgner</a>
            </td></tr>
          </table>
          <p style="margin:0;font-size:11px;line-height:1.6;color:#333333;">If the button does not work, <a href="${actionLink}" style="color:#9a7d3a;text-decoration:underline;">click here</a> to access your account.</p>
        </td></tr>
        <tr><td align="center" style="padding-top:32px;">
          <p style="margin:0;font-size:11px;color:#333333;letter-spacing:0.05em;">LORGNER &middot; PRIVATE INTELLIGENCE FOR YOUR COLLECTION</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  });

  return true;
}

/* ══════════════════════════════════════════════
   HEALTH CHECK
══════════════════════════════════════════════ */
app.get('/health', (req, res) => {
  res.json({ status: 'Lorgner is ready.', timestamp: new Date().toISOString() });
});

/* ══════════════════════════════════════════════
   MAGIC LINK ENDPOINT
══════════════════════════════════════════════ */
const magicLinkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: true, message: 'Too many requests. Please wait before trying again.' }),
});

app.post('/send-magic-link', magicLinkLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: true, message: 'Email required.' });
  }
  try {
    await sendMagicLinkEmail(email.trim().toLowerCase());
    console.log(`[LORGNER] Magic link sent: ${email}`);
  } catch (err) {
    console.error('[LORGNER] send-magic-link error:', err.message);
  }
  res.json({ ok: true });
});

/* ══════════════════════════════════════════════
   MAIN CHAT ENDPOINT
══════════════════════════════════════════════ */
app.post('/chat', requireAuth, chatLimiter, async (req, res) => {
  const { system, messages, max_tokens } = req.body;
  const user = req.lorgnerUser;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: true, message: 'Invalid request.' });
  }
  if (messages.length > 60) {
    return res.status(400).json({ error: true, message: 'Session complete. Please begin a new consultation.' });
  }

  const latest = messages[messages.length - 1];
  if (latest?.role === 'user') {
    const textParts = Array.isArray(latest.content)
      ? latest.content.filter(c => c.type === 'text').map(c => c.text).join(' ')
      : (typeof latest.content === 'string' ? latest.content : '');
    if (isBlocked(textParts)) {
      console.log(`[LORGNER] Input blocked | user:${user.id} | "${textParts.slice(0,80)}"`);
      return res.status(200).json({ error: true, code: 'BLOCKED', message: 'Lorgner is here for your collection. What are we styling today?' });
    }
  }

  let imageCount = 0;
  for (const msg of messages) {
    if (!Array.isArray(msg.content)) continue;
    for (const part of msg.content) {
      if (part.type === 'image') {
        imageCount++;
        if (!validateImage(part)) {
          console.warn(`[LORGNER] Invalid image | user:${user.id}`);
          return res.status(400).json({ error: true, message: 'One or more images could not be processed. Please use JPEG or PNG under 5MB.' });
        }
      }
    }
  }
  if (imageCount > CONFIG.MAX_PAIRS) {
    return res.status(400).json({ error: true, message: `Lorgner supports up to ${CONFIG.MAX_PAIRS} pairs per consultation.` });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         CONFIG.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta':    'prompt-caching-2024-07-31',
      },
      body: JSON.stringify({
        model:      CONFIG.MODEL,
        max_tokens: max_tokens || CONFIG.MAX_TOKENS,
        system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
        messages,
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error(`[LORGNER] Anthropic error | user:${user.id} |`, data.error?.message);
      return res.status(500).json({ error: true, message: data.error?.message || 'Lorgner is momentarily unavailable. Please try again.' });
    }

    const aiText = data.content?.[0]?.text || '';
    if (isBlocked(aiText)) {
      console.warn(`[LORGNER] Output filtered | user:${user.id}`);
      return res.status(200).json({ content: [{ type: 'text', text: 'Lorgner is here for your collection. What are we styling today?' }] });
    }

    res.status(200).json(data);
    console.log(`[LORGNER] Chat | user:${user.id.slice(0,8)}… | in:${data.usage?.input_tokens} out:${data.usage?.output_tokens} cached:${data.usage?.cache_read_input_tokens || 0}`);

  } catch (err) {
    console.error(`[LORGNER] Server error | user:${user.id} |`, err.message);
    res.status(500).json({ error: true, message: 'Lorgner is momentarily unavailable. Please try again.' });
  }
});

/* ══════════════════════════════════════════════
   PARTNER INQUIRY ENDPOINT
══════════════════════════════════════════════ */
app.post('/partner-inquiry', async (req, res) => {
  const { name, email, company, type, note, timestamp } = req.body;
  if (!name || !email || !company || !type) {
    return res.status(400).json({ error: true, message: 'Missing required fields.' });
  }
  try {
    const { Resend } = require('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from:    'Lorgner Partners <hello@lorgner.co>',
      to:      'partnerships@lorgner.co',
      replyTo: email,
      subject: `Partner inquiry — ${company}`,
      html: `
        <div style="font-family:Georgia,serif;max-width:520px;margin:0 auto;background:#060608;color:#EEE9DF;padding:40px 36px;">
          <p style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#C9A96E;margin-bottom:24px;">New Partner Inquiry</p>
          <table style="width:100%;border-collapse:collapse;font-size:14px;line-height:1.8;">
            <tr><td style="color:#8A8272;padding:6px 0;width:100px;">Name</td><td style="color:#EEE9DF;">${name}</td></tr>
            <tr><td style="color:#8A8272;padding:6px 0;">Email</td><td style="color:#C9A96E;"><a href="mailto:${email}" style="color:#C9A96E;">${email}</a></td></tr>
            <tr><td style="color:#8A8272;padding:6px 0;">Company</td><td style="color:#EEE9DF;">${company}</td></tr>
            <tr><td style="color:#8A8272;padding:6px 0;">Type</td><td style="color:#EEE9DF;">${type}</td></tr>
            ${note ? `<tr><td style="color:#8A8272;padding:6px 0;vertical-align:top;">Note</td><td style="color:#EEE9DF;">${note}</td></tr>` : ''}
            <tr><td style="color:#8A8272;padding:6px 0;">Submitted</td><td style="color:#4A4438;font-size:12px;">${timestamp || new Date().toISOString()}</td></tr>
          </table>
        </div>`
    });
    console.log(`[LORGNER] Partner inquiry from ${company} (${email})`);
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[LORGNER] Partner inquiry email error:', err.message);
    res.status(200).json({ ok: true });
  }
});

/* ══════════════════════════════════════════════
   UNSUBSCRIBE ENDPOINT
   POST /unsubscribe
══════════════════════════════════════════════ */
app.post('/unsubscribe', async (req, res) => {
  const { email, timestamp } = req.body;
  if (!email) return res.status(400).json({ error: true, message: 'Email required.' });

  try {
    const { Resend } = require('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from:    'Lorgner <hello@lorgner.co>',
      to:      'hello@lorgner.co',
      subject: `Unsubscribe request — ${email}`,
      html: `<p style="font-family:sans-serif;font-size:15px;color:#333;">
        <strong>${email}</strong> has requested to be removed from the Lorgner email list.<br><br>
        <span style="color:#999;font-size:13px;">Submitted: ${timestamp || new Date().toISOString()}</span>
      </p>`
    });
    console.log(`[LORGNER] Unsubscribe: ${email}`);
  } catch (err) {
    console.error('[LORGNER] Unsubscribe email error:', err.message);
  }

  res.json({ ok: true });
});

/* ══════════════════════════════════════════════
   DEMO CHAT ENDPOINT
══════════════════════════════════════════════ */
const demoLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: true, message: 'Demo limit reached. Visit lorgner.co to get full access.' });
  }
});

app.post('/demo-chat', demoLimiter, async (req, res) => {
  const { system, messages, max_tokens } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: true, message: 'Invalid request.' });
  }
  const latest = messages[messages.length - 1];
  if (latest?.role === 'user') {
    const textParts = Array.isArray(latest.content)
      ? latest.content.filter(c => c.type === 'text').map(c => c.text).join(' ')
      : (typeof latest.content === 'string' ? latest.content : '');
    if (isBlocked(textParts)) {
      return res.status(200).json({ error: true, code: 'BLOCKED', message: 'Please keep questions about eyewear styling.' });
    }
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         CONFIG.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      CONFIG.MODEL,
        max_tokens: max_tokens || CONFIG.MAX_TOKENS,
        system: [{ type: 'text', text: system }],
        messages,
      })
    });
    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: true, message: 'Service momentarily unavailable.' });
    res.status(200).json(data);
    console.log(`[LORGNER] Demo chat | ip:${req.ip} | in:${data.usage?.input_tokens} out:${data.usage?.output_tokens}`);
  } catch (err) {
    res.status(500).json({ error: true, message: 'Service momentarily unavailable.' });
  }
});

/* ══════════════════════════════════════════════
   STRIPE CHECKOUT ENDPOINT
══════════════════════════════════════════════ */
app.post('/create-checkout-session', async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: true, message: 'STRIPE_SECRET_KEY not configured on server.' });
  }
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const { email, name } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      allow_promotion_codes: true,
      customer_email: email || undefined,
      line_items: [{ price: process.env.STRIPE_PRICE_ID || 'price_1TX9YYJdJONprYpJHpVIcF6p', quantity: 1 }],
      success_url: `${CONFIG.FRONTEND_URL}/?subscribed=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${CONFIG.FRONTEND_URL}/`,
      metadata: { full_name: name || '' },
    });
    res.json({ checkoutUrl: session.url });
  } catch (err) {
    console.error('[LORGNER] Stripe checkout error:', JSON.stringify(err));
    res.status(500).json({ error: true, message: err.message || 'Checkout unavailable.' });
  }
});

/* ══════════════════════════════════════════════
   BILLING PORTAL ENDPOINT
══════════════════════════════════════════════ */
app.post('/create-portal-session', requireAuth, async (req, res) => {
  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const email = req.lorgnerUser.email;
    const customers = await stripe.customers.list({ email, limit: 1 });
    const customerId = customers.data?.[0]?.id;
    if (!customerId) {
      return res.status(404).json({ error: true, message: 'No billing account found for this email.' });
    }
    const session = await stripe.billingPortal.sessions.create({ customer: customerId, return_url: CONFIG.FRONTEND_URL });
    res.json({ portalUrl: session.url });
  } catch (err) {
    console.error('[LORGNER] Portal session error:', err.message);
    res.status(500).json({ error: true, message: err.message || 'Could not open billing portal.' });
  }
});

/* ══════════════════════════════════════════════
   SESSION ENDPOINT
══════════════════════════════════════════════ */
app.post('/session', requireAuth, async (req, res) => {
  const { occasion, aiReply, pairCount, pairNames } = req.body;
  const user = req.lorgnerUser;
  try {
    const response = await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/sessions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey':       CONFIG.SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        'Prefer':       'return=minimal',
      },
      body: JSON.stringify({
        user_id:    user.id,
        occasion:   occasion?.slice(0, 200),
        ai_reply:   aiReply?.slice(0, 500),
        pair_count: pairCount || 0,
        pair_names: pairNames || [],
        created_at: new Date().toISOString(),
      })
    });
    if (!response.ok) console.error('[LORGNER] Session write failed:', response.status);
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[LORGNER] Session error:', err.message);
    res.status(500).json({ ok: false });
  }
});

/* ══════════════════════════════════════════════
   IMAGE MODERATION ENDPOINT
══════════════════════════════════════════════ */
app.post('/moderate-image', requireAuth, async (req, res) => {
  const { base64, mime } = req.body;
  if (!base64 || !ALLOWED_MIMES.includes(mime)) {
    return res.status(400).json({ ok: false, reason: 'Invalid image format.' });
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CONFIG.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 10,
        system: 'You are a strict image classifier. Respond only with YES or NO — no other text.',
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mime, data: base64 } },
            { type: 'text', text: 'Is the PRIMARY subject of this image a pair of eyeglasses, sunglasses, or optical frames? Answer YES only if glasses or sunglasses are the dominant subject. Answer NO otherwise.' }
          ]
        }]
      })
    });
    if (!response.ok) {
      const errBody = await response.text();
      console.error('[LORGNER] Moderation API error:', response.status, errBody.slice(0, 200));
      return res.json({ ok: false, reason: 'Image validation unavailable. Please try again.' });
    }
    const data   = await response.json();
    const answer = data.content?.[0]?.text?.trim().toUpperCase();
    console.log(`[LORGNER] Moderation answer: "${answer}" | user:${req.lorgnerUser.id.slice(0,8)}`);
    if (!answer) return res.json({ ok: false, reason: 'Image validation unavailable. Please try again.' });
    const ok = answer.startsWith('YES');
    res.json({ ok, reason: ok ? null : 'Please upload a photo of your glasses or sunglasses.' });
  } catch (err) {
    console.error('[LORGNER] Moderation exception:', err.message);
    res.json({ ok: false, reason: 'Image validation unavailable. Please try again.' });
  }
});

/* ══════════════════════════════════════════════
   STRIPE WEBHOOK ENDPOINT
══════════════════════════════════════════════ */
app.use('/stripe-webhook', express.raw({ type: 'application/json' }));

app.post('/stripe-webhook', async (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    console.error(`[LORGNER] Stripe webhook signature failed: ${err.message}`);
    return res.status(400).json({ error: 'Webhook signature verification failed.' });
  }

  console.log(`[LORGNER] Stripe event received: ${event.type}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    if (session.metadata?.type === 'wedding_bundle') {
      try { await handleWeddingCheckout(session); }
      catch (err) { console.error('[LORGNER] Wedding checkout handler failed:', err.message); }
      return res.status(200).json({ received: true });
    }

    const email          = session.customer_details?.email || session.customer_email;
    const name           = session.customer_details?.name || '';
    const customerId     = session.customer;
    const subscriptionId = session.subscription;
    const amountPaid     = session.amount_total;

    if (!email) {
      console.error('[LORGNER] No email in Stripe session');
      return res.status(200).json({ received: true });
    }

    try {
      const signUpRes = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/admin/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        },
        body: JSON.stringify({
          email,
          email_confirm: true,
          user_metadata: {
            full_name:    name,
            member_tier:  amountPaid <= 2900 ? 'founding' : 'standard',
            member_since: new Date().toISOString(),
          }
        })
      });

      let authUser = await signUpRes.json();

      if (!authUser?.id) {
        console.log(`[LORGNER] User may already exist, looking up: ${email}`);
        const listRes = await fetch(
          `${CONFIG.SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
          { headers: { apikey: CONFIG.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}` } }
        );
        const listData = await listRes.json();
        authUser = listData?.users?.[0] || listData?.[0] || authUser;
      }

      const userId = authUser?.id;

      if (userId) {
        await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/members`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
            'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
            'Prefer':        'return=minimal,resolution=ignore-duplicates',
          },
          body: JSON.stringify({
            id:                     userId,
            email,
            full_name:              name,
            member_tier:            amountPaid <= 2900 ? 'founding' : 'standard',
            monthly_rate:           amountPaid,
            stripe_customer_id:     customerId,
            stripe_subscription_id: subscriptionId,
            member_since:           new Date().toISOString(),
          })
        });
      }

      const sent = await sendMagicLinkEmail(email, name);
      if (sent) {
        console.log(`[LORGNER] ✓ Account created, magic link sent: ${email}`);
      } else {
        console.error(`[LORGNER] ✗ Magic link generation failed for: ${email}`);
      }

    } catch (err) {
      console.error('[LORGNER] Account creation failed:', err.message);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const customerId   = subscription.customer;
    await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/members?stripe_customer_id=eq.${customerId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
      },
      body: JSON.stringify({ member_tier: 'cancelled' })
    });
    console.log(`[LORGNER] Subscription cancelled: customer ${customerId}`);
  }

  if (event.type === 'invoice.payment_failed') {
    const invoice    = event.data.object;
    const customerId = invoice.customer;
    await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/members?stripe_customer_id=eq.${customerId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
      },
      body: JSON.stringify({ member_tier: 'paused' })
    });
    console.log(`[LORGNER] Payment failed: customer ${customerId}`);
  }

  res.status(200).json({ received: true });
});

/* ══════════════════════════════════════════════
   WEDDING BUNDLE HELPER
══════════════════════════════════════════════ */
async function handleWeddingCheckout(session) {
  const buyerEmail = session.customer_details?.email || session.customer_email;
  const buyerName  = session.customer_details?.name  || session.metadata?.buyer_name || '';
  const partySize  = parseInt(session.metadata?.party_size || '1', 10);
  const sessionId  = session.id;

  if (!buyerEmail) { console.error('[LORGNER] Wedding checkout: no buyer email'); return; }

  const invitations = Array.from({ length: partySize }, () => ({
    token:       randomUUID(),
    invite_code: generateInviteCode(),
  }));

  for (const inv of invitations) {
    await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/wedding_redemptions`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        'Prefer':        'return=minimal',
      },
      body: JSON.stringify({
        token:             inv.token,
        invite_code:       inv.invite_code,
        stripe_session_id: sessionId,
        buyer_email:       buyerEmail,
        buyer_name:        buyerName,
        party_size:        partySize,
      }),
    });
  }

  const inviteCards = invitations.map((inv, i) => {
    const url     = `${CONFIG.FRONTEND_URL}/gift/${inv.invite_code}`;
    const message = `I've given you six months with Lorgner — a private styling service for your glasses collection, there when you need a considered second opinion. Here's your invitation: ${url}`;
    return `
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;border:1px solid rgba(201,169,110,0.25);background:#FFFCF5;">
      <tr><td style="padding:20px 24px 0;">
        <p style="margin:0;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#9A7A48;">Invitation ${i + 1} of ${partySize}</p>
      </td></tr>
      <tr><td style="padding:10px 24px 6px;">
        <p style="margin:0;font-size:11px;color:#9A8E7E;line-height:1.5;">Copy and send this to your next guest:</p>
      </td></tr>
      <tr><td style="padding:0 24px 20px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(201,169,110,0.06);border-left:2px solid #C9A96E;">
          <tr><td style="padding:16px 18px;">
            <p style="margin:0;font-family:Georgia,serif;font-style:italic;font-size:14px;color:#1E1A14;line-height:1.8;">&ldquo;${message}&rdquo;</p>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:0 24px 16px;">
        <p style="margin:0;font-size:11px;color:#9A8E7E;">Or share the link directly: <a href="${url}" style="color:#C9A96E;text-decoration:none;">lorgner.co/gift/${inv.invite_code}</a></p>
      </td></tr>
    </table>`;
  }).join('');

  const { Resend } = require('resend');
  const resend = new Resend(CONFIG.RESEND_KEY);

  await resend.emails.send({
    from:    'Lorgner <hello@lorgner.co>',
    to:      buyerEmail,
    subject: `Your Lorgner invitations are ready — ${partySize} to send`,
    html: `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#FAF6EE;font-family:Georgia,serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#FAF6EE;padding:60px 20px;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0" style="max-width:580px;width:100%;">
        <tr><td align="center" style="padding-bottom:40px;">
          <span style="font-family:Georgia,serif;font-size:13px;letter-spacing:8px;color:#C9A96E;text-transform:uppercase;">L O R G N E R</span>
        </td></tr>
        <tr><td style="background:#FFFCF5;border:1px solid rgba(30,26,20,0.10);padding:44px 44px 32px;">
          <p style="margin:0 0 6px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#9A7A48;">Your Wedding Party Gift</p>
          <p style="margin:0 0 20px;font-family:Georgia,serif;font-size:26px;font-weight:normal;color:#1E1A14;line-height:1.2;">${partySize} invitation${partySize > 1 ? 's' : ''}, ready to send.</p>
          <p style="margin:0 0 32px;font-size:14px;line-height:1.8;color:#5A5244;">
            ${buyerName ? `Dear ${buyerName},` : 'Hello,'}<br><br>
            Your gift is confirmed. Below are ${partySize} private invitation${partySize > 1 ? 's' : ''} — one for each person. Each card has a message ready to copy and forward. Every link is unique and single-use.
          </p>
          ${inviteCards}
          <p style="margin:24px 0 0;font-size:13px;line-height:1.8;color:#9A8E7E;">Each person's six months begins the day they accept their invitation. After six months they'll have the option to continue at $49/month.</p>
        </td></tr>
        <tr><td style="padding:24px 0 0;text-align:center;">
          <p style="margin:0;font-size:11px;color:#9A8E7E;letter-spacing:1px;">LORGNER &middot; A PRIVATE STYLING MEMBERSHIP</p>
          <p style="margin:6px 0 0;font-size:11px;color:#9A8E7E;">Questions? <a href="mailto:hello@lorgner.co" style="color:#C9A96E;text-decoration:none;">hello@lorgner.co</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  });

  console.log(`[LORGNER] Wedding bundle: ${partySize} invitations sent to ${buyerEmail}`);
}

/* ══════════════════════════════════════════════
   WEDDING CHECKOUT ENDPOINT
══════════════════════════════════════════════ */
app.post('/create-wedding-checkout', async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: true, message: 'Stripe not configured.' });
  }

  const { name, email, partySize } = req.body;
  const size = parseInt(partySize, 10);

  if (!email || !name || !size || size < 1 || size > 20) {
    return res.status(400).json({ error: true, message: 'Invalid request.' });
  }

  try {
    const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.checkout.sessions.create({
      mode:                 'payment',
      payment_method_types: ['card'],
      customer_email:       email,
      line_items: [{ price: CONFIG.STRIPE_WEDDING_PRICE_ID, quantity: size }],
      success_url: `${CONFIG.FRONTEND_URL}/wedding?purchased=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${CONFIG.FRONTEND_URL}/wedding`,
      metadata: { type: 'wedding_bundle', buyer_name: name, party_size: String(size) },
    });

    console.log(`[LORGNER] Wedding checkout created: ${size} guests for ${email}`);
    res.json({ checkoutUrl: session.url });

  } catch (err) {
    console.error('[LORGNER] Wedding checkout error:', err.message);
    res.status(500).json({ error: true, message: err.message || 'Checkout unavailable.' });
  }
});

/* ══════════════════════════════════════════════
   VALIDATE WEDDING TOKEN
══════════════════════════════════════════════ */
app.post('/validate-wedding-token', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ valid: false });

  try {
    const r    = await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/wedding_redemptions?invite_code=eq.${encodeURIComponent(code.toUpperCase())}&select=buyer_name,redeemed_at`,
      { headers: { apikey: CONFIG.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}` } }
    );
    const rows = await r.json();
    const row  = rows?.[0];

    if (!row)            return res.json({ valid: false });
    if (row.redeemed_at) return res.json({ valid: true, alreadyRedeemed: true });
    res.json({ valid: true, alreadyRedeemed: false, buyerName: row.buyer_name || '' });
  } catch (err) {
    console.error('[LORGNER] validate-wedding-token error:', err.message);
    res.status(500).json({ valid: false });
  }
});

/* ══════════════════════════════════════════════
   REDEEM WEDDING GIFT
══════════════════════════════════════════════ */
app.post('/redeem-wedding-gift', async (req, res) => {
  const { code, name, email } = req.body;

  if (!code || !name || !email) {
    return res.status(400).json({ error: true, message: 'Missing required fields.' });
  }

  try {
    const r    = await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/wedding_redemptions?invite_code=eq.${encodeURIComponent(code.toUpperCase())}&select=*`,
      { headers: { apikey: CONFIG.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}` } }
    );
    const rows = await r.json();
    const row  = rows?.[0];

    if (!row) {
      return res.status(404).json({ error: true, message: 'This invitation link is not valid.' });
    }
    if (row.redeemed_at) {
      return res.status(409).json({ error: true, code: 'ALREADY_REDEEMED', message: 'This invitation has already been used.' });
    }

    const membershipEndsAt = new Date(Date.now() + 6 * 30 * 24 * 60 * 60 * 1000).toISOString();

    const signUpRes = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/admin/users`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
      },
      body: JSON.stringify({
        email,
        email_confirm: true,
        user_metadata: {
          full_name:          name,
          member_tier:        'wedding_gift',
          member_since:       new Date().toISOString(),
          membership_ends_at: membershipEndsAt,
          gifted_by:          row.buyer_name || row.buyer_email,
        },
      }),
    });
    let authUser = await signUpRes.json();

    if (!authUser?.id) {
      const listRes  = await fetch(
        `${CONFIG.SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
        { headers: { apikey: CONFIG.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}` } }
      );
      const listData = await listRes.json();
      authUser       = listData?.users?.[0] || listData?.[0] || authUser;
    }

    const userId = authUser?.id;

    if (userId) {
      await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/members`, {
        method:  'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
          'Prefer':        'return=minimal,resolution=ignore-duplicates',
        },
        body: JSON.stringify({
          id:                 userId,
          email,
          full_name:          name,
          member_tier:        'wedding_gift',
          member_since:       new Date().toISOString(),
          membership_ends_at: membershipEndsAt,
        }),
      });
    }

    await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/wedding_redemptions?invite_code=eq.${encodeURIComponent(code.toUpperCase())}`,
      {
        method:  'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        },
        body: JSON.stringify({
          redeemed_at:        new Date().toISOString(),
          redeemed_by_email:  email,
          redeemed_by_name:   name,
          membership_ends_at: membershipEndsAt,
        }),
      }
    );

    await sendMagicLinkEmail(email, name);

    console.log(`[LORGNER] Wedding gift redeemed: ${email} (gifted by ${row.buyer_email})`);
    res.json({ ok: true });

  } catch (err) {
    console.error('[LORGNER] redeem-wedding-gift error:', err.message);
    res.status(500).json({ error: true, message: 'Activation failed. Please try again.' });
  }
});

/* ══════════════════════════════════════════════
   START SERVER
══════════════════════════════════════════════ */
app.listen(PORT, () => {
  console.log(`[LORGNER] Server running on port ${PORT}`);
});
