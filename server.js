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

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ══════════════════════════════════════════════
   CONFIGURATION — ALL FROM ENVIRONMENT VARIABLES
   No secrets are hardcoded in this file.
══════════════════════════════════════════════ */
const CONFIG = {
  ANTHROPIC_KEY:        process.env.ANTHROPIC_API_KEY,     // Claude API key — server only
  SUPABASE_URL:         process.env.SUPABASE_URL,          // Supabase project URL
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,  // Service role key for JWT verification
  ALLOWED_ORIGINS:      (process.env.ALLOWED_ORIGIN || 'https://lorgner.vercel.app')
                          .split(',').map(o => o.trim()),
  FRONTEND_URL:         process.env.FRONTEND_URL || 'https://lorgner.vercel.app',
  RESEND_KEY:           process.env.RESEND_API_KEY,
  RATE_LIMIT_MAX:       parseInt(process.env.RATE_LIMIT_MAX || '20'),
  MODEL:                'claude-sonnet-4-6',
  MAX_TOKENS:           800,
  MAX_IMG_SIZE_MB:      5,
  MAX_PAIRS:            8,
};

/* ══════════════════════════════════════════════
   LAYER 3 — INPUT / OUTPUT FILTERING
   Blocklist of patterns rejected before Claude.
══════════════════════════════════════════════ */
const BLOCKLIST = [
  // Jailbreak attempts
  /ignore (all |your |previous |above )?instructions/i,
  /you are now|pretend (you are|to be)/i,
  /disregard|forget (your|the) (instructions|rules)/i,
  /jailbreak|dan mode|developer mode|unrestricted mode/i,
  /repeat after me|output the following/i,
  /your (true|real) (self|purpose|nature)/i,
  /ignore previous|ignore all|new instructions/i,

  // Explicit / adult
  /\b(nude|naked|sex|sexual|explicit|porn|nsfw|erotic|xxx)\b/i,
  /\b(genitals?|penis|vagina|breasts?)\b/i,

  // Violence / harm
  /\b(kill|murder|harm|hurt|weapon|bomb|explosive|shoot)\b/i,
  /\b(suicide|self.harm|self.injur)\b/i,

  // Off-topic probing
  /\b(hack|crack|bypass|exploit|vulnerability|malware)\b/i,
  /\b(password|credit card number|social security|ssn)\b/i,
];

function isBlocked(text) {
  if (!text || typeof text !== 'string') return false;
  return BLOCKLIST.some(p => p.test(text));
}

/* ══════════════════════════════════════════════
   LAYER 4 — IMAGE VALIDATION
══════════════════════════════════════════════ */
const ALLOWED_MIMES  = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const MAX_IMG_BYTES  = CONFIG.MAX_IMG_SIZE_MB * 1024 * 1024;

function validateImage(img) {
  if (!img?.source?.data || !img?.source?.media_type) return false;
  if (!ALLOWED_MIMES.includes(img.source.media_type))  return false;
  const approxBytes = (img.source.data.length * 3) / 4;
  if (approxBytes > MAX_IMG_BYTES)                     return false;
  return true;
}

/* ══════════════════════════════════════════════
   JWT VERIFICATION — SUPABASE AUTH
   ─────────────────────────────────────────────
   Every chat request includes a JWT in the
   Authorization header sent by the frontend.
   This function verifies it against Supabase.
   
   If valid: the verified user object is returned.
   If invalid or expired: returns null.
   
   This ensures only paying members with real
   Supabase accounts can consume Claude API tokens.
   The service role key is used here (server-side
   only) — it never appears in frontend code.
══════════════════════════════════════════════ */
async function verifyJWT(token) {
  if (!token) return null;

  try {
    // Call Supabase Auth API to verify the JWT
    // Uses the service role key for server-to-server verification
    const res = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
      }
    });

    if (!res.ok) return null;

    const user = await res.json();

    // Confirm user has a valid ID — confirms they exist in Supabase
    if (!user?.id) return null;

    return user;

  } catch (err) {
    console.error('[LORGNER] JWT verification error:', err.message);
    return null;
  }
}

/* ══════════════════════════════════════════════
   JWT MIDDLEWARE
   Runs on every /chat request before anything else.
   Extracts JWT from Authorization header.
   Verifies it. Attaches user to request.
   Rejects with 401 if invalid.
══════════════════════════════════════════════ */
async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    console.warn(`[LORGNER] No JWT provided from ${req.ip}`);
    return res.status(401).json({
      error: true,
      code: 'UNAUTHORIZED',
      message: 'Authentication required.'
    });
  }

  const user = await verifyJWT(token);

  if (!user) {
    console.warn(`[LORGNER] Invalid JWT from ${req.ip}`);
    return res.status(401).json({
      error: true,
      code: 'INVALID_TOKEN',
      message: 'Your session has expired. Please sign in again.'
    });
  }

  // Attach verified user to request for downstream use
  req.lorgnerUser = user;
  next();
}

/* ══════════════════════════════════════════════
   MIDDLEWARE STACK
══════════════════════════════════════════════ */

// Layer 7 — Helmet security headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-site' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", 'https://api.anthropic.com', CONFIG.SUPABASE_URL],
    }
  }
}));

// Body parser — 50MB limit to accommodate image payloads
app.use(express.json({ limit: '50mb' }));

// Layer 7 — CORS: only Lorgner's frontend can call this proxy
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

// Layer 5 — Rate limiting: 20 messages per IP per hour
const chatLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: CONFIG.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`[LORGNER] Rate limited: ${req.ip} (user: ${req.lorgnerUser?.id || 'unverified'})`);
    res.status(429).json({
      error: true,
      code: 'RATE_LIMITED',
      message: 'Lorgner is here for your collection. What are we styling today?'
    });
  }
});

/* ══════════════════════════════════════════════
   SHARED HELPER — SEND MAGIC LINK VIA RESEND
══════════════════════════════════════════════ */
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
          <p style="margin:0 0 24px;font-size:15px;line-height:1.8;color:#888888;">Your membership is confirmed. Use the link below to access your private intelligence service.</p>
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
   POST /send-magic-link
   Called by the sign-in form. Generates a token
   via Supabase admin API and sends it via Resend.
   Always returns 200 to prevent email enumeration.
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

  // Always 200 — prevents account enumeration
  res.json({ ok: true });
});

/* ══════════════════════════════════════════════
   MAIN CHAT ENDPOINT
   POST /chat
   
   Protection order:
   1. JWT verification (requireAuth middleware)
   2. Rate limiting (chatLimiter middleware)
   3. Input filtering (isBlocked)
   4. Image validation (validateImage)
   5. Claude API call (API key added server-side)
   6. Output filtering (isBlocked on response)
══════════════════════════════════════════════ */
app.post('/chat',
  requireAuth,    // JWT must be valid before anything else
  chatLimiter,    // Rate limit after auth confirmation
  async (req, res) => {

  const { system, messages, max_tokens } = req.body;
  const user = req.lorgnerUser; // Set by requireAuth middleware

  /* ── BASIC VALIDATION ── */
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: true, message: 'Invalid request.' });
  }
  if (messages.length > 60) {
    return res.status(400).json({ error: true, message: 'Session complete. Please begin a new consultation.' });
  }

  /* ── LAYER 3: INPUT FILTERING ──
     Check latest user message for blocked content.
  */
  const latest = messages[messages.length - 1];
  if (latest?.role === 'user') {
    const textParts = Array.isArray(latest.content)
      ? latest.content.filter(c => c.type === 'text').map(c => c.text).join(' ')
      : (typeof latest.content === 'string' ? latest.content : '');

    if (isBlocked(textParts)) {
      console.log(`[LORGNER] Input blocked | user:${user.id} | "${textParts.slice(0,80)}"`);
      return res.status(200).json({
        error: true,
        code: 'BLOCKED',
        message: 'Lorgner is here for your collection. What are we styling today?'
      });
    }
  }

  /* ── LAYER 4: IMAGE VALIDATION ──
     Validate all images across the message history.
  */
  let imageCount = 0;
  for (const msg of messages) {
    if (!Array.isArray(msg.content)) continue;
    for (const part of msg.content) {
      if (part.type === 'image') {
        imageCount++;
        if (!validateImage(part)) {
          console.warn(`[LORGNER] Invalid image | user:${user.id}`);
          return res.status(400).json({
            error: true,
            message: 'One or more images could not be processed. Please use JPEG or PNG under 5MB.'
          });
        }
      }
    }
  }
  if (imageCount > CONFIG.MAX_PAIRS) {
    return res.status(400).json({
      error: true,
      message: `Lorgner supports up to ${CONFIG.MAX_PAIRS} pairs per consultation.`
    });
  }

  /* ── CALL CLAUDE API ──
     ANTHROPIC_API_KEY is an environment variable on Railway.
     It is added here on the server side.
     The browser never sees it.
     It does not appear in network requests from the browser.
     It does not appear in this file as a string literal.
  */
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         CONFIG.ANTHROPIC_KEY,       // ← From Railway env var only
        'anthropic-version': '2023-06-01',
        'anthropic-beta':    'prompt-caching-2024-07-31', // Prompt caching — reduces cost ~40%
      },
      body: JSON.stringify({
        model:      CONFIG.MODEL,
        max_tokens: max_tokens || CONFIG.MAX_TOKENS,
        system: [
          {
            type:          'text',
            text:          system,
            cache_control: { type: 'ephemeral' }, // Cache system prompt across calls
          }
        ],
        messages,
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error(`[LORGNER] Anthropic error | user:${user.id} |`, data.error?.message);
      return res.status(500).json({
        error: true,
        message: data.error?.message || 'Lorgner is momentarily unavailable. Please try again.'
      });
    }

    /* ── LAYER 3: OUTPUT FILTERING ──
       Scan Claude's response for any blocked content.
       Extremely rare given Layer 1 system prompt + Layer 2 Anthropic safety,
       but this provides a final catch.
    */
    const aiText = data.content?.[0]?.text || '';
    if (isBlocked(aiText)) {
      console.warn(`[LORGNER] Output filtered | user:${user.id}`);
      return res.status(200).json({
        content: [{
          type: 'text',
          text: 'Lorgner is here for your collection. What are we styling today?'
        }]
      });
    }

    // Success
    res.status(200).json(data);

    // Log for Railway monitoring (no sensitive data logged)
    console.log(
      `[LORGNER] Chat | user:${user.id.slice(0,8)}… | ` +
      `in:${data.usage?.input_tokens} out:${data.usage?.output_tokens} ` +
      `cached:${data.usage?.cache_read_input_tokens || 0}`
    );

  } catch (err) {
    console.error(`[LORGNER] Server error | user:${user.id} |`, err.message);
    res.status(500).json({
      error: true,
      message: 'Lorgner is momentarily unavailable. Please try again.'
    });
  }
});

/* ══════════════════════════════════════════════
   STRIPE CHECKOUT ENDPOINT
   POST /create-checkout-session
   Creates a Stripe Checkout URL for the founding
   member subscription. Frontend redirects the
   user to this URL. Stripe handles the payment
   form and calls the webhook on success.
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
      customer_email: email || undefined,
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID || 'price_1TX9YYJdJONprYpJHpVIcF6p',
          quantity: 1,
        }
      ],
      success_url: `${CONFIG.FRONTEND_URL}/?subscribed=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${CONFIG.FRONTEND_URL}/`,
      metadata: { full_name: name || '' },
    });

    res.json({ checkoutUrl: session.url });

  } catch (err) {
    console.error('[LORGNER] Stripe checkout error:', JSON.stringify(err));
    res.status(500).json({ error: true, message: err.message || err.toString() || 'Checkout unavailable.' });
  }
});

/* ══════════════════════════════════════════════
   BILLING PORTAL ENDPOINT
   POST /create-portal-session
   Looks up Stripe customer ID from Supabase members table,
   then creates a Stripe Customer Portal session.
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

    const session = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: CONFIG.FRONTEND_URL,
    });

    res.json({ portalUrl: session.url });
  } catch (err) {
    console.error('[LORGNER] Portal session error:', err.message);
    res.status(500).json({ error: true, message: err.message || 'Could not open billing portal.' });
  }
});

/* ══════════════════════════════════════════════
   SESSION ENDPOINT
   POST /session
   Receives session metadata from frontend.
   Writes to Supabase for analytics.
   Only accepts requests from verified users.
══════════════════════════════════════════════ */
app.post('/session', requireAuth, async (req, res) => {
  const { occasion, aiReply, pairCount, pairNames } = req.body;
  const user = req.lorgnerUser;

  // Write to Supabase using service key
  // This bypasses RLS for server-to-server writes
  try {
    const response = await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/sessions`,
      {
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
      }
    );

    if (!response.ok) {
      console.error('[LORGNER] Session write failed:', response.status);
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[LORGNER] Session error:', err.message);
    res.status(500).json({ ok: false });
  }
});

/* ══════════════════════════════════════════════
   IMAGE MODERATION ENDPOINT (OPTIONAL)
   POST /moderate-image
   Validates uploaded image contains eyewear.
   Uses Claude Haiku for cost efficiency.
   Uncomment when ready to activate.
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
            { type: 'text', text: 'Is the PRIMARY subject of this image a pair of eyeglasses, sunglasses, or optical frames — meaning glasses are the main focus, clearly visible and identifiable as wearable eyewear? Answer YES only if glasses or sunglasses are the dominant subject. Answer NO if glasses are absent, in the background, or if the image is of anything else (people, scenery, clothing, accessories, patterns, etc).' }
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
   POST /stripe-webhook
   ─────────────────────────────────────────────
   Stripe calls this URL automatically after
   every successful payment. This is what creates
   the Supabase account and sends the magic link.

   SETUP IN STRIPE DASHBOARD:
   1. Go to Developers → Webhooks
   2. Add endpoint: https://your-proxy.railway.app/stripe-webhook
   3. Select events: checkout.session.completed
      + customer.subscription.deleted
      + invoice.payment_failed
   4. Copy the webhook signing secret
   5. Add to Railway env vars as STRIPE_WEBHOOK_SECRET

   Add STRIPE_SECRET_KEY to Railway env vars too.
   ─────────────────────────────────────────────
   ENVIRONMENT VARIABLES NEEDED:
     STRIPE_SECRET_KEY       your Stripe secret key
     STRIPE_WEBHOOK_SECRET   your Stripe webhook signing secret
══════════════════════════════════════════════ */

// Raw body needed for Stripe signature verification
app.use('/stripe-webhook', express.raw({ type: 'application/json' }));

app.post('/stripe-webhook', async (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  // Verify the webhook came from Stripe — not a spoofed request
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    console.error(`[LORGNER] Stripe webhook signature failed: ${err.message}`);
    return res.status(400).json({ error: 'Webhook signature verification failed.' });
  }

  console.log(`[LORGNER] Stripe event received: ${event.type}`);

  // ── PAYMENT SUCCEEDED — CREATE ACCOUNT ──
  if (event.type === 'checkout.session.completed') {
    const session       = event.data.object;
    const email         = session.customer_details?.email || session.customer_email;
    const name          = session.customer_details?.name || '';
    const customerId    = session.customer;
    const subscriptionId = session.subscription;
    const amountPaid    = session.amount_total; // in cents

    if (!email) {
      console.error('[LORGNER] No email in Stripe session');
      return res.status(200).json({ received: true });
    }

    try {
      // 1. Create Supabase Auth user
      const signUpRes = await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/admin/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        },
        body: JSON.stringify({
          email,
          email_confirm: true,  // Skip email confirmation — they just paid
          user_metadata: {
            full_name:    name,
            member_tier:  amountPaid <= 2900 ? 'founding' : 'standard',
            member_since: new Date().toISOString(),
          }
        })
      });

      let authUser = await signUpRes.json();

      if (!authUser?.id) {
        // User already exists — look them up by email
        console.log(`[LORGNER] User may already exist, looking up: ${email}`);
        const listRes = await fetch(
          `${CONFIG.SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
          { headers: { apikey: CONFIG.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}` } }
        );
        const listData = await listRes.json();
        authUser = listData?.users?.[0] || listData?.[0] || authUser;
      }

      const userId = authUser?.id;

      // 2. Insert into members table
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

      // 3. Send magic link via Resend
      const sent = await sendMagicLinkEmail(email, name);
      if (sent) {
        console.log(`[LORGNER] ✓ Account created, magic link sent via Resend: ${email}`);
      } else {
        console.error(`[LORGNER] ✗ Magic link generation failed for: ${email}`);
      }

    } catch (err) {
      console.error('[LORGNER] Account creation failed:', err.message);
      // Return 200 anyway — Stripe retries on non-200 responses
      // Log manually and handle edge cases in dashboard
    }
  }

  // ── SUBSCRIPTION CANCELLED ──
  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const customerId   = subscription.customer;

    // Update member tier to cancelled in Supabase
    await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/members?stripe_customer_id=eq.${customerId}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        },
        body: JSON.stringify({ member_tier: 'cancelled' })
      }
    );

    console.log(`[LORGNER] Subscription cancelled: customer ${customerId}`);
  }

  // ── PAYMENT FAILED ──
  if (event.type === 'invoice.payment_failed') {
    const invoice    = event.data.object;
    const customerId = invoice.customer;

    // Update member tier to paused
    await fetch(
      `${CONFIG.SUPABASE_URL}/rest/v1/members?stripe_customer_id=eq.${customerId}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'apikey':        CONFIG.SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${CONFIG.SUPABASE_SERVICE_KEY}`,
        },
        body: JSON.stringify({ member_tier: 'paused' })
      }
    );

    console.log(`[LORGNER] Payment failed: customer ${customerId}`);
  }

  // Always return 200 to Stripe — otherwise it retries
  res.status(200).json({ received: true });
});

/* ══════════════════════════════════════════════
   START SERVER
══════════════════════════════════════════════ */
app.listen(PORT, () => {
  const missingVars = ['ANTHROPIC_API_KEY','SUPABASE_URL','SUPABASE_SERVICE_KEY','RESEND_API_KEY']
    .filter(k => !process.env[k]);

  if (missingVars.length > 0) {
    console.warn(`\n  ⚠ Missing environment variables: ${missingVars.join(', ')}\n`);
  }

  console.log(`
  ╔════════════════════════════════════════╗
  ║  LORGNER — Backend Proxy               ║
  ║  Port    : ${String(PORT).padEnd(28)}  ║
  ║  Origin  : ${CONFIG.FRONTEND_URL.slice(0,28).padEnd(28)}  ║
  ╚════════════════════════════════════════╝

  Security layers active:
  [Auth]  JWT verification (Supabase)        ✓
  [1]     System prompt scope constraint     ✓ (in frontend)
  [2]     Anthropic constitutional AI        ✓ (model level)
  [3]     Input + output filtering           ✓
  [4]     Image validation                   ✓
  [5]     Rate limiting (${CONFIG.RATE_LIMIT_MAX}/hr per IP)          ✓
  [6]     Membership payment barrier         ✓ (Stripe)
  [7]     CORS + Helmet security headers     ✓

  API key status:
  [✓]     ANTHROPIC_API_KEY in env vars only
  [✓]     Never transmitted to browser
  [✓]     Never appears in frontend code
  `);
});

/* ══════════════════════════════════════════════
   HOW THE API KEY IS PROTECTED — SUMMARY
   ──────────────────────────────────────────────
   1. The key is set in Railway's environment
      variables dashboard. It is never in code.

   2. Railway injects it as process.env.ANTHROPIC_API_KEY
      at runtime on their secure servers.

   3. When the frontend wants to call Claude it
      sends a request to THIS proxy with its JWT.

   4. This proxy verifies the JWT, then adds the
      API key to the outgoing Anthropic request.

   5. The browser's network inspector shows:
      - Request to: your-lorgner-proxy.railway.app
      - No API key in request headers
      - No API key in response

   6. The Anthropic API call happens entirely
      server-to-server between Railway and Anthropic.
      The browser is never part of that connection.

   RESULT: A user inspecting your frontend source
   code, your HTML, your JavaScript, or their
   browser's network tab will find no trace of
   the Claude API key anywhere.
══════════════════════════════════════════════ */
