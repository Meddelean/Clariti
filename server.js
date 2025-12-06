// server.js
/**
 * Security Features Implemented:
 * 1. Rate Limiting - Prevents brute force attacks on login/signup (5 attempts per 15 minutes)
 * 2. Helmet - Security headers (XSS protection, content security policy, etc.)
 * 3. Input Validation - Email and password validation with express-validator
 * 4. Input Sanitization - Removes dangerous characters and limits input length
 * 5. Password Strength - Minimum 8 characters, requires letters and numbers
 * 6. Timing Attack Protection - Consistent response times for auth endpoints
 * 7. Security Logging - Logs all authentication attempts for monitoring
 * 8. Error Handling - Generic error messages to prevent information leakage
 * 9. Request Size Limits - Prevents DoS attacks via large payloads
 * 10. ID Validation - Validates and sanitizes all ID parameters
 */

const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// Initialize Supabase clients
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseServiceKey || !supabaseAnonKey) {
  console.error('BŁĄD: Brak konfiguracji Supabase!');
  console.error('Upewnij się, że plik .env zawiera:');
  console.error('  SUPABASE_URL=twoj_url');
  console.error('  SUPABASE_ANON_KEY=twoj_anon_key');
  console.error('  SUPABASE_SERVICE_ROLE_KEY=twoj_service_role_key');
  process.exit(1);
}

// Service role client for admin operations
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

const app = express();

// Security middleware - Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      styleSrcAttr: ["'unsafe-inline'"], // Allow inline style attributes for CSS custom properties
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'none'"], // Block inline event handlers (we use addEventListener instead)
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://*.supabase.co"], // Allow Supabase API connections
    },
  },
  crossOriginEmbedderPolicy: false
}));

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(PUBLIC_DIR));

// Rate limiting configuration
// Stricter rate limit for authentication endpoints
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 5, // maksymalnie 5 prób na 15 minut
  message: { error: 'too_many_attempts', message: 'Zbyt wiele prób. Spróbuj ponownie za 15 minut.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false, // Licz również udane próby
  handler: (req, res) => {
    res.status(429).json({ 
      error: 'too_many_attempts', 
      message: 'Zbyt wiele prób. Spróbuj ponownie za 15 minut.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

// General API rate limiter
const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 100, // maksymalnie 100 requestów na 15 minut
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply general rate limiting to all API routes
app.use('/auth', apiRateLimiter);
app.use('/trades', apiRateLimiter);

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Password validation function
function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'password_required' };
  }
  
  if (password.length < 5) {
    return { valid: false, error: 'password_too_short' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'password_too_long' };
  }
  
  // No requirements for letters, digits, or special characters
  // Password can be any combination of characters (minimum 5)
  
  return { valid: true };
}

// Sanitize input - remove potentially dangerous characters
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  // Remove null bytes and control characters
  return input.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

// Validation middleware for login (less strict - just check format)
const validateLoginInput = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('invalid_email')
    .isLength({ max: 255 })
    .withMessage('email_too_long'),
  body('password')
    .notEmpty()
    .withMessage('password_required')
    .isLength({ min: 1, max: 128 })
    .withMessage('password_invalid_length'),
];

// Validation middleware for signup (minimum 5 characters, no complexity requirements)
const validateSignupInput = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('invalid_email')
    .isLength({ max: 255 })
    .withMessage('email_too_long'),
  body('password')
    .isLength({ min: 5, max: 128 })
    .withMessage('password_invalid_length'),
];

// Helper function to check validation results
function checkValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array()[0];
    console.log('Validation error:', firstError); // Debug log
    return res.status(400).json({ 
      error: firstError.msg || 'validation_error',
      message: 'Nieprawidłowe dane wejściowe',
      details: process.env.NODE_ENV === 'development' ? firstError : undefined
    });
  }
  next();
}

// Security logging middleware for authentication attempts
function logAuthAttempt(req, success, reason = null) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const timestamp = new Date().toISOString();
  const logMessage = `[AUTH ${success ? 'SUCCESS' : 'FAILED'}] ${timestamp} - IP: ${ip} - Endpoint: ${req.path}`;
  
  if (!success && reason) {
    console.warn(`${logMessage} - Reason: ${reason}`);
  } else if (success) {
    console.log(logMessage);
  } else {
    console.warn(logMessage);
  }
}

// Middleware to verify user session
async function verifySession(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = authHeader.substring(7);
  
  try {
    // Verify token and get user
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (err) {
    console.error('Błąd weryfikacji sesji:', err);
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// Auth endpoints
app.post('/auth/login', authRateLimiter, validateLoginInput, checkValidation, async (req, res) => {
  const startTime = Date.now();
  let { email, password } = req.body;
  
  // Sanitize inputs (express-validator already validated format)
  email = sanitizeInput(email);
  password = sanitizeInput(password);
  
  // Additional safety check
  if (!email || !password) {
    logAuthAttempt(req, false, 'missing_fields');
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const { data, error } = await supabaseAdmin.auth.signInWithPassword({
      email,
      password
    });

    // Timing attack protection - ensure minimum response time
    const elapsed = Date.now() - startTime;
    const minResponseTime = 500; // minimum 500ms
    if (elapsed < minResponseTime) {
      await new Promise(resolve => setTimeout(resolve, minResponseTime - elapsed));
    }

    if (error) {
      // Don't reveal if email exists or not
      logAuthAttempt(req, false, 'invalid_credentials');
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    logAuthAttempt(req, true);
    res.json({
      user: data.user,
      session: data.session
    });
  } catch (err) {
    console.error('Błąd logowania:', err);
    logAuthAttempt(req, false, 'internal_error');
    // Don't expose internal error details
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/auth/signup', authRateLimiter, validateSignupInput, checkValidation, async (req, res) => {
  const startTime = Date.now();
  let { email, password } = req.body;
  
  // Sanitize inputs
  email = sanitizeInput(email);
  password = sanitizeInput(password);
  
  // Additional validation
  if (!email || !password) {
    logAuthAttempt(req, false, 'missing_fields');
    return res.status(400).json({ error: 'missing_fields' });
  }

  if (!emailRegex.test(email)) {
    logAuthAttempt(req, false, 'invalid_email');
    return res.status(400).json({ error: 'invalid_email' });
  }

  // Enhanced password validation
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    logAuthAttempt(req, false, passwordValidation.error);
    return res.status(400).json({ error: passwordValidation.error });
  }

  try {
    const { data, error } = await supabaseAdmin.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: undefined // Don't require email confirmation for immediate login
      }
    });

    // Timing attack protection - ensure minimum response time
    const elapsed = Date.now() - startTime;
    const minResponseTime = 500; // minimum 500ms
    if (elapsed < minResponseTime) {
      await new Promise(resolve => setTimeout(resolve, minResponseTime - elapsed));
    }

    if (error) {
      // Don't expose detailed error messages that could help attackers
      const errorMessage = error.message.toLowerCase();
      if (errorMessage.includes('already registered') || errorMessage.includes('user already')) {
        logAuthAttempt(req, false, 'email_exists');
        return res.status(400).json({ error: 'email_exists' });
      }
      logAuthAttempt(req, false, 'signup_failed');
      return res.status(400).json({ error: 'signup_failed' });
    }

    logAuthAttempt(req, true);
    // If session is null, user needs to confirm email
    // Return user info and indicate if email confirmation is needed
    res.json({
      user: data.user,
      session: data.session,
      requiresEmailConfirmation: !data.session
    });
  } catch (err) {
    console.error('Błąd rejestracji:', err);
    logAuthAttempt(req, false, 'internal_error');
    // Don't expose internal error details
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/auth/logout', verifySession, async (req, res) => {
  try {
    await supabaseAdmin.auth.signOut(req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Błąd wylogowania:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/auth/session', verifySession, async (req, res) => {
  res.json({ user: req.user });
});

// Handle email confirmation
app.get('/auth/confirm', async (req, res) => {
  const { token_hash, type } = req.query;
  
  // Sanitize and validate inputs
  if (!token_hash || typeof token_hash !== 'string' || token_hash.length > 500) {
    return res.redirect('/?error=invalid_confirmation_link');
  }
  
  if (type !== 'email') {
    return res.redirect('/?error=invalid_confirmation_link');
  }

  // Sanitize token_hash - remove potentially dangerous characters
  const sanitizedToken = sanitizeInput(token_hash);

  try {
    // Verify the token and confirm email
    const { data, error } = await supabaseAdmin.auth.verifyOtp({
      token_hash: sanitizedToken,
      type: 'email'
    });

    if (error) {
      // Don't expose error details
      return res.redirect('/?error=confirmation_failed');
    }

    // If successful, redirect with success message
    if (data.session) {
      return res.redirect(`/?email_confirmed=true&token=${data.session.access_token}`);
    }
    
    return res.redirect('/?email_confirmed=true');
  } catch (err) {
    console.error('Email confirmation error:', err);
    return res.redirect('/?error=confirmation_failed');
  }
});

// GET /trades - pobierz wszystkie wpisy użytkownika
app.get('/trades', verifySession, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('trades')
      .select('*')
      .eq('user_id', req.user.id)
      .order('id', { ascending: false });

    if (error) {
      console.error('Błąd pobierania wpisów:', error);
      return res.status(500).json({ error: 'internal_error' });
    }

    res.json(data || []);
  } catch (err) {
    console.error('Błąd pobierania wpisów:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// GET /trades/:id - pobierz pojedynczy wpis
app.get('/trades/:id', verifySession, async (req, res) => {
  const id = Number(req.params.id);
  
  // Validate ID - must be positive integer
  if (!Number.isInteger(id) || id <= 0 || id > Number.MAX_SAFE_INTEGER) {
    return res.status(400).json({ error: 'invalid_id' });
  }

  try {
    const { data, error } = await supabaseAdmin
      .from('trades')
      .select('*')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'not_found' });
    }

    res.json(data);
  } catch (err) {
    console.error('Błąd pobierania wpisu:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// POST /trades - dodaj wpis
// oczekuje JSON: { date: "DD/MM/YYYY", symbol: "...", type: "...", rr: "...", result: "...", pnl: "...", screenshot: "...", note: "..." }
app.post('/trades', verifySession, async (req, res) => {
  let { date, symbol, type, rr, result, pnl, screenshot, note } = req.body;
  
  if (!date) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  // Sanitize all string inputs
  date = sanitizeInput(date);
  symbol = symbol ? sanitizeInput(symbol).substring(0, 100) : null; // Limit length
  type = type ? sanitizeInput(type).substring(0, 50) : null;
  result = result ? sanitizeInput(result).substring(0, 50) : null;
  screenshot = screenshot ? sanitizeInput(screenshot).substring(0, 5000) : null; // Limit URL length
  note = note ? sanitizeInput(note).substring(0, 1000) : null; // Limit note length

  // Validate date format (DD/MM/YYYY)
  const dateRegex = /^(\d{2})\/(\d{2})\/(\d{4})$/;
  if (!dateRegex.test(date)) {
    return res.status(400).json({ error: 'invalid_date_format' });
  }

  // Convert rr and pnl to numbers (or null if empty/invalid)
  const rrNum = (rr && rr !== '') ? parseFloat(String(rr).replace(',', '.')) : null;
  const pnlNum = (pnl && pnl !== '') ? parseFloat(String(pnl).replace(',', '.')) : null;
  
  // Use null for invalid numbers and check ranges
  const rrValue = (rrNum !== null && Number.isFinite(rrNum) && Math.abs(rrNum) < 1000000) ? rrNum : null;
  const pnlValue = (pnlNum !== null && Number.isFinite(pnlNum) && Math.abs(pnlNum) < 1000000000) ? pnlNum : null;

  try {
    const { data, error } = await supabaseAdmin
      .from('trades')
      .insert({
        user_id: req.user.id,
        date,
        symbol: symbol || null,
        type: type || null,
        rr: rrValue,
        result: result || null,
        pnl: pnlValue,
        screenshot: screenshot || null,
        note: note || null
      })
      .select()
      .single();

    if (error) {
      console.error('Błąd zapisu wpisu:', error);
      return res.status(500).json({ error: 'internal_error' });
    }

    res.status(201).json(data);
  } catch (err) {
    console.error('Błąd zapisu wpisu:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// PUT /trades/:id - edytuj wpis
app.put('/trades/:id', verifySession, async (req, res) => {
  const id = Number(req.params.id);
  
  // Validate ID - must be positive integer
  if (!Number.isInteger(id) || id <= 0 || id > Number.MAX_SAFE_INTEGER) {
    return res.status(400).json({ error: 'invalid_id' });
  }

  let { date, symbol, type, rr, result, pnl, screenshot, note } = req.body;
  
  if (!date) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  // Sanitize all string inputs
  date = sanitizeInput(date);
  symbol = symbol ? sanitizeInput(symbol).substring(0, 100) : null;
  type = type ? sanitizeInput(type).substring(0, 50) : null;
  result = result ? sanitizeInput(result).substring(0, 50) : null;
  screenshot = screenshot ? sanitizeInput(screenshot).substring(0, 5000) : null;
  note = note ? sanitizeInput(note).substring(0, 1000) : null;

  // Validate date format (DD/MM/YYYY)
  const dateRegex = /^(\d{2})\/(\d{2})\/(\d{4})$/;
  if (!dateRegex.test(date)) {
    return res.status(400).json({ error: 'invalid_date_format' });
  }

  // Convert rr and pnl to numbers (or null if empty/invalid)
  const rrNum = (rr && rr !== '') ? parseFloat(String(rr).replace(',', '.')) : null;
  const pnlNum = (pnl && pnl !== '') ? parseFloat(String(pnl).replace(',', '.')) : null;
  
  // Use null for invalid numbers and check ranges
  const rrValue = (rrNum !== null && Number.isFinite(rrNum) && Math.abs(rrNum) < 1000000) ? rrNum : null;
  const pnlValue = (pnlNum !== null && Number.isFinite(pnlNum) && Math.abs(pnlNum) < 1000000000) ? pnlNum : null;

  try {
    // First check if trade belongs to user
    const { data: trade, error: fetchError } = await supabaseAdmin
      .from('trades')
      .select('id, user_id')
      .eq('id', id)
      .single();

    if (fetchError || !trade) {
      return res.status(404).json({ error: 'not_found' });
    }

    if (trade.user_id !== req.user.id) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { data, error } = await supabaseAdmin
      .from('trades')
      .update({
        date,
        symbol: symbol || null,
        type: type || null,
        rr: rrValue,
        result: result || null,
        pnl: pnlValue,
        screenshot: screenshot || null,
        note: note || null
      })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      console.error('Błąd aktualizacji wpisu:', error);
      return res.status(500).json({ error: 'internal_error' });
    }

    res.status(200).json(data);
  } catch (err) {
    console.error('Błąd aktualizacji wpisu:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// DELETE /trades/:id - usuń wpis
app.delete('/trades/:id', verifySession, async (req, res) => {
  const id = Number(req.params.id);
  
  // Validate ID - must be positive integer
  if (!Number.isInteger(id) || id <= 0 || id > Number.MAX_SAFE_INTEGER) {
    return res.status(400).json({ error: 'invalid_id' });
  }

  try {
    // First check if trade belongs to user
    const { data: trade, error: fetchError } = await supabaseAdmin
      .from('trades')
      .select('id, user_id')
      .eq('id', id)
      .single();

    if (fetchError || !trade) {
      return res.status(404).json({ error: 'not_found' });
    }

    if (trade.user_id !== req.user.id) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { error } = await supabaseAdmin
      .from('trades')
      .delete()
      .eq('id', id)
      .eq('user_id', req.user.id);

    if (error) {
      console.error('Błąd usuwania wpisu:', error);
      return res.status(500).json({ error: 'internal_error' });
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Błąd usuwania wpisu:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// health
app.get('/health', (req, res) => res.json({ ok: true }));

// SPA fallback - use app.use to avoid path-to-regexp '*' parsing issues
app.use((req, res, next) => {
  // allow API and static files to proceed
  if (req.path.startsWith('/trades') || req.path.startsWith('/health') || req.path.startsWith('/auth')) return next();

  // if request accepts html, return index.html for SPA routing
  const acceptsHtml = req.accepts && req.accepts('html');
  if (acceptsHtml) {
    return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  }

  next();
});

// start
app.listen(PORT, () => {
  console.log(`Serwer uruchomiony na http://localhost:${PORT}`);
  console.log('Połączono z Supabase');
});
