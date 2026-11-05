import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Body parsing
app.use(express.json({ limit: '2mb' }));

// Master staff password and session configuration
const STAFF_PASSWORD = process.env.STAFF_PASSWORD || 'Director@1974';
const STAFF_SESSION_SECRET = process.env.STAFF_SESSION_SECRET || 'the-last-signal-case17-staff-secret-key-2026';
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// Rate-limiting for password attempts (In-memory IP tracking)
interface RateLimitRecord {
  failedAttempts: number;
  firstAttempt: number;
  lockedUntil: number;
}
const loginRateLimits = new Map<string, RateLimitRecord>();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes lockout

function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

function verifyPasswordConstantTime(provided: string, expected: string): boolean {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const hashProvided = crypto.createHash('sha256').update(provided.trim()).digest();
  const hashExpected = crypto.createHash('sha256').update(expected.trim()).digest();
  return crypto.timingSafeEqual(hashProvided, hashExpected);
}

function generateStaffToken(): { token: string; expiresAt: number } {
  const expiresAt = Date.now() + TOKEN_TTL_MS;
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${expiresAt}:${nonce}`;
  const signature = crypto.createHmac('sha256', STAFF_SESSION_SECRET).update(payload).digest('hex');
  const token = Buffer.from(`${payload}:${signature}`).toString('base64url');
  return { token, expiresAt };
}

function verifyStaffToken(tokenStr?: string): { valid: boolean; expiresAt?: number } {
  if (!tokenStr) return { valid: false };
  try {
    const raw = Buffer.from(tokenStr, 'base64url').toString('utf-8');
    const parts = raw.split(':');
    if (parts.length !== 3) return { valid: false };
    const [expiresAtStr, nonce, sig] = parts;
    const expiresAt = parseInt(expiresAtStr, 10);
    if (isNaN(expiresAt) || Date.now() > expiresAt) {
      return { valid: false };
    }
    const payload = `${expiresAtStr}:${nonce}`;
    const expectedSig = crypto.createHmac('sha256', STAFF_SESSION_SECRET).update(payload).digest('hex');
    const isValid = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig));
    return { valid: isValid, expiresAt };
  } catch {
    return { valid: false };
  }
}

// Authentication middleware for staff-only endpoints
function requireStaffAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.headers['x-staff-token'] as string);

  const verification = verifyStaffToken(token);
  if (!verification.valid) {
    res.status(401).json({
      success: false,
      error: 'Unauthorized. Valid staff clearance session token required.',
    });
    return;
  }
  next();
}

/* =========================================================================
   PERSISTENCE LAYER (Central Server Ticket & Audit Repository)
   ========================================================================= */

const DATA_DIR = path.join(__dirname, 'data');
const TICKETS_FILE = path.join(DATA_DIR, 'support_tickets.json');
const AUDIT_FILE = path.join(DATA_DIR, 'staff_audit_log.json');
const OVERRIDES_FILE = path.join(DATA_DIR, 'participant_overrides.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

export interface ServerTicket {
  id: string;
  callSign: string;
  fullName: string;
  studentClass: string;
  subject: string;
  category: string;
  message: string;
  status: 'OPEN' | 'UNDER_REVIEW' | 'RESOLVED' | 'CLOSED';
  priority: 'NORMAL' | 'HIGH' | 'CRITICAL';
  createdAt: string;
  updatedAt: string;
  staffResponse?: string;
  staffNotes?: string;
  resolvedBy?: string;
}

function loadTickets(): ServerTicket[] {
  ensureDataDir();
  try {
    if (fs.existsSync(TICKETS_FILE)) {
      const content = fs.readFileSync(TICKETS_FILE, 'utf-8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error('[server] Error reading tickets file:', err);
  }
  return [];
}

function saveTickets(tickets: ServerTicket[]) {
  ensureDataDir();
  try {
    fs.writeFileSync(TICKETS_FILE, JSON.stringify(tickets, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving tickets file:', err);
  }
}

function loadAuditLogs(): any[] {
  ensureDataDir();
  try {
    if (fs.existsSync(AUDIT_FILE)) {
      return JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading audit file:', err);
  }
  return [];
}

function saveAuditLogs(logs: any[]) {
  ensureDataDir();
  try {
    fs.writeFileSync(AUDIT_FILE, JSON.stringify(logs, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving audit file:', err);
  }
}

function loadOverrides(): Record<string, any> {
  ensureDataDir();
  try {
    if (fs.existsSync(OVERRIDES_FILE)) {
      return JSON.parse(fs.readFileSync(OVERRIDES_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading overrides file:', err);
  }
  return {};
}

function saveOverrides(overrides: Record<string, any>) {
  ensureDataDir();
  try {
    fs.writeFileSync(OVERRIDES_FILE, JSON.stringify(overrides, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving overrides file:', err);
  }
}

// Optional Supabase admin client for server-side operations if service role key exists
let supabaseAdmin: any = null;
const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (supabaseUrl && supabaseServiceKey && !supabaseUrl.includes('placeholder')) {
  import('@supabase/supabase-js').then(({ createClient }) => {
    supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
      auth: { persistSession: false },
    });
    console.info('[server] Supabase Admin Client initialized with Service Role Key.');
  }).catch((err) => {
    console.warn('[server] Supabase admin init skipped:', err.message);
  });
}

/* =========================================================================
   API ROUTES
   ========================================================================= */

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    supabaseConnected: Boolean(supabaseAdmin),
  });
});

// 1. STAFF AUTHENTICATION (PASSWORD-ONLY ACCESS)
app.post('/api/staff/login', (req, res) => {
  const ip = getClientIp(req);
  const now = Date.now();
  const record = loginRateLimits.get(ip) || { failedAttempts: 0, firstAttempt: now, lockedUntil: 0 };

  // Check rate limit lockout
  if (record.lockedUntil > now) {
    const remainingSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    res.status(429).json({
      success: false,
      error: `Too many failed authorization attempts. Staff terminal locked for ${Math.ceil(remainingSeconds / 60)} minutes.`,
      lockedUntil: record.lockedUntil,
      retryAfterSeconds: remainingSeconds,
    });
    return;
  }

  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    res.status(400).json({ success: false, error: 'Staff authorization password is required.' });
    return;
  }

  const isMatch = verifyPasswordConstantTime(password, STAFF_PASSWORD);

  if (!isMatch) {
    record.failedAttempts += 1;
    if (record.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      loginRateLimits.set(ip, record);
      console.warn(`[SECURITY] Staff login locked for IP: ${ip} after ${MAX_FAILED_ATTEMPTS} failed attempts.`);
      res.status(429).json({
        success: false,
        error: `Maximum authorization attempts exceeded. Console locked for 15 minutes.`,
        lockedUntil: record.lockedUntil,
        retryAfterSeconds: Math.ceil(LOCKOUT_MS / 1000),
      });
      return;
    }

    loginRateLimits.set(ip, record);
    const remainingAttempts = MAX_FAILED_ATTEMPTS - record.failedAttempts;
    res.status(401).json({
      success: false,
      error: `Invalid staff authorization password. ${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} remaining before lockout.`,
      remainingAttempts,
    });
    return;
  }

  // Password verified: Reset rate-limit record and issue timed token
  loginRateLimits.delete(ip);
  const { token, expiresAt } = generateStaffToken();
  console.info(`[SECURITY] Staff session authorized successfully from IP: ${ip}`);

  res.json({
    success: true,
    token,
    expiresAt,
    message: 'Staff clearance authorized.',
  });
});

// Verify active staff session token
app.post('/api/staff/verify-session', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : req.body?.token) || (req.headers['x-staff-token'] as string);

  const verification = verifyStaffToken(token);
  res.json({
    valid: verification.valid,
    expiresAt: verification.expiresAt,
  });
});

// Logout staff session
app.post('/api/staff/logout', (_req, res) => {
  res.json({ success: true, message: 'Staff session deauthorized.' });
});

// 2. SUPPORT TICKET SYSTEM

// Investigators submit support ticket
app.post('/api/tickets/submit', async (req, res) => {
  const { callSign, fullName, studentClass, subject, category, message, priority = 'NORMAL' } = req.body;

  if (!callSign || !subject || !category || !message) {
    res.status(400).json({ success: false, error: 'Missing required ticket submission fields.' });
    return;
  }

  const cleanSubject = String(subject).trim();
  const cleanMessage = String(message).trim();

  if (cleanSubject.length < 4 || cleanSubject.length > 100) {
    res.status(400).json({ success: false, error: 'Subject must be between 4 and 100 characters.' });
    return;
  }
  if (cleanMessage.length < 10 || cleanMessage.length > 1500) {
    res.status(400).json({ success: false, error: 'Message must be between 10 and 1500 characters.' });
    return;
  }

  const ticketId = `TKT-2026-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const nowIso = new Date().toISOString();

  const newTicket: ServerTicket = {
    id: ticketId,
    callSign: String(callSign).trim(),
    fullName: String(fullName || callSign).trim(),
    studentClass: String(studentClass || 'Class 9').trim(),
    subject: cleanSubject,
    category: String(category).trim(),
    message: cleanMessage,
    status: 'OPEN',
    priority: priority === 'CRITICAL' ? 'CRITICAL' : priority === 'HIGH' ? 'HIGH' : 'NORMAL',
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  // 1. Save to central server repository
  const tickets = loadTickets();
  tickets.unshift(newTicket);
  saveTickets(tickets);

  // 2. Mirror to Supabase if configured
  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('support_tickets').insert({
        id: newTicket.id,
        call_sign: newTicket.callSign,
        full_name: newTicket.fullName,
        student_class: newTicket.studentClass,
        subject: newTicket.subject,
        category: newTicket.category,
        message: newTicket.message,
        status: newTicket.status,
        priority: newTicket.priority,
        created_at: newTicket.createdAt,
        updated_at: newTicket.updatedAt,
      });
    } catch (sbErr) {
      console.warn('[server] Supabase ticket mirror warning:', sbErr);
    }
  }

  // Return sanitized ticket without staff notes
  const { staffNotes, ...sanitized } = newTicket;
  res.status(201).json({ success: true, ticket: sanitized });
});

// Investigators fetch their own tickets (Omit staffNotes)
app.get('/api/tickets/mine', async (req, res) => {
  const callSign = req.query.callSign as string;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign query parameter required.' });
    return;
  }

  const clean = callSign.trim().toLowerCase();
  const all = loadTickets();
  const mine = all
    .filter((t) => t.callSign.toLowerCase() === clean)
    .map(({ staffNotes, ...sanitized }) => sanitized);

  res.json({ success: true, tickets: mine });
});

// STAFF: Shared Inbox — Fetch ALL tickets across ALL investigators (Requires staff auth)
app.get('/api/staff/tickets', requireStaffAuth, async (_req, res) => {
  let allTickets = loadTickets();

  // If Supabase admin is available, sync/merge any remote tickets
  if (supabaseAdmin) {
    try {
      const { data, error } = await supabaseAdmin
        .from('support_tickets')
        .select('*')
        .order('created_at', { ascending: false });

      if (!error && Array.isArray(data)) {
        const remoteTickets: ServerTicket[] = data.map((r: any) => ({
          id: r.id,
          callSign: r.call_sign,
          fullName: r.full_name || r.call_sign,
          studentClass: r.student_class || 'Class 9',
          subject: r.subject,
          category: r.category,
          message: r.message,
          status: r.status,
          priority: r.priority,
          staffResponse: r.staff_response,
          staffNotes: r.staff_notes,
          resolvedBy: r.resolved_by,
          createdAt: r.created_at,
          updatedAt: r.updated_at,
        }));

        // Merge remote with local (key by id)
        const map = new Map<string, ServerTicket>();
        for (const t of allTickets) map.set(t.id, t);
        for (const t of remoteTickets) map.set(t.id, t);
        allTickets = Array.from(map.values()).sort(
          (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        );
        saveTickets(allTickets);
      }
    } catch (err) {
      console.warn('[server] Error syncing Supabase tickets for staff:', err);
    }
  }

  res.json({ success: true, tickets: allTickets });
});

// STAFF: Update ticket (Status, Response, Staff Notes) (Requires staff auth)
app.patch('/api/staff/tickets/:id', requireStaffAuth, async (req, res) => {
  const ticketId = req.params.id;
  const { status, priority, staffResponse, staffNotes, staffCallSign } = req.body;

  const tickets = loadTickets();
  const idx = tickets.findIndex((t) => t.id === ticketId);
  if (idx === -1) {
    res.status(404).json({ success: false, error: `Ticket ${ticketId} not found.` });
    return;
  }

  const existing = tickets[idx];
  const nowIso = new Date().toISOString();

  const updated: ServerTicket = {
    ...existing,
    status: status || existing.status,
    priority: priority || existing.priority,
    staffResponse: staffResponse !== undefined ? String(staffResponse).trim() : existing.staffResponse,
    staffNotes: staffNotes !== undefined ? String(staffNotes).trim() : existing.staffNotes,
    resolvedBy: staffCallSign || existing.resolvedBy || 'Master Staff Console',
    updatedAt: nowIso,
  };

  tickets[idx] = updated;
  saveTickets(tickets);

  if (supabaseAdmin) {
    try {
      await supabaseAdmin
        .from('support_tickets')
        .update({
          status: updated.status,
          priority: updated.priority,
          staff_response: updated.staffResponse,
          staff_notes: updated.staffNotes,
          resolved_by: updated.resolvedBy,
          updated_at: updated.updatedAt,
        })
        .eq('id', ticketId);
    } catch (sbErr) {
      console.warn('[server] Supabase ticket update warning:', sbErr);
    }
  }

  res.json({ success: true, ticket: updated });
});

// STAFF: Participant Overrides & Leaderboard Exclusions (Requires staff auth)
app.get('/api/staff/overrides', requireStaffAuth, (_req, res) => {
  res.json({ success: true, overrides: loadOverrides() });
});

app.post('/api/staff/override-stage', requireStaffAuth, (req, res) => {
  const { callSign, stage, enabled } = req.body;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign required.' });
    return;
  }

  const overrides = loadOverrides();
  const key = callSign.toLowerCase();
  overrides[key] = overrides[key] || { stages: {} };
  overrides[key].stages[stage] = Boolean(enabled);
  saveOverrides(overrides);

  res.json({ success: true, overrides: overrides[key] });
});

app.post('/api/staff/leaderboard-exclusion', requireStaffAuth, (req, res) => {
  const { callSign, excluded } = req.body;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign required.' });
    return;
  }

  const overrides = loadOverrides();
  const key = callSign.toLowerCase();
  overrides[key] = overrides[key] || { stages: {} };
  overrides[key].excludeFromLeaderboard = Boolean(excluded);
  saveOverrides(overrides);

  res.json({ success: true, excluded: overrides[key].excludeFromLeaderboard });
});

// STAFF: Audit Logs (Requires staff auth)
app.get('/api/staff/audit-log', requireStaffAuth, (_req, res) => {
  res.json({ success: true, logs: loadAuditLogs() });
});

app.post('/api/staff/audit-log', requireStaffAuth, (req, res) => {
  const entry = req.body;
  const logs = loadAuditLogs();
  logs.unshift({
    id: `aud_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    timestamp: new Date().toISOString(),
    ...entry,
  });
  saveAuditLogs(logs.slice(0, 500)); // retain latest 500
  res.json({ success: true });
});

/* =========================================================================
   TEAM MANAGEMENT PERSISTENCE & API ROUTES
   ========================================================================= */

const TEAMS_FILE = path.join(DATA_DIR, 'teams.json');

export interface ServerTeamMember {
  callSign: string;
  fullName: string;
  joinedAt: string;
  isCreator: boolean;
}

export interface ServerTeam {
  id: string;
  name: string;
  inviteCode: string;
  createdBy: string;
  createdAt: string;
  maxSize: number;
  retired: boolean;
  members: ServerTeamMember[];
}

function loadTeams(): ServerTeam[] {
  ensureDataDir();
  try {
    if (fs.existsSync(TEAMS_FILE)) {
      return JSON.parse(fs.readFileSync(TEAMS_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading teams file:', err);
  }
  return [];
}

function saveTeams(teams: ServerTeam[]) {
  ensureDataDir();
  try {
    fs.writeFileSync(TEAMS_FILE, JSON.stringify(teams, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving teams file:', err);
  }
}

// 1. Fetch current user's team
app.get('/api/teams/mine', (req, res) => {
  const callSign = req.query.callSign as string;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign query parameter required.' });
    return;
  }

  const cleanCall = callSign.trim().toLowerCase();
  const allTeams = loadTeams();
  const activeTeam = allTeams.find(
    (t) => !t.retired && t.members.some((m) => m.callSign.toLowerCase() === cleanCall)
  );

  if (!activeTeam) {
    res.json({ success: true, inTeam: false, team: null });
    return;
  }

  const isCreator = activeTeam.createdBy.toLowerCase() === cleanCall;
  res.json({
    success: true,
    inTeam: true,
    team: {
      name: activeTeam.name,
      inviteCode: activeTeam.inviteCode,
      isCreator,
      maxSize: activeTeam.maxSize || 5,
      membershipOpen: true,
      members: activeTeam.members.map((m) => ({
        callSign: m.callSign,
        fullName: m.fullName || m.callSign,
        isCreator: m.isCreator,
        joinedAt: m.joinedAt,
      })),
    },
  });
});

// 2. Create team
app.post('/api/teams/create', (req, res) => {
  const { name, callSign, fullName } = req.body;
  if (!name || !callSign) {
    res.status(400).json({ success: false, error: 'Team name and callSign are required.' });
    return;
  }

  const cleanName = String(name).trim();
  const cleanCall = String(callSign).trim();
  const cleanFull = String(fullName || cleanCall).trim();

  if (cleanName.length < 3 || cleanName.length > 40) {
    res.status(400).json({ success: false, error: 'Team designation must be between 3 and 40 characters.' });
    return;
  }

  const reserved = ['admin','administrator','director','zodiac','cipher','organiser','organizer','system','moderator','owner','staff'];
  if (reserved.includes(cleanName.toLowerCase())) {
    res.status(400).json({ success: false, error: 'Designation contains reserved tactical terms.' });
    return;
  }

  const allTeams = loadTeams();

  // Check if user is already in an active team
  const existingUserTeam = allTeams.find(
    (t) => !t.retired && t.members.some((m) => m.callSign.toLowerCase() === cleanCall.toLowerCase())
  );
  if (existingUserTeam) {
    res.status(400).json({
      success: false,
      error: `You are already registered with active unit "${existingUserTeam.name}". Leave that unit first.`,
    });
    return;
  }

  // Check if team name is taken
  const nameTaken = allTeams.some(
    (t) => !t.retired && t.name.toLowerCase() === cleanName.toLowerCase()
  );
  if (nameTaken) {
    res.status(400).json({
      success: false,
      error: `A tactical unit with designation "${cleanName}" already exists. Choose a unique name.`,
    });
    return;
  }

  // Allocate unique code TLS-XXXXXX
  let inviteCode = '';
  for (let i = 0; i < 10; i++) {
    const candidate = `TLS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    if (!allTeams.some((t) => !t.retired && t.inviteCode.toUpperCase() === candidate)) {
      inviteCode = candidate;
      break;
    }
  }

  const nowIso = new Date().toISOString();
  const newTeam: ServerTeam = {
    id: `TEAM-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    name: cleanName,
    inviteCode,
    createdBy: cleanCall,
    createdAt: nowIso,
    maxSize: 5,
    retired: false,
    members: [
      {
        callSign: cleanCall,
        fullName: cleanFull,
        joinedAt: nowIso,
        isCreator: true,
      },
    ],
  };

  allTeams.unshift(newTeam);
  saveTeams(allTeams);

  console.info(`[TEAMS] Created unit "${cleanName}" (${inviteCode}) by @${cleanCall}`);

  res.status(201).json({
    success: true,
    message: `Tactical unit "${cleanName}" established! Invite code: ${inviteCode}`,
    team: {
      name: newTeam.name,
      inviteCode: newTeam.inviteCode,
      isCreator: true,
      maxSize: newTeam.maxSize,
      membershipOpen: true,
      members: newTeam.members,
    },
  });
});

// 3. Join team by invite code
app.post('/api/teams/join', (req, res) => {
  const { inviteCode, callSign, fullName } = req.body;
  if (!inviteCode || !callSign) {
    res.status(400).json({ success: false, error: 'Invite code and callSign are required.' });
    return;
  }

  const cleanCode = String(inviteCode).trim().toUpperCase();
  const cleanCall = String(callSign).trim();
  const cleanFull = String(fullName || cleanCall).trim();

  const allTeams = loadTeams();

  // Check if user is already in an active team
  const existingUserTeam = allTeams.find(
    (t) => !t.retired && t.members.some((m) => m.callSign.toLowerCase() === cleanCall.toLowerCase())
  );
  if (existingUserTeam) {
    res.status(400).json({
      success: false,
      error: `You are already assigned to active unit "${existingUserTeam.name}".`,
    });
    return;
  }

  // Find target team by invite code (handles raw or TLS- prefix)
  const targetTeam = allTeams.find((t) => {
    if (t.retired) return false;
    const tc = t.inviteCode.toUpperCase();
    return tc === cleanCode || tc === `TLS-${cleanCode}` || `TLS-${tc}` === cleanCode;
  });

  if (!targetTeam) {
    res.status(404).json({
      success: false,
      error: 'Invalid or expired invite code. Confirm the code with your lead operative.',
    });
    return;
  }

  if (targetTeam.members.length >= (targetTeam.maxSize || 5)) {
    res.status(400).json({
      success: false,
      error: `Tactical unit "${targetTeam.name}" has reached maximum capacity (${targetTeam.maxSize || 5} investigators).`,
    });
    return;
  }

  const nowIso = new Date().toISOString();
  targetTeam.members.push({
    callSign: cleanCall,
    fullName: cleanFull,
    joinedAt: nowIso,
    isCreator: false,
  });

  saveTeams(allTeams);

  console.info(`[TEAMS] @${cleanCall} joined unit "${targetTeam.name}" (${targetTeam.inviteCode})`);

  res.json({
    success: true,
    message: `Successfully enlisted into unit "${targetTeam.name}".`,
    team: {
      name: targetTeam.name,
      inviteCode: targetTeam.inviteCode,
      isCreator: targetTeam.createdBy.toLowerCase() === cleanCall.toLowerCase(),
      maxSize: targetTeam.maxSize || 5,
      membershipOpen: true,
      members: targetTeam.members,
    },
  });
});

// 4. Leave team
app.post('/api/teams/leave', (req, res) => {
  const { callSign } = req.body;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign is required.' });
    return;
  }

  const cleanCall = String(callSign).trim().toLowerCase();
  const allTeams = loadTeams();

  const targetTeam = allTeams.find(
    (t) => !t.retired && t.members.some((m) => m.callSign.toLowerCase() === cleanCall)
  );

  if (!targetTeam) {
    res.status(400).json({ success: false, error: 'You are not currently in an active unit.' });
    return;
  }

  // Remove member
  targetTeam.members = targetTeam.members.filter((m) => m.callSign.toLowerCase() !== cleanCall);

  // If no members remain, disband unit
  if (targetTeam.members.length === 0) {
    targetTeam.retired = true;
    console.info(`[TEAMS] Unit "${targetTeam.name}" disbanded (all members left).`);
  } else if (targetTeam.createdBy.toLowerCase() === cleanCall) {
    // If creator leaves, reassign creator to next oldest member
    targetTeam.createdBy = targetTeam.members[0].callSign;
    targetTeam.members[0].isCreator = true;
  }

  saveTeams(allTeams);

  console.info(`[TEAMS] @${cleanCall} departed unit "${targetTeam.name}". Reverted to solo operative.`);

  res.json({
    success: true,
    message: `Departed unit "${targetTeam.name}". You are now investigating as a solo operative.`,
  });
});

// 5. Rotate invite code (Creator only)
app.post('/api/teams/rotate-code', (req, res) => {
  const { callSign } = req.body;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign is required.' });
    return;
  }

  const cleanCall = String(callSign).trim().toLowerCase();
  const allTeams = loadTeams();

  const targetTeam = allTeams.find(
    (t) => !t.retired && t.createdBy.toLowerCase() === cleanCall
  );

  if (!targetTeam) {
    res.status(403).json({ success: false, error: 'Only the unit creator can cycle the invite code.' });
    return;
  }

  const newCode = `TLS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  targetTeam.inviteCode = newCode;
  saveTeams(allTeams);

  console.info(`[TEAMS] Rotated invite code for "${targetTeam.name}" to ${newCode}`);

  res.json({
    success: true,
    message: `Invite code updated to ${newCode}.`,
    inviteCode: newCode,
  });
});

// 6. STAFF: List all teams (Requires staff auth)
app.get('/api/staff/teams', requireStaffAuth, (_req, res) => {
  const teams = loadTeams();
  res.json({ success: true, teams });
});

/* =========================================================================
   LEADERBOARD PERSISTENCE & AGGREGATION ENGINE
   ========================================================================= */

const SCORES_FILE = path.join(DATA_DIR, 'player_scores.json');

export interface ServerPlayerScore {
  callSign: string;
  fullName: string;
  studentClass: string;
  score: number;
  stagesCompleted: number;
  lastProgress: string;
  excludeFromLeaderboard?: boolean;
  hasStageOverride?: boolean;
  teamName?: string | null;
  isStaff?: boolean;
  updatedAt: string;
}

function loadPlayerScores(): Record<string, ServerPlayerScore> {
  ensureDataDir();
  try {
    if (fs.existsSync(SCORES_FILE)) {
      return JSON.parse(fs.readFileSync(SCORES_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading scores file:', err);
  }
  return {};
}

function savePlayerScores(scores: Record<string, ServerPlayerScore>) {
  ensureDataDir();
  try {
    fs.writeFileSync(SCORES_FILE, JSON.stringify(scores, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving scores file:', err);
  }
}

// Client syncs their current progress and score
app.post('/api/leaderboard/sync', (req, res) => {
  const {
    callSign,
    fullName,
    studentClass = 'Class 9',
    score = 0,
    stagesCompleted = 0,
    lastProgress,
    excludeFromLeaderboard = false,
    hasStageOverride = false,
    teamName = null,
    isStaff = false,
  } = req.body;

  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign is required.' });
    return;
  }

  const cleanCall = String(callSign).trim().toLowerCase();
  const scores = loadPlayerScores();

  // Merge with staff overrides if present
  const overrides = loadOverrides();
  const overrideForUser = overrides[cleanCall];
  const isDevAccount = cleanCall === 'rudrapratapj.0562@gmail.com' || cleanCall === 'rudrapratapf.0562@gmail.com';
  const hasOverrideActive = Boolean(
    hasStageOverride ||
    (overrideForUser?.stages && Object.keys(overrideForUser.stages).length > 0)
  );
  const isExcluded = Boolean(
    excludeFromLeaderboard ||
    overrideForUser?.excludeFromLeaderboard ||
    isDevAccount ||
    hasOverrideActive ||
    isStaff
  );

  scores[cleanCall] = {
    callSign: String(callSign).trim(),
    fullName: String(fullName || callSign).trim(),
    studentClass: String(studentClass).trim(),
    score: Number(score) || 0,
    stagesCompleted: Number(stagesCompleted) || 0,
    lastProgress: lastProgress || new Date().toISOString(),
    excludeFromLeaderboard: isExcluded,
    hasStageOverride: hasOverrideActive,
    teamName: teamName ? String(teamName).trim() : null,
    isStaff: Boolean(isStaff),
    updatedAt: new Date().toISOString(),
  };

  savePlayerScores(scores);
  res.json({ success: true, record: scores[cleanCall] });
});

// GET /api/leaderboard - Real aggregated leaderboard entries
app.get('/api/leaderboard', async (req, res) => {
  const kindFilter = (req.query.kind as string) || 'all'; // 'all' | 'team' | 'solo'
  const classFilter = req.query.class as string; // e.g. 'Class 9'

  const scores = loadPlayerScores();
  const allTeams = loadTeams();
  const overrides = loadOverrides();

  interface LeaderboardEntryDTO {
    rank: number;
    name: string;
    kind: 'team' | 'solo';
    score: number;
    stagesCompleted: number;
    currentStage: number;
    completionPercentage: number;
    lastProgress: string | null;
    studentClass?: string;
    members?: string[];
    isCreator?: boolean;
    teamSize?: number;
  }

  let candidates: LeaderboardEntryDTO[] = [];

  // 1. Process Teams
  if (kindFilter === 'all' || kindFilter === 'team') {
    for (const team of allTeams) {
      if (team.retired) continue;

      // Only exclude team if all members are staff or explicitly marked excluded by staff
      const isTeamExcluded = team.members.length > 0 && team.members.every((m) => {
        const mc = m.callSign.toLowerCase();
        return (
          Boolean(overrides[mc]?.excludeFromLeaderboard) ||
          Boolean(scores[mc]?.excludeFromLeaderboard) ||
          Boolean(scores[mc]?.isStaff)
        );
      });

      if (isTeamExcluded) continue;

      // Calculate aggregate team score and stages completed (highest completed stage among active members)
      let maxScore = 0;
      let maxStages = 0;
      let latestProgress: string | null = null;
      let teamClasses: string[] = [];

      for (const member of team.members) {
        const pScore = scores[member.callSign.toLowerCase()];
        if (pScore) {
          if (pScore.score > maxScore) maxScore = pScore.score;
          if (pScore.stagesCompleted > maxStages) maxStages = pScore.stagesCompleted;
          if (pScore.lastProgress) {
            if (!latestProgress || new Date(pScore.lastProgress) > new Date(latestProgress)) {
              latestProgress = pScore.lastProgress;
            }
          }
          if (pScore.studentClass && !teamClasses.includes(pScore.studentClass)) {
            teamClasses.push(pScore.studentClass);
          }
        }
      }

      // If class filter is active, match if any member is in that class
      if (classFilter && classFilter !== 'all' && !teamClasses.includes(classFilter)) {
        continue;
      }

      candidates.push({
        rank: 0,
        name: team.name,
        kind: 'team',
        score: maxScore,
        stagesCompleted: maxStages,
        currentStage: Math.min(7, maxStages + 1),
        completionPercentage: Math.round((maxStages / 7) * 100),
        lastProgress: latestProgress || team.createdAt,
        studentClass: teamClasses.join(', ') || undefined,
        members: team.members.map((m) => m.callSign),
        teamSize: team.members.length,
      });
    }
  }

  // 2. Process Solo Operatives
  if (kindFilter === 'all' || kindFilter === 'solo') {
    for (const [key, pScore] of Object.entries(scores)) {
      // Exclude if already in an active team
      if (pScore.teamName) {
        const inActiveTeam = allTeams.some(
          (t) => !t.retired && t.members.some((m) => m.callSign.toLowerCase() === key)
        );
        if (inActiveTeam) continue;
      }

      // Exclusion check: only exclude if explicitly marked excludeFromLeaderboard or staff
      if (
        Boolean(pScore.excludeFromLeaderboard) ||
        Boolean(pScore.isStaff) ||
        Boolean(overrides[key]?.excludeFromLeaderboard)
      ) {
        continue;
      }

      // Class filter check
      if (classFilter && classFilter !== 'all' && pScore.studentClass !== classFilter) {
        continue;
      }

      candidates.push({
        rank: 0,
        name: pScore.callSign,
        kind: 'solo',
        score: pScore.score,
        stagesCompleted: pScore.stagesCompleted,
        currentStage: Math.min(7, pScore.stagesCompleted + 1),
        completionPercentage: Math.round((pScore.stagesCompleted / 7) * 100),
        lastProgress: pScore.lastProgress || pScore.updatedAt,
        studentClass: pScore.studentClass,
      });
    }
  }

  // 3. Sort entries: score desc, stagesCompleted desc, lastProgress asc, name asc
  candidates.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (b.stagesCompleted !== a.stagesCompleted) return b.stagesCompleted - a.stagesCompleted;
    if (a.lastProgress && b.lastProgress) {
      const diff = new Date(a.lastProgress).getTime() - new Date(b.lastProgress).getTime();
      if (diff !== 0) return diff;
    }
    return a.name.localeCompare(b.name);
  });

  // 4. Assign ranks with tie-handling
  const ranked = candidates.map((entry, idx) => ({
    ...entry,
    rank: idx + 1,
  }));

  res.json({
    success: true,
    total: ranked.length,
    entries: ranked,
  });
});

/* =========================================================================
   DEV / PRODUCTION SERVER SETUP
   ========================================================================= */

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    // Development mode: Mount Vite middleware
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Production mode: Serve built static assets from dist
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.info(`[THE LAST SIGNAL] Full-stack application server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[server] Fatal startup failure:', err);
  process.exit(1);
});
