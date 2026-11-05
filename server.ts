import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Body parsing
app.use(express.json({ limit: '2mb' }));

// Serve static public assets with correct MIME types and byte range support for media
app.use(express.static(path.join(__dirname, 'public')));

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

function sanitizeSupabaseUrl(url?: string): string | undefined {
  if (!url) return undefined;
  const trimmed = url.trim();
  if (!trimmed || trimmed.includes('your-project-id') || trimmed.includes('placeholder')) {
    return undefined;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return undefined;
    }
    return parsed.origin;
  } catch {
    return trimmed.replace(/\/+$/, '');
  }
}

// Supabase admin client for server-side operations
const supabaseUrl = sanitizeSupabaseUrl(process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL);
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
let supabaseAdmin: any = null;

if (supabaseUrl && supabaseServiceKey) {
  try {
    supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
      auth: { persistSession: false },
    });
    console.info(`[server] Supabase Admin Client initialized at ${supabaseUrl}`);
  } catch (err: any) {
    console.warn('[server] Supabase admin init error:', err?.message);
  }
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

// Authoritative Server Time Synchronization Endpoint
app.get('/api/time', (_req, res) => {
  res.json({
    success: true,
    serverTime: new Date().toISOString(),
    timestamp: Date.now(),
  });
});

// Settings & Registration Configuration (Authoritative Database State)
const SETTINGS_FILE = path.join(DATA_DIR, 'game_settings.json');

function loadGameSettings(): { registrationOpen: boolean; membershipOpen: boolean; paused: boolean; teamSizeMax: number } {
  ensureDataDir();
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading settings file:', err);
  }
  return { registrationOpen: true, membershipOpen: true, paused: false, teamSizeMax: 5 };
}

function saveGameSettings(settings: any) {
  ensureDataDir();
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving settings file:', err);
  }
}

app.get('/api/settings', async (_req, res) => {
  let settings = loadGameSettings();
  if (supabaseAdmin) {
    try {
      const { data, error } = await supabaseAdmin
        .from('game_settings')
        .select('*')
        .limit(1)
        .maybeSingle();
      if (!error && data) {
        settings = {
          registrationOpen: data.registration_open !== false,
          membershipOpen: data.membership_open !== false,
          paused: Boolean(data.paused ?? false),
          teamSizeMax: data.team_size_max || 5,
        };
        saveGameSettings(settings);
      }
    } catch (sbErr) {
      console.warn('[server] Supabase game_settings query warning:', sbErr);
    }
  }
  res.json({ success: true, settings });
});

// Staff toggle registration open / closed in live database
app.post('/api/staff/settings/registration', requireStaffAuth, async (req, res) => {
  const { open } = req.body;
  const isOpen = Boolean(open);
  const settings = loadGameSettings();
  settings.registrationOpen = isOpen;
  saveGameSettings(settings);

  if (supabaseAdmin) {
    try {
      await supabaseAdmin
        .from('game_settings')
        .upsert({ id: true, registration_open: isOpen, updated_at: new Date().toISOString() });
    } catch (sbErr) {
      console.warn('[server] Supabase game_settings update warning:', sbErr);
    }
  }

  console.info(`[SETTINGS] Registration status updated to ${isOpen ? 'OPEN' : 'CLOSED'} by staff.`);
  res.json({ success: true, registrationOpen: isOpen });
});


// USERNAME-BASED AUTHENTICATION PROXY (SUPABASE AUTH NATIVE)
app.post('/api/auth/username-login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    res.status(400).json({ success: false, error: 'Call-sign and password are required.' });
    return;
  }

  // Strip leading @ if entered by investigator (e.g. "@Cipher_echo" -> "Cipher_echo")
  const cleanUsername = username.trim().replace(/^@+/, '').trim();
  if (cleanUsername.length < 3) {
    res.status(400).json({ success: false, error: 'Call-sign must be at least 3 characters.' });
    return;
  }

  const anonKey = process.env.VITE_SUPABASE_ANON_KEY;
  if (supabaseUrl && anonKey) {
    try {
      const client = supabaseAdmin || createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
      let userEmail: string | null = null;
      let profile: any = null;

      // 1. If cleanUsername is already an email format
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanUsername)) {
        userEmail = cleanUsername.toLowerCase();
      }

      // 2. Try database RPC lookup if deployed
      if (!userEmail) {
        try {
          const { data: rpcEmail } = await client.rpc('lookup_auth_email_by_username', { p_username: cleanUsername });
          if (rpcEmail && typeof rpcEmail === 'string' && rpcEmail.includes('@')) {
            userEmail = rpcEmail.toLowerCase().trim();
          }
        } catch {}
      }

      // 3. Case-insensitive lookup in public.profiles by username or email
      if (!userEmail) {
        let { data: prof } = await client
          .from('profiles')
          .select('id, username, email, full_name, student_class, admission_masked')
          .ilike('username', cleanUsername)
          .maybeSingle();

        if (!prof) {
          const { data: profByEmail } = await client
            .from('profiles')
            .select('id, username, email, full_name, student_class, admission_masked')
            .ilike('email', cleanUsername)
            .maybeSingle();
          prof = profByEmail;
        }

        if (prof) {
          profile = prof;
          if (prof.email && prof.email.includes('@')) {
            userEmail = prof.email.toLowerCase().trim();
          } else if (supabaseAdmin) {
            try {
              const { data: userRecord } = await supabaseAdmin.auth.admin.getUserById(prof.id);
              if (userRecord?.user?.email) {
                userEmail = userRecord.user.email.toLowerCase().trim();
              }
            } catch {}
          }
        }
      }

      // 4. If email could not be resolved, return uniform credential error (no enumeration)
      if (!userEmail) {
        res.status(401).json({
          success: false,
          error: 'Invalid case credentials. Please verify your username and password.',
        });
        return;
      }

      // 5. Authenticate with Supabase Auth using the resolved email and provided password
      const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
      const { data: authData, error: authError } = await authClient.auth.signInWithPassword({
        email: userEmail,
        password: password,
      });

      if (authError || !authData.session) {
        res.status(401).json({
          success: false,
          error: 'Invalid case credentials. Please verify your username and password.',
        });
        return;
      }

      // 6. Fetch profile if not already fetched
      if (!profile) {
        const { data: fetchedProf } = await client
          .from('profiles')
          .select('id, username, email, full_name, student_class, admission_masked')
          .eq('id', authData.user.id)
          .maybeSingle();
        profile = fetchedProf;
      }

      // Return real Supabase session so browser can set it via supabase.auth.setSession()
      res.json({
        success: true,
        session: authData.session,
        user: authData.user,
        profile: profile || { id: authData.user.id, username: cleanUsername },
      });
      return;
    } catch (err: any) {
      console.error('[server] Error in username-login:', err);
      res.status(500).json({ success: false, error: 'Internal authentication server error.' });
      return;
    }
  }

  // Fallback if live Supabase is unconfigured (prototype mode)
  res.status(503).json({
    success: false,
    error: 'Live authentication service unavailable. Check Supabase connection.',
  });
});

// STAGE SCHEDULE & DUAL RELEASE CONFIGURATION FOR SERVER VERIFICATION
const STAGE_SCHEDULE_SERVER: Record<number, { openIso: string; prereqStages: number }> = {
  1: { openIso: '2026-11-01T00:00:00+05:30', prereqStages: 0 },
  2: { openIso: '2026-11-03T00:00:00+05:30', prereqStages: 1 },
  3: { openIso: '2026-11-05T00:00:00+05:30', prereqStages: 2 },
  4: { openIso: '2026-11-07T00:00:00+05:30', prereqStages: 3 },
  5: { openIso: '2026-11-09T00:00:00+05:30', prereqStages: 4 },
  6: { openIso: '2026-11-11T00:00:00+05:30', prereqStages: 5 },
  7: { openIso: '2026-11-13T00:00:00+05:30', prereqStages: 6 },
};

const CHALLENGE_TO_STAGE: Record<string, number> = {
  gate_zk_login: 1,
  stage2_coords: 2,
  gate_map: 3,
  gate_suspect_db: 5,
  gate_audio: 6,
};

// AUTHORITATIVE CHALLENGE VERIFICATION ENDPOINT
app.post('/api/challenges/submit', async (req, res) => {
  const { callSign, challengeKey, answer, username } = req.body;
  if (!challengeKey || !answer) {
    res.status(400).json({ success: false, status: 'unavailable', error: 'challengeKey and answer are required.' });
    return;
  }

  const cleanCall = String(callSign || username || '').trim().toLowerCase();
  const stageNumber = CHALLENGE_TO_STAGE[challengeKey] || 1;
  const stageConfig = STAGE_SCHEDULE_SERVER[stageNumber];

  // Check Staff / Admin Override
  const overrides = loadOverrides();
  const scores = loadPlayerScores();
  const userScoreRecord = scores[cleanCall];
  const userOverride = overrides[cleanCall];

  let dbStagesCompleted = 0;
  let dbHasOverride = false;
  let dbAlreadySolved = false;

  // If Supabase Admin is available, check authoritative participant record
  if (supabaseAdmin && cleanCall) {
    try {
      const { data: prof } = await supabaseAdmin
        .from('profiles')
        .select('id')
        .ilike('username', cleanCall)
        .maybeSingle();

      if (prof) {
        const { data: memberRows } = await supabaseAdmin
          .from('participant_members')
          .select('participant_id')
          .eq('user_id', prof.id)
          .is('left_at', null)
          .limit(1);

        const pid = memberRows?.[0]?.participant_id;
        if (pid) {
          const { data: compRows } = await supabaseAdmin
            .from('stage_completions')
            .select('stage_id')
            .eq('participant_id', pid);

          if (Array.isArray(compRows)) {
            dbStagesCompleted = compRows.reduce((max: number, r: any) => Math.max(max, Number(r.stage_id) || 0), 0);
            dbAlreadySolved = compRows.some((r: any) => Number(r.stage_id) === stageNumber);
          }

          const { data: ovRow } = await supabaseAdmin
            .from('participant_stage_overrides')
            .select('enabled')
            .eq('participant_id', pid)
            .maybeSingle();

          if (ovRow?.enabled) {
            dbHasOverride = true;
          }
        }
      }
    } catch (sbCheckErr) {
      console.warn('[server] Supabase profile check notice:', sbCheckErr);
    }
  }

  const effectiveHasOverride = Boolean(
    dbHasOverride ||
    userScoreRecord?.hasStageOverride ||
    userOverride?.hasStageOverride ||
    (userOverride?.stages && userOverride.stages[stageNumber]) ||
    req.body.currentProgress?.hasStageOverride
  );

  const effectiveStagesCompleted = Math.max(
    dbStagesCompleted,
    userScoreRecord?.stagesCompleted ?? 0,
    Number(req.body.stagesCompleted || req.body.currentProgress?.stagesCompleted || 0)
  );

  // DUAL RELEASE REQUIREMENT: PREVIOUS_STAGE_COMPLETED AND CURRENT_TIME >= RELEASE_TIMESTAMP
  if (!effectiveHasOverride && stageConfig) {
    const isPrereqCompleted = stageNumber === 1 || effectiveStagesCompleted >= stageConfig.prereqStages;
    const isReleaseTimeReached = Date.now() >= new Date(stageConfig.openIso).getTime();

    if (!isPrereqCompleted || !isReleaseTimeReached) {
      res.status(403).json({
        success: false,
        status: 'unavailable',
        message: !isPrereqCompleted
          ? 'PREREQUISITE LOCKED: Immediately preceding case sector must be cleared first.'
          : 'TIMELOCKED: Case file is sealed under stage release timetable.',
      });
      return;
    }
  }

  // Check if stage is already cleared by this operative
  const alreadyCleared = dbAlreadySolved || (userScoreRecord && userScoreRecord.stagesCompleted >= stageNumber);

  // 1. Authoritative Canonical Validation
  const norm = (s: string) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

  let isCorrect = false;
  let unlockedEvidence: string[] = [];

  if (challengeKey === 'gate_zk_login') {
    const cleanUser = norm(username || '');
    const cleanAns = norm(answer || '');
    const validUsers = ['zkcase', 'zkcase17', 'zk', 'zcase', 'archivalb'];
    const validAnswers = ['case17', '17'];

    // STRICT INDEPENDENT VERIFICATION:
    // Stage 1 has separate ZKCase (acrostic) and password (telestich) requirements.
    // 1. ZKCase directory requirement: must match the acrostic from the document margins.
    const isZkUserValid = validUsers.includes(cleanUser) || (cleanUser === 'zkcase17' && cleanAns === 'orion');
    // 2. Password clearance key requirement: must match the telestich key.
    const isPasswordValid = validAnswers.includes(cleanAns) || (cleanUser === 'zkcase17' && cleanAns === 'orion');

    // Both requirements must be satisfied independently.
    // The password 'case17' must NOT automatically satisfy the separate ZKCase requirement.
    // Neither requirement can be empty or bypass the other.
    if (cleanUser.length > 0 && cleanAns.length > 0 && isZkUserValid && isPasswordValid) {
      isCorrect = true;
      unlockedEvidence = ['EV-0102', 'EV-0103', 'EV-0201', 'EV-0202', 'EV-0203', 'EV-0204'];
    }
  } else if (challengeKey === 'stage2_coords') {
    const raw = String(answer || '').trim().toLowerCase();
    // Support cadastral house number or geographic coordinates
    const cleanHouse = raw.replace(/[^a-z0-9]/g, '');
    const isHouseNumber = cleanHouse === '3893' || cleanHouse === 'house3893';

    // Geographic decimal coordinates: latitude ~37.78874, longitude ~122.45709
    // Handles format variations: "37.78874, -122.45709", "(37.78874, -122.45709)",
    // "37.78874° N, 122.45709° W", "37.78874, 122.45709", "37.78874 -122.45709"
    const cleanCoords = raw.replace(/[()\[\]°\s]/g, '');
    const hasLat = cleanCoords.includes('37.78874');
    const hasLon = cleanCoords.includes('122.45709');

    if (isHouseNumber || (hasLat && hasLon)) {
      isCorrect = true;
      unlockedEvidence = ['CAS-017', 'EV-0301'];
    }
  } else if (challengeKey === 'gate_map') {
    const c = norm(answer || '');
    if (c === '3893' || c.includes('3893')) {
      isCorrect = true;
      unlockedEvidence = ['MAP-001', 'EV-0302'];
    }
  } else if (challengeKey === 'gate_suspect_db') {
    const c = norm(answer || '');
    if (c === 'z408reopened' || c === 'z408' || c.includes('z408reopened')) {
      isCorrect = true;
      unlockedEvidence = ['SUSP-001', 'SUSP-002', 'SUSP-003', 'SUSP-004'];
    }
  } else if (challengeKey === 'gate_audio') {
    const c = norm(answer || '');
    if (c.includes('ev1971') || c.includes('echo')) {
      isCorrect = true;
      unlockedEvidence = ['AUD-001', 'EV-0601'];
    }
  }

  // If input fails canonical validation, reject immediately
  if (!isCorrect) {
    res.status(400).json({
      success: false,
      status: 'incorrect',
      message: 'ACCESS DENIED: Decryption verification failed.',
    });
    return;
  }

  // 2. Synchronize with Supabase if token provided
  const authHeader = req.headers.authorization;
  const userBearerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (supabaseUrl && process.env.VITE_SUPABASE_ANON_KEY && userBearerToken) {
    try {
      const userClient = createClient(supabaseUrl, process.env.VITE_SUPABASE_ANON_KEY, {
        global: { headers: { Authorization: `Bearer ${userBearerToken}` } },
        auth: { persistSession: false },
      });

      await userClient.rpc('submit_challenge', {
        p_key: challengeKey,
        p_answer: answer,
        p_username: username || null,
      });
    } catch (err) {
      console.warn('[server] Supabase token sync notice:', err);
    }
  }

  if (isCorrect) {
    const nowIso = new Date().toISOString();

    // If this challenge was already solved, return already_solved with 0 additional points
    if (alreadyCleared) {
      res.json({
        success: true,
        status: 'already_solved',
        message: 'RECORD ON FILE: Clearance was previously unlocked for this case file.',
        pointsEarned: 0,
        hourlyBonus: 0,
        unlockedEvidence,
        stagesCompleted: effectiveStagesCompleted,
      });
      return;
    }

    // Authoritative hourly score calculation:
    // Base 100 points + 1 pt per elapsed hour from stage release, capped at 24 pts
    const openTimeMs = stageConfig ? new Date(stageConfig.openIso).getTime() : Date.now();
    const isPastDeadline = Boolean(stageConfig?.deadlineIso && Date.now() > new Date(stageConfig.deadlineIso).getTime());
    let hourlyBonus = 0;
    let awardedPoints = 0;
    let scoringEligible = true;

    if (isPastDeadline) {
      // Solved after stage deadline: 0 competitive points (story progression only)
      awardedPoints = 0;
      hourlyBonus = 0;
      scoringEligible = false;
    } else {
      const elapsedHours = Math.max(0, Math.floor((Date.now() - openTimeMs) / (3600 * 1000)));
      hourlyBonus = Math.min(24, elapsedHours);
      let targetBonus = 0;
      if (stageNumber === 4 && stageConfig?.targetBonus) {
        targetBonus = stageConfig.targetBonus;
      }
      awardedPoints = 100 + hourlyBonus + targetBonus;
      scoringEligible = true;
    }

    // Authoritative Supabase Persistence for solves & stage completions
    if (supabaseAdmin && cleanCall) {
      try {
        const { data: prof } = await supabaseAdmin
          .from('profiles')
          .select('id, username')
          .ilike('username', cleanCall)
          .maybeSingle();

        if (prof) {
          // Find active participant membership (team or solo)
          const { data: memberRows } = await supabaseAdmin
            .from('participant_members')
            .select('participant_id')
            .eq('user_id', prof.id)
            .is('left_at', null)
            .limit(1);

          let participantId = memberRows?.[0]?.participant_id;
          if (!participantId) {
            const { data: soloPart } = await supabaseAdmin
              .from('participants')
              .select('id')
              .eq('solo_user_id', prof.id)
              .eq('retired', false)
              .maybeSingle();
            participantId = soloPart?.id;
          }

          if (participantId) {
            // Find corresponding challenge ID
            const { data: chRow } = await supabaseAdmin
              .from('challenges')
              .select('id')
              .eq('key', challengeKey)
              .maybeSingle();

            if (chRow) {
              await supabaseAdmin.from('solves').upsert({
                participant_id: participantId,
                challenge_id: chRow.id,
                user_id: prof.id,
                solved_at: nowIso,
              }, { onConflict: 'participant_id,challenge_id' });
            }

            // Insert authoritative stage completion with hourly bonus points
            await supabaseAdmin.from('stage_completions').upsert({
              participant_id: participantId,
              stage_id: stageNumber,
              completed_at: nowIso,
              points_earned: awardedPoints,
              scoring_eligible: scoringEligible,
            }, { onConflict: 'participant_id,stage_id' });

            console.info(`[CHALLENGE] Authoritatively persisted stage ${stageNumber} (${challengeKey}) with ${awardedPoints} pts for participant ${participantId} (@${cleanCall})`);
          }
        }
      } catch (dbErr) {
        console.warn('[server] Supabase solve persistence warning:', dbErr);
      }
    }

    // Mirror to local cache as secondary offline fallback
    if (cleanCall) {
      scores[cleanCall] = scores[cleanCall] || {
        callSign: cleanCall,
        fullName: cleanCall,
        studentClass: 'Class 9',
        score: 0,
        stagesCompleted: 0,
        lastProgress: nowIso,
        updatedAt: nowIso,
      };

      if (scores[cleanCall].stagesCompleted < stageNumber) {
        scores[cleanCall].score += awardedPoints;
        scores[cleanCall].stagesCompleted = stageNumber;
      }
      scores[cleanCall].lastProgress = nowIso;
      scores[cleanCall].updatedAt = nowIso;
      savePlayerScores(scores);
    }

    res.json({
      success: true,
      status: 'correct',
      message: 'CLEARANCE GRANTED: Cryptographic key match confirmed.',
      pointsEarned: awardedPoints,
      hourlyBonus,
      scoringEligible,
      unlockedEvidence,
      stagesCompleted: stageNumber,
    });
  } else {
    res.status(400).json({
      success: false,
      status: 'incorrect',
      message: 'ACCESS DENIED: Decryption verification failed.',
    });
  }
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
  const ticketMap = new Map<string, any>();

  // 1. Add local tickets first (sanitized)
  all
    .filter((t) => t.callSign.toLowerCase() === clean)
    .forEach((t) => {
      const { staffNotes, ...sanitized } = t;
      ticketMap.set(sanitized.id, sanitized);
    });

  // 2. Fetch from Supabase if configured
  if (supabaseAdmin) {
    try {
      const { data: dbTickets, error: tErr } = await supabaseAdmin
        .from('support_tickets')
        .select('*')
        .ilike('call_sign', clean)
        .order('created_at', { ascending: false });

      if (!tErr && Array.isArray(dbTickets)) {
        dbTickets.forEach((r: any) => {
          ticketMap.set(r.id, {
            id: r.id,
            callSign: r.call_sign || clean,
            fullName: r.full_name || clean,
            studentClass: r.student_class || 'Class 9',
            subject: r.subject,
            category: r.category,
            message: r.message,
            status: r.status || 'OPEN',
            priority: r.priority || 'NORMAL',
            staffResponse: r.staff_response,
            resolvedBy: r.resolved_by,
            createdAt: r.created_at,
            updatedAt: r.updated_at,
          });
        });
      }
    } catch (err) {
      console.warn('[server] Supabase /api/tickets/mine query notice:', err);
    }
  }

  const result = Array.from(ticketMap.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  res.json({ success: true, tickets: result });
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

app.post('/api/staff/override-stage', requireStaffAuth, async (req, res) => {
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

  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin.from('profiles').select('id').ilike('username', callSign.trim()).maybeSingle();
      if (prof) {
        const { data: part } = await supabaseAdmin.from('participants').select('id').eq('solo_user_id', prof.id).maybeSingle();
        if (part) {
          await supabaseAdmin.from('participant_stage_overrides').upsert({
            participant_id: part.id,
            enabled: Boolean(enabled),
            granted_at: new Date().toISOString(),
          }, { onConflict: 'participant_id' });
        }
      }
    } catch (err) {
      console.warn('[server] Failed mirroring stage override to Supabase:', err);
    }
  }

  res.json({ success: true, overrides: overrides[key] });
});

app.post('/api/staff/leaderboard-exclusion', requireStaffAuth, async (req, res) => {
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

  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin.from('profiles').select('id').ilike('username', callSign.trim()).maybeSingle();
      if (prof) {
        await supabaseAdmin.from('participants').update({ exclude_from_leaderboard: Boolean(excluded) }).eq('solo_user_id', prof.id);
      }
    } catch (err) {
      console.warn('[server] Failed mirroring leaderboard exclusion to Supabase:', err);
    }
  }

  res.json({ success: true, excluded: overrides[key].excludeFromLeaderboard });
});

// STAFF: Real registered participants directory (Requires staff auth)
app.get('/api/staff/participants', requireStaffAuth, async (_req, res) => {
  let participantsList: any[] = [];

  if (supabaseAdmin) {
    try {
      const { data: parts, error: pErr } = await supabaseAdmin
        .from('participants')
        .select(`
          id,
          kind,
          name,
          invite_code,
          solo_user_id,
          created_by,
          exclude_from_leaderboard,
          retired,
          created_at,
          participant_members (
            user_id,
            joined_at,
            left_at,
            profiles:user_id (
              id,
              username,
              full_name,
              student_class,
              admission_masked,
              created_at
            )
          ),
          participant_stage_overrides (
            enabled,
            granted_at
          )
        `)
        .order('created_at', { ascending: false });

      if (!pErr && Array.isArray(parts)) {
        const { data: allCompletions } = await supabaseAdmin
          .from('stage_completions')
          .select('participant_id, stage_id, points_earned');

        const solvesMap = new Map<string, number>();
        const stagesMap = new Map<string, number>();

        if (Array.isArray(allCompletions)) {
          for (const c of allCompletions) {
            solvesMap.set(c.participant_id, (solvesMap.get(c.participant_id) || 0) + (c.points_earned || 0));
            stagesMap.set(c.participant_id, Math.max(stagesMap.get(c.participant_id) || 0, c.stage_id || 0));
          }
        }

        participantsList = parts.map((p: any) => {
          const members = (p.participant_members || [])
            .filter((m: any) => !m.left_at)
            .map((m: any) => ({
              userId: m.user_id,
              joinedAt: m.joined_at,
              isCreator: m.user_id === p.created_by,
              username: m.profiles?.username || 'Unknown Operative',
              fullName: m.profiles?.full_name || m.profiles?.username || 'Unknown',
              studentClass: m.profiles?.student_class || 'Class 9',
              admissionMasked: m.profiles?.admission_masked || 'ADM-••••0000',
            }));

          const primaryProfile = members[0] || null;
          const hasOverride = Boolean(
            p.participant_stage_overrides?.enabled ||
            (Array.isArray(p.participant_stage_overrides) && p.participant_stage_overrides.some((o: any) => o.enabled))
          );

          const score = solvesMap.get(p.id) || 0;
          const stagesCompleted = stagesMap.get(p.id) || 0;

          return {
            id: p.id,
            kind: p.kind as 'solo' | 'team',
            name: p.kind === 'team' ? p.name : (primaryProfile?.username || 'Solo Operative'),
            callSign: primaryProfile?.username || p.name || 'Operative',
            fullName: primaryProfile?.fullName || primaryProfile?.username || p.name || 'Operative',
            studentClass: primaryProfile?.studentClass || 'Class 9',
            admissionNumberMasked: primaryProfile?.admissionMasked || 'ADM-••••0000',
            inviteCode: p.invite_code || null,
            isCreator: true,
            retired: Boolean(p.retired),
            excludeFromLeaderboard: Boolean(p.exclude_from_leaderboard),
            hasStageOverride: hasOverride,
            score,
            stagesCompleted,
            activeStage: Math.min(7, stagesCompleted + 1),
            createdAt: p.created_at,
            members,
            teamSize: members.length,
          };
        });
      }
    } catch (err) {
      console.warn('[server] Error fetching Supabase participants for staff:', err);
    }
  }

  res.json({ success: true, participants: participantsList });
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
app.get('/api/teams/mine', async (req, res) => {
  const callSign = req.query.callSign as string;
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign query parameter required.' });
    return;
  }

  const cleanCall = callSign.trim().toLowerCase();

  // Authoritative Supabase query first
  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin
        .from('profiles')
        .select('id, username, full_name')
        .ilike('username', cleanCall)
        .maybeSingle();

      if (prof) {
        const { data: memberRows } = await supabaseAdmin
          .from('participant_members')
          .select(`
            participant_id,
            joined_at,
            participants:participant_id (
              id,
              kind,
              name,
              invite_code,
              created_by,
              retired,
              max_size,
              participant_members (
                user_id,
                joined_at,
                profiles:user_id (
                  username,
                  full_name
                )
              )
            )
          `)
          .eq('user_id', prof.id)
          .is('left_at', null)
          .limit(1);

        const activeMembership = memberRows?.[0];
        const part = activeMembership?.participants as any;

        if (part && !part.retired && part.kind === 'team') {
          const members = (part.participant_members || [])
            .filter((m: any) => !m.left_at)
            .map((m: any) => ({
              callSign: m.profiles?.username || 'Operative',
              fullName: m.profiles?.full_name || m.profiles?.username || 'Operative',
              isCreator: Boolean(m.user_id === part.created_by),
              joinedAt: m.joined_at,
            }));

          const isCreator = Boolean(
            part.created_by === prof.id ||
            members.some((m: any) => m.isCreator && m.callSign.toLowerCase() === cleanCall)
          );

          res.json({
            success: true,
            inTeam: true,
            team: {
              name: part.name,
              inviteCode: part.invite_code || '',
              isCreator,
              maxSize: part.max_size || 5,
              membershipOpen: true,
              members,
            },
          });
          return;
        } else if (part && part.kind === 'solo') {
          res.json({ success: true, inTeam: false, team: null });
          return;
        }
      }
    } catch (sbErr) {
      console.warn('[server] Supabase /api/teams/mine lookup warning:', sbErr);
    }
  }

  // Fallback to local cache
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
app.post('/api/teams/create', async (req, res) => {
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

  // Sync to Supabase if configured
  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin.from('profiles').select('id').ilike('username', cleanCall).maybeSingle();
      if (prof) {
        // Close prior solo active membership
        await supabaseAdmin.from('participant_members').update({ left_at: nowIso }).eq('user_id', prof.id).is('left_at', null);

        // Insert new team participant
        const { data: sbTeam } = await supabaseAdmin.from('participants').insert({
          kind: 'team',
          name: cleanName,
          invite_code: inviteCode,
          created_by: prof.id,
          retired: false,
        }).select('id').single();

        if (sbTeam) {
          await supabaseAdmin.from('participant_members').insert({
            participant_id: sbTeam.id,
            user_id: prof.id,
            joined_at: nowIso,
            left_at: null,
          });
        }
      }
    } catch (sbErr) {
      console.warn('[server] Supabase team creation mirror notice:', sbErr);
    }
  }

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
app.post('/api/teams/join', async (req, res) => {
  const { inviteCode, callSign, fullName } = req.body;
  if (!inviteCode || !callSign) {
    res.status(400).json({ success: false, error: 'Invite code and callSign are required.' });
    return;
  }

  const cleanCode = String(inviteCode).trim().toUpperCase();
  const rawInput = cleanCode.replace(/^TLS-/, '');
  const cleanCall = String(callSign).trim();
  const cleanFull = String(fullName || cleanCall).trim();
  const allTeams = loadTeams();

  // 1. Authoritative Supabase Validation First
  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin.from('profiles').select('id, username').ilike('username', cleanCall).maybeSingle();
      if (prof) {
        // Find team in Supabase
        const { data: sbTeam } = await supabaseAdmin
          .from('participants')
          .select(`
            id,
            name,
            invite_code,
            max_size,
            retired,
            created_by,
            participant_members (
              user_id,
              joined_at,
              left_at,
              profiles:user_id (
                username,
                full_name
              )
            )
          `)
          .eq('kind', 'team')
          .eq('retired', false)
          .or(`invite_code.ilike."${cleanCode}",invite_code.ilike."TLS-${rawInput}"`)
          .maybeSingle();

        if (sbTeam) {
          const activeMembers = (sbTeam.participant_members || []).filter((m: any) => !m.left_at);
          const limit = sbTeam.max_size || 5;

          if (activeMembers.length >= limit) {
            res.status(400).json({
              success: false,
              error: `Tactical unit "${sbTeam.name}" has reached maximum capacity (${limit} investigators).`,
            });
            return;
          }

          if (activeMembers.some((m: any) => m.user_id === prof.id)) {
            res.status(400).json({
              success: false,
              error: `You are already registered with unit "${sbTeam.name}".`,
            });
            return;
          }

          const nowIso = new Date().toISOString();
          // Close prior solo active membership
          await supabaseAdmin.from('participant_members').update({ left_at: nowIso }).eq('user_id', prof.id).is('left_at', null);

          // Insert into participant_members
          await supabaseAdmin.from('participant_members').upsert({
            participant_id: sbTeam.id,
            user_id: prof.id,
            joined_at: nowIso,
            left_at: null,
          }, { onConflict: 'participant_id,user_id' });

          const membersList = [
            ...activeMembers.map((m: any) => ({
              callSign: m.profiles?.username || 'Operative',
              fullName: m.profiles?.full_name || m.profiles?.username || 'Operative',
              isCreator: m.user_id === sbTeam.created_by,
              joinedAt: m.joined_at,
            })),
            {
              callSign: cleanCall,
              fullName: cleanFull,
              joinedAt: nowIso,
              isCreator: false,
            },
          ];

          // Mirror into local cache
          const localMatch = allTeams.find((t) => t.id === sbTeam.id || t.name.toLowerCase() === sbTeam.name.toLowerCase());
          if (localMatch) {
            localMatch.members = membersList;
          } else {
            allTeams.push({
              id: sbTeam.id,
              name: sbTeam.name,
              inviteCode: sbTeam.invite_code,
              createdBy: cleanCall,
              createdAt: nowIso,
              maxSize: limit,
              retired: false,
              members: membersList,
            });
          }
          saveTeams(allTeams);

          console.info(`[TEAMS] @${cleanCall} joined Supabase unit "${sbTeam.name}" (${sbTeam.invite_code})`);

          res.json({
            success: true,
            message: `Successfully enlisted into unit "${sbTeam.name}".`,
            team: {
              name: sbTeam.name,
              inviteCode: sbTeam.invite_code,
              isCreator: sbTeam.created_by === prof.id,
              maxSize: limit,
              membershipOpen: true,
              members: membersList,
            },
          });
          return;
        }
      }
    } catch (sbErr) {
      console.warn('[server] Supabase /api/teams/join lookup notice:', sbErr);
    }
  }

  // 2. Local fallback if not handled in Supabase
  const targetTeam = allTeams.find(
    (t) => !t.retired && (t.inviteCode.toUpperCase() === cleanCode || t.inviteCode.toUpperCase() === `TLS-${rawInput}`)
  );

  if (!targetTeam) {
    res.status(404).json({ success: false, error: 'Invalid or unrecognized unit invite code.' });
    return;
  }

  if (targetTeam.members.some((m) => m.callSign.toLowerCase() === cleanCall.toLowerCase())) {
    res.status(400).json({ success: false, error: `You are already registered with unit "${targetTeam.name}".` });
    return;
  }

  const limit = targetTeam.maxSize || 5;
  if (targetTeam.members.length >= limit) {
    res.status(400).json({ success: false, error: `Unit "${targetTeam.name}" has reached maximum capacity (${limit} investigators).` });
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
app.post('/api/teams/leave', async (req, res) => {
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

  // Supabase sync for departure
  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin.from('profiles').select('id').ilike('username', cleanCall).maybeSingle();
      if (prof) {
        await supabaseAdmin.from('participant_members').update({ left_at: new Date().toISOString() }).eq('user_id', prof.id).is('left_at', null);
      }
    } catch (sbErr) {
      console.warn('[server] Supabase team departure sync notice:', sbErr);
    }
  }

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
  const processedCallSigns = new Set<string>();

  // 1. Fetch real eligible participants from Supabase if available
  if (supabaseAdmin) {
    try {
      const { data: parts, error: pErr } = await supabaseAdmin
        .from('participants')
        .select(`
          id,
          kind,
          name,
          solo_user_id,
          exclude_from_leaderboard,
          retired,
          created_at,
          participant_members (
            user_id,
            left_at,
            profiles:user_id (
              id,
              username,
              full_name,
              student_class,
              admission_masked
            )
          ),
          participant_stage_overrides (
            enabled
          )
        `)
        .eq('retired', false);

      if (!pErr && Array.isArray(parts)) {
        const { data: allComps } = await supabaseAdmin
          .from('stage_completions')
          .select('participant_id, stage_id, points_earned');

        const { data: allAdjs } = await supabaseAdmin
          .from('score_adjustments')
          .select('participant_id, points');

        const solvesMap = new Map<string, number>();
        const compsMap = new Map<string, number>();
        allComps?.forEach((c: any) => {
          solvesMap.set(c.participant_id, (solvesMap.get(c.participant_id) || 0) + (c.points_earned || 0));
          compsMap.set(c.participant_id, Math.max(compsMap.get(c.participant_id) || 0, c.stage_id || 0));
        });
        allAdjs?.forEach((a: any) => {
          solvesMap.set(a.participant_id, (solvesMap.get(a.participant_id) || 0) + (a.points || 0));
        });

        for (const p of parts) {
          const hasOverride = Boolean(
            p.participant_stage_overrides?.enabled ||
            (Array.isArray(p.participant_stage_overrides) && p.participant_stage_overrides.some((o: any) => o.enabled))
          );

          const activeMembers = (p.participant_members || [])
            .filter((m: any) => !m.left_at)
            .map((m: any) => m.profiles)
            .filter(Boolean);

          const firstProfile = activeMembers[0];
          const username = (p.kind === 'team' ? p.name : firstProfile?.username) || 'Unknown';
          const callKey = (firstProfile?.username || username).toLowerCase().trim();

          const isDev = callKey.includes('rudrapratapj') || callKey.includes('rudrapratapf');
          const isExcluded = Boolean(
            p.exclude_from_leaderboard ||
            hasOverride ||
            isDev ||
            overrides[callKey]?.excludeFromLeaderboard ||
            scores[callKey]?.excludeFromLeaderboard ||
            scores[callKey]?.hasStageOverride
          );

          // Skip testing/admin accounts with overrides or exclusion flags
          if (isExcluded) continue;

          // Merge score from DB solves or live client sync
          const dbScore = solvesMap.get(p.id) || 0;
          const dbStages = compsMap.get(p.id) || 0;

          let liveScore = scores[callKey]?.score || 0;
          let liveStages = scores[callKey]?.stagesCompleted || 0;
          if (p.kind === 'team') {
            for (const m of activeMembers) {
              const mk = (m.username || '').toLowerCase().trim();
              if (scores[mk]) {
                liveScore = Math.max(liveScore, scores[mk].score || 0);
                liveStages = Math.max(liveStages, scores[mk].stagesCompleted || 0);
              }
            }
          }

          const finalScore = Math.max(dbScore, liveScore);
          const finalStages = Math.max(dbStages, liveStages);

          const userClass = firstProfile?.student_class || scores[callKey]?.studentClass || 'Class 9';

          if (classFilter && classFilter !== 'all' && userClass !== classFilter) {
            continue;
          }

          if (p.kind === 'team' && (kindFilter === 'all' || kindFilter === 'team')) {
            candidates.push({
              rank: 0,
              name: p.name || 'Tactical Team',
              kind: 'team',
              score: finalScore,
              stagesCompleted: finalStages,
              currentStage: Math.min(7, finalStages + 1),
              completionPercentage: Math.round((finalStages / 7) * 100),
              lastProgress: scores[callKey]?.lastProgress || p.created_at,
              studentClass: userClass,
              members: activeMembers.map((m: any) => m.username),
              teamSize: activeMembers.length,
            });
          } else if (p.kind === 'solo' && (kindFilter === 'all' || kindFilter === 'solo')) {
            candidates.push({
              rank: 0,
              name: firstProfile?.username || 'Operative',
              kind: 'solo',
              score: finalScore,
              stagesCompleted: finalStages,
              currentStage: Math.min(7, finalStages + 1),
              completionPercentage: Math.round((finalStages / 7) * 100),
              lastProgress: scores[callKey]?.lastProgress || p.created_at,
              studentClass: userClass,
            });
            processedCallSigns.add(callKey);
          }
        }
      }
    } catch (sbErr) {
      console.warn('[server] Supabase leaderboard aggregation notice:', sbErr);
    }
  }

  // 2. Offline Fallback ONLY: Process purely local scores when Supabase is disconnected
  if (!supabaseAdmin) {
    const activeTeamMemberCallsigns = new Set<string>();
    for (const tm of allTeams) {
      if (tm.retired) continue;
      for (const m of tm.members) {
        activeTeamMemberCallsigns.add(m.callSign.toLowerCase().trim());
      }
    }

    // A. Tactical Teams
    if (kindFilter === 'all' || kindFilter === 'team') {
      for (const tm of allTeams) {
        if (tm.retired) continue;
        const validMembers = tm.members.filter((m) => {
          const mk = m.callSign.toLowerCase().trim();
          return !mk.includes('rudrapratapj') && !mk.includes('rudrapratapf') && !overrides[mk]?.excludeFromLeaderboard && !scores[mk]?.excludeFromLeaderboard;
        });
        if (validMembers.length === 0) continue;

        const teamScore = Math.max(0, ...validMembers.map((m) => scores[m.callSign.toLowerCase().trim()]?.score || 0));
        const teamStages = Math.max(0, ...validMembers.map((m) => scores[m.callSign.toLowerCase().trim()]?.stagesCompleted || 0));
        const teamClass = validMembers.map((m) => scores[m.callSign.toLowerCase().trim()]?.studentClass).find(Boolean) || 'Class 9';

        if (classFilter && classFilter !== 'all' && teamClass !== classFilter) continue;

        candidates.push({
          rank: 0,
          name: tm.name,
          kind: 'team',
          score: teamScore,
          stagesCompleted: teamStages,
          currentStage: Math.min(7, teamStages + 1),
          completionPercentage: Math.round((teamStages / 7) * 100),
          lastProgress: tm.createdAt,
          studentClass: teamClass,
          members: validMembers.map((m) => m.callSign),
          teamSize: validMembers.length,
        });
      }
    }

    // B. Solo Operatives
    if (kindFilter === 'all' || kindFilter === 'solo') {
      for (const [key, pScore] of Object.entries(scores)) {
        if (processedCallSigns.has(key)) continue;

        // When in 'all' view, unaffiliated operatives or non-team members appear as solo
        if (kindFilter === 'all' && activeTeamMemberCallsigns.has(key)) {
          continue;
        }

        if (
          pScore.excludeFromLeaderboard ||
          pScore.hasStageOverride ||
          pScore.isStaff ||
          overrides[key]?.excludeFromLeaderboard ||
          (overrides[key]?.stages && Object.keys(overrides[key].stages).length > 0) ||
          key === 'rudrapratapj.0562@gmail.com' ||
          key === 'rudrapratapf.0562@gmail.com'
        ) {
          continue;
        }

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
   STAFF-TO-PLAYER COMMUNICATIONS SYSTEM (Announcements & Private Messages)
   ========================================================================= */

const COMMUNICATIONS_FILE = path.join(DATA_DIR, 'communications.json');

interface CommunicationsStore {
  announcements: Array<{
    id: string;
    title: string;
    message: string;
    targetType: 'all' | 'stage' | 'team' | 'player';
    targetValue?: string;
    createdBy: string;
    createdAt: string;
    pinned?: boolean;
  }>;
  conversations: Array<{
    id: string;
    playerCallSign: string;
    playerName: string;
    playerStudentClass?: string;
    status: 'open' | 'resolved';
    unreadStaffCount: number;
    unreadPlayerCount: number;
    lastMessage?: string;
    lastMessageAt: string;
    createdAt: string;
    updatedAt: string;
    messages: Array<{
      id: string;
      conversationId: string;
      senderType: 'staff' | 'player';
      senderCallSign: string;
      senderName: string;
      message: string;
      readByStaff: boolean;
      readByPlayer: boolean;
      createdAt: string;
    }>;
  }>;
}

function loadCommunications(): CommunicationsStore {
  ensureDataDir();
  try {
    if (fs.existsSync(COMMUNICATIONS_FILE)) {
      return JSON.parse(fs.readFileSync(COMMUNICATIONS_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('[server] Error reading communications file:', err);
  }
  return {
    announcements: [
      {
        id: 'ann-init-01',
        title: 'Operations Desk: Welcome to Case TLS-0017',
        message: 'All student investigators: Review the First Directive classified case files. Ensure your call-sign registration is logged. Case sectors unlock on the scheduled IST timetable.',
        targetType: 'all',
        createdBy: 'DIRECTOR OF INVESTIGATION',
        createdAt: '2026-10-30T00:00:00.000Z',
        pinned: true,
      },
    ],
    conversations: [],
  };
}

function saveCommunications(store: CommunicationsStore) {
  ensureDataDir();
  try {
    fs.writeFileSync(COMMUNICATIONS_FILE, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.error('[server] Error saving communications file:', err);
  }
}

// 1. Player: Get eligible announcements
app.get('/api/communications/announcements', async (req, res) => {
  const callSign = (req.query.callSign as string || '').toLowerCase().trim();
  const stage = Number(req.query.stage) || 1;
  const team = (req.query.team as string || '').toLowerCase().trim();

  const store = loadCommunications();

  // Try Supabase if configured
  if (supabaseAdmin) {
    try {
      const { data: dbAnnouncements } = await supabaseAdmin
        .from('announcements')
        .select('*')
        .order('created_at', { ascending: false });

      if (Array.isArray(dbAnnouncements) && dbAnnouncements.length > 0) {
        const filtered = dbAnnouncements.filter((a: any) => {
          if (!a.target_type || a.target_type === 'all') return true;
          if (a.target_type === 'stage' && String(a.target_value) === String(stage)) return true;
          if (a.target_type === 'team' && team && a.target_value?.toLowerCase() === team) return true;
          if (a.target_type === 'player' && callSign && a.target_value?.toLowerCase() === callSign) return true;
          return false;
        }).map((a: any) => ({
          id: a.id,
          title: a.title,
          message: a.message,
          targetType: a.target_type,
          targetValue: a.target_value,
          createdBy: a.created_by || 'Operations Command',
          createdAt: a.created_at,
          pinned: Boolean(a.pinned),
        }));

        res.json({ success: true, announcements: filtered });
        return;
      }
    } catch (sbErr) {
      console.warn('[server] Supabase announcements query warning:', sbErr);
    }
  }

  // Fallback to local store
  const filtered = store.announcements.filter((a) => {
    if (!a.targetType || a.targetType === 'all') return true;
    if (a.targetType === 'stage' && String(a.targetValue) === String(stage)) return true;
    if (a.targetType === 'team' && team && a.targetValue?.toLowerCase() === team) return true;
    if (a.targetType === 'player' && callSign && a.targetValue?.toLowerCase() === callSign) return true;
    return false;
  });

  res.json({ success: true, announcements: filtered });
});

// 2. Staff: List all announcements
app.get('/api/staff/announcements', requireStaffAuth, async (_req, res) => {
  const store = loadCommunications();
  if (supabaseAdmin) {
    try {
      const { data: dbAnnouncements } = await supabaseAdmin
        .from('announcements')
        .select('*')
        .order('created_at', { ascending: false });
      if (Array.isArray(dbAnnouncements) && dbAnnouncements.length > 0) {
        const mapped = dbAnnouncements.map((a: any) => ({
          id: a.id,
          title: a.title,
          message: a.message,
          targetType: a.target_type,
          targetValue: a.target_value,
          createdBy: a.created_by,
          createdAt: a.created_at,
          pinned: Boolean(a.pinned),
        }));
        res.json({ success: true, announcements: mapped });
        return;
      }
    } catch {}
  }
  res.json({ success: true, announcements: store.announcements });
});

// 3. Staff: Post announcement
app.post('/api/staff/announcements', requireStaffAuth, async (req, res) => {
  const { title, message, targetType = 'all', targetValue, pinned = false } = req.body;
  if (!title || !message) {
    res.status(400).json({ success: false, error: 'Announcement title and message are required.' });
    return;
  }

  const store = loadCommunications();
  const nowIso = new Date().toISOString();
  const newAnn = {
    id: `ann_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    title: String(title).trim(),
    message: String(message).trim(),
    targetType: targetType as 'all' | 'stage' | 'team' | 'player',
    targetValue: targetValue ? String(targetValue).trim() : undefined,
    createdBy: 'STAFF OPERATIONS DESK',
    createdAt: nowIso,
    pinned: Boolean(pinned),
  };

  store.announcements.unshift(newAnn);
  saveCommunications(store);

  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('announcements').insert({
        id: newAnn.id,
        title: newAnn.title,
        message: newAnn.message,
        target_type: newAnn.targetType,
        target_value: newAnn.targetValue || null,
        created_by: newAnn.createdBy,
        created_at: nowIso,
        pinned: newAnn.pinned,
      });
    } catch (sbErr) {
      console.warn('[server] Supabase announcement insert warning:', sbErr);
    }
  }

  res.json({ success: true, announcement: newAnn });
});

// 4. Staff: Delete announcement
app.delete('/api/staff/announcements/:id', requireStaffAuth, async (req, res) => {
  const { id } = req.params;
  const store = loadCommunications();
  store.announcements = store.announcements.filter((a) => a.id !== id);
  saveCommunications(store);

  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('announcements').delete().eq('id', id);
    } catch {}
  }
  res.json({ success: true });
});

// 5. Staff: List all conversations (Inbox)
app.get('/api/staff/conversations', requireStaffAuth, async (_req, res) => {
  const store = loadCommunications();

  if (supabaseAdmin) {
    try {
      const { data: dbConv } = await supabaseAdmin
        .from('staff_conversations')
        .select(`
          id,
          player_callsign,
          player_name,
          player_student_class,
          status,
          unread_staff_count,
          unread_player_count,
          last_message,
          last_message_at,
          created_at,
          updated_at
        `)
        .order('last_message_at', { ascending: false });

      if (Array.isArray(dbConv) && dbConv.length > 0) {
        const mapped = dbConv.map((c: any) => ({
          id: c.id,
          playerCallSign: c.player_callsign,
          playerName: c.player_name,
          playerStudentClass: c.player_student_class,
          status: c.status,
          unreadStaffCount: c.unread_staff_count || 0,
          unreadPlayerCount: c.unread_player_count || 0,
          lastMessage: c.last_message,
          lastMessageAt: c.last_message_at || c.updated_at,
          createdAt: c.created_at,
          updatedAt: c.updated_at,
        }));
        res.json({ success: true, conversations: mapped });
        return;
      }
    } catch {}
  }

  const mapped = store.conversations.map((c) => ({
    id: c.id,
    playerCallSign: c.playerCallSign,
    playerName: c.playerName,
    playerStudentClass: c.playerStudentClass,
    status: c.status,
    unreadStaffCount: c.unreadStaffCount,
    unreadPlayerCount: c.unreadPlayerCount,
    lastMessage: c.lastMessage,
    lastMessageAt: c.lastMessageAt,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
  }));

  res.json({ success: true, conversations: mapped });
});

// 6. Staff: Get conversation messages
app.get('/api/staff/conversations/:id/messages', requireStaffAuth, async (req, res) => {
  const { id } = req.params;
  const store = loadCommunications();

  if (supabaseAdmin) {
    try {
      const { data: msgs } = await supabaseAdmin
        .from('staff_conversation_messages')
        .select('*')
        .eq('conversation_id', id)
        .order('created_at', { ascending: true });

      if (Array.isArray(msgs)) {
        // Mark as read by staff
        await supabaseAdmin
          .from('staff_conversation_messages')
          .update({ read_by_staff: true })
          .eq('conversation_id', id)
          .eq('read_by_staff', false);

        await supabaseAdmin
          .from('staff_conversations')
          .update({ unread_staff_count: 0 })
          .eq('id', id);

        const mapped = msgs.map((m: any) => ({
          id: m.id,
          conversationId: m.conversation_id,
          senderType: m.sender_type,
          senderCallSign: m.sender_callsign,
          senderName: m.sender_name,
          message: m.message,
          readByStaff: true,
          readByPlayer: m.read_by_player,
          createdAt: m.created_at,
        }));

        res.json({ success: true, messages: mapped });
        return;
      }
    } catch {}
  }

  const conv = store.conversations.find((c) => c.id === id);
  if (!conv) {
    res.status(404).json({ success: false, error: 'Conversation not found.' });
    return;
  }

  conv.unreadStaffCount = 0;
  conv.messages.forEach((m) => {
    m.readByStaff = true;
  });
  saveCommunications(store);

  res.json({ success: true, messages: conv.messages });
});

// 7. Staff: Start or open conversation with a player
app.post('/api/staff/conversations/start', requireStaffAuth, async (req, res) => {
  const { playerCallSign } = req.body;
  if (!playerCallSign) {
    res.status(400).json({ success: false, error: 'playerCallSign is required.' });
    return;
  }

  const cleanCall = String(playerCallSign).trim();
  const store = loadCommunications();
  let existing = store.conversations.find(
    (c) => c.playerCallSign.toLowerCase() === cleanCall.toLowerCase()
  );

  let playerName = cleanCall;
  let playerClass = 'Class 9';

  if (supabaseAdmin) {
    try {
      const { data: prof } = await supabaseAdmin
        .from('profiles')
        .select('username, full_name, student_class')
        .ilike('username', cleanCall)
        .maybeSingle();

      if (prof) {
        playerName = prof.full_name || prof.username;
        playerClass = prof.student_class || 'Class 9';
      }

      // Check Supabase conversation
      const { data: sbConv } = await supabaseAdmin
        .from('staff_conversations')
        .select('*')
        .ilike('player_callsign', cleanCall)
        .maybeSingle();

      if (sbConv) {
        res.json({
          success: true,
          conversation: {
            id: sbConv.id,
            playerCallSign: sbConv.player_callsign,
            playerName: sbConv.player_name,
            playerStudentClass: sbConv.player_student_class,
            status: sbConv.status,
            unreadStaffCount: sbConv.unread_staff_count || 0,
            unreadPlayerCount: sbConv.unread_player_count || 0,
            lastMessage: sbConv.last_message,
            lastMessageAt: sbConv.last_message_at,
            createdAt: sbConv.created_at,
            updatedAt: sbConv.updated_at,
          },
        });
        return;
      }
    } catch {}
  }

  if (existing) {
    res.json({ success: true, conversation: existing });
    return;
  }

  const nowIso = new Date().toISOString();
  const newConvId = `conv_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const newConv = {
    id: newConvId,
    playerCallSign: cleanCall,
    playerName,
    playerStudentClass: playerClass,
    status: 'open' as const,
    unreadStaffCount: 0,
    unreadPlayerCount: 0,
    lastMessage: 'Conversation opened by Staff Operations.',
    lastMessageAt: nowIso,
    createdAt: nowIso,
    updatedAt: nowIso,
    messages: [
      {
        id: `msg_${Date.now()}_init`,
        conversationId: newConvId,
        senderType: 'staff' as const,
        senderCallSign: 'OPERATIONS',
        senderName: 'Staff Operations Command',
        message: 'Tactical channel established with Staff Operations. How can we assist your investigation?',
        readByStaff: true,
        readByPlayer: false,
        createdAt: nowIso,
      },
    ],
  };

  store.conversations.unshift(newConv);
  saveCommunications(store);

  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('staff_conversations').insert({
        id: newConv.id,
        player_callsign: newConv.playerCallSign,
        player_name: newConv.playerName,
        player_student_class: newConv.playerStudentClass,
        status: newConv.status,
        unread_staff_count: 0,
        unread_player_count: 1,
        last_message: newConv.lastMessage,
        last_message_at: nowIso,
        created_at: nowIso,
        updated_at: nowIso,
      });

      await supabaseAdmin.from('staff_conversation_messages').insert({
        id: newConv.messages[0].id,
        conversation_id: newConv.id,
        sender_type: 'staff',
        sender_callsign: 'OPERATIONS',
        sender_name: 'Staff Operations Command',
        message: newConv.messages[0].message,
        read_by_staff: true,
        read_by_player: false,
        created_at: nowIso,
      });
    } catch {}
  }

  res.json({ success: true, conversation: newConv });
});

// 8. Staff: Post message to conversation
app.post('/api/staff/conversations/:id/message', requireStaffAuth, async (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  if (!message || !String(message).trim()) {
    res.status(400).json({ success: false, error: 'Message content is required.' });
    return;
  }

  const cleanMsg = String(message).trim();
  const nowIso = new Date().toISOString();
  const store = loadCommunications();
  const conv = store.conversations.find((c) => c.id === id);

  const newMsg = {
    id: `msg_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    conversationId: id,
    senderType: 'staff' as const,
    senderCallSign: 'OPERATIONS',
    senderName: 'Staff Operations Desk',
    message: cleanMsg,
    readByStaff: true,
    readByPlayer: false,
    createdAt: nowIso,
  };

  if (conv) {
    conv.messages.push(newMsg);
    conv.lastMessage = cleanMsg;
    conv.lastMessageAt = nowIso;
    conv.updatedAt = nowIso;
    conv.unreadPlayerCount = (conv.unreadPlayerCount || 0) + 1;
    saveCommunications(store);
  }

  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('staff_conversation_messages').insert({
        id: newMsg.id,
        conversation_id: id,
        sender_type: 'staff',
        sender_callsign: 'OPERATIONS',
        sender_name: 'Staff Operations Desk',
        message: cleanMsg,
        read_by_staff: true,
        read_by_player: false,
        created_at: nowIso,
      });

      await supabaseAdmin
        .from('staff_conversations')
        .update({
          last_message: cleanMsg,
          last_message_at: nowIso,
          updated_at: nowIso,
        })
        .eq('id', id);
    } catch {}
  }

  res.json({ success: true, message: newMsg });
});

// 9. Staff: Update conversation status (open / resolved)
app.post('/api/staff/conversations/:id/status', requireStaffAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (status !== 'open' && status !== 'resolved') {
    res.status(400).json({ success: false, error: 'Status must be "open" or "resolved".' });
    return;
  }

  const store = loadCommunications();
  const conv = store.conversations.find((c) => c.id === id);
  if (conv) {
    conv.status = status;
    conv.updatedAt = new Date().toISOString();
    saveCommunications(store);
  }

  if (supabaseAdmin) {
    try {
      await supabaseAdmin
        .from('staff_conversations')
        .update({ status, updated_at: new Date().toISOString() })
        .eq('id', id);
    } catch {}
  }

  res.json({ success: true, status });
});

// 10. Player: Fetch conversation and messages
app.get('/api/communications/conversation', async (req, res) => {
  const callSign = (req.query.callSign as string || '').trim();
  if (!callSign) {
    res.status(400).json({ success: false, error: 'callSign is required.' });
    return;
  }

  const cleanCall = callSign.toLowerCase();
  const store = loadCommunications();

  if (supabaseAdmin) {
    try {
      const { data: sbConv } = await supabaseAdmin
        .from('staff_conversations')
        .select('*')
        .ilike('player_callsign', cleanCall)
        .maybeSingle();

      if (sbConv) {
        const { data: msgs } = await supabaseAdmin
          .from('staff_conversation_messages')
          .select('*')
          .eq('conversation_id', sbConv.id)
          .order('created_at', { ascending: true });

        const mappedMsgs = (msgs || []).map((m: any) => ({
          id: m.id,
          conversationId: m.conversation_id,
          senderType: m.sender_type,
          senderCallSign: m.sender_callsign,
          senderName: m.sender_name,
          message: m.message,
          readByStaff: m.read_by_staff,
          readByPlayer: m.read_by_player,
          createdAt: m.created_at,
        }));

        res.json({
          success: true,
          conversation: {
            id: sbConv.id,
            playerCallSign: sbConv.player_callsign,
            playerName: sbConv.player_name,
            playerStudentClass: sbConv.player_student_class,
            status: sbConv.status,
            unreadStaffCount: sbConv.unread_staff_count || 0,
            unreadPlayerCount: sbConv.unread_player_count || 0,
            lastMessage: sbConv.last_message,
            lastMessageAt: sbConv.last_message_at,
            createdAt: sbConv.created_at,
            updatedAt: sbConv.updated_at,
          },
          messages: mappedMsgs,
        });
        return;
      }
    } catch {}
  }

  const conv = store.conversations.find((c) => c.playerCallSign.toLowerCase() === cleanCall);
  if (!conv) {
    res.json({ success: true, conversation: null, messages: [] });
    return;
  }

  res.json({ success: true, conversation: conv, messages: conv.messages });
});

// 11. Player: Send reply message to staff
app.post('/api/communications/message', async (req, res) => {
  const { callSign, fullName, studentClass = 'Class 9', message } = req.body;
  if (!callSign || !message || !String(message).trim()) {
    res.status(400).json({ success: false, error: 'callSign and message are required.' });
    return;
  }

  const cleanCall = String(callSign).trim();
  const cleanMsg = String(message).trim();
  const nowIso = new Date().toISOString();
  const store = loadCommunications();

  let conv = store.conversations.find((c) => c.playerCallSign.toLowerCase() === cleanCall.toLowerCase());
  let convId = conv?.id;

  if (!conv) {
    convId = `conv_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    conv = {
      id: convId,
      playerCallSign: cleanCall,
      playerName: String(fullName || cleanCall).trim(),
      playerStudentClass: String(studentClass).trim(),
      status: 'open',
      unreadStaffCount: 1,
      unreadPlayerCount: 0,
      lastMessage: cleanMsg,
      lastMessageAt: nowIso,
      createdAt: nowIso,
      updatedAt: nowIso,
      messages: [],
    };
    store.conversations.unshift(conv);
  }

  const newMsg = {
    id: `msg_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    conversationId: convId!,
    senderType: 'player' as const,
    senderCallSign: cleanCall,
    senderName: String(fullName || cleanCall).trim(),
    message: cleanMsg,
    readByStaff: false,
    readByPlayer: true,
    createdAt: nowIso,
  };

  conv.messages.push(newMsg);
  conv.lastMessage = cleanMsg;
  conv.lastMessageAt = nowIso;
  conv.updatedAt = nowIso;
  conv.unreadStaffCount = (conv.unreadStaffCount || 0) + 1;
  saveCommunications(store);

  if (supabaseAdmin) {
    try {
      // Upsert conversation row
      await supabaseAdmin.from('staff_conversations').upsert({
        id: convId,
        player_callsign: cleanCall,
        player_name: String(fullName || cleanCall).trim(),
        player_student_class: String(studentClass).trim(),
        status: 'open',
        last_message: cleanMsg,
        last_message_at: nowIso,
        updated_at: nowIso,
      }, { onConflict: 'id' });

      // Insert message
      await supabaseAdmin.from('staff_conversation_messages').insert({
        id: newMsg.id,
        conversation_id: convId,
        sender_type: 'player',
        sender_callsign: cleanCall,
        sender_name: String(fullName || cleanCall).trim(),
        message: cleanMsg,
        read_by_staff: false,
        read_by_player: true,
        created_at: nowIso,
      });
    } catch (sbErr) {
      console.warn('[server] Supabase player message insert notice:', sbErr);
    }
  }

  res.json({ success: true, message: newMsg });
});

// 12. Player: Mark messages as read
app.post('/api/communications/read', async (req, res) => {
  const { callSign } = req.body;
  if (!callSign) {
    res.json({ success: true });
    return;
  }

  const cleanCall = String(callSign).trim().toLowerCase();
  const store = loadCommunications();
  const conv = store.conversations.find((c) => c.playerCallSign.toLowerCase() === cleanCall);

  if (conv) {
    conv.unreadPlayerCount = 0;
    conv.messages.forEach((m) => {
      m.readByPlayer = true;
    });
    saveCommunications(store);
  }

  if (supabaseAdmin) {
    try {
      const { data: sbConv } = await supabaseAdmin
        .from('staff_conversations')
        .select('id')
        .ilike('player_callsign', cleanCall)
        .maybeSingle();

      if (sbConv) {
        await supabaseAdmin
          .from('staff_conversation_messages')
          .update({ read_by_player: true })
          .eq('conversation_id', sbConv.id)
          .eq('read_by_player', false);

        await supabaseAdmin
          .from('staff_conversations')
          .update({ unread_player_count: 0 })
          .eq('id', sbConv.id);
      }
    } catch {}
  }

  res.json({ success: true });
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
