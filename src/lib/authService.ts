/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * THE LAST SIGNAL — UNIFIED AUTHENTICATION SERVICE
 * 
 * Bridges between Supabase Auth (when credentials exist in .env)
 * and the local prototype authentication engine (when in offline/local testing mode).
 * 
 * Guarantees:
 * 1. Zero plaintext password storage in database or browser storage.
 * 2. Admission numbers are cryptographically hashed and masked for student privacy.
 * 3. Consistent session restoration and token refresh.
 * 4. Automatic fallback with diagnostic reporting.
 */

import { supabase, isSupabaseConfigured } from './supabase';
import {
  registerPrototypeUser,
  loginPrototypeUser,
  getActiveUser as getLocalActiveUser,
  clearActiveSession as clearLocalActiveSession,
  setActiveSession as setLocalActiveSession,
  isCallSignTaken as isLocalCallSignTaken,
  cacheUserLocally,
  getAllUsers,
  hashString,
  maskAdmissionNumber,
  type PrototypeUser,
  type UserProgress,
  getUserProgress,
  createInitialProgress,
  saveUserProgress,
} from './prototypeAuth';
import { isRegistrationOpen, REGISTRATION_OPEN_IST } from './stageConfig';

export interface AuthResult {
  success: boolean;
  error?: string;
  user?: PrototypeUser;
  mode: 'live_supabase' | 'prototype_local';
}

export interface RegisterParams {
  fullName: string;
  email: string;
  studentClass: string;
  admissionNumber: string;
  callSign: string;
  passwordPlain: string;
  school?: string;
}

const EMAIL_DOMAIN = '@case17.internal';

/**
 * Format a student call-sign into an internal legacy auth email format.
 */
function callSignToInternalEmail(callSign: string): string {
  const clean = callSign.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
  return `${clean}${EMAIL_DOMAIN}`;
}

/**
 * Check if a call-sign is already registered.
 */
export async function isCallSignAvailable(callSign: string): Promise<boolean> {
  const clean = callSign.trim();
  if (clean.length < 3) return false;

  if (isSupabaseConfigured && supabase) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('username')
        .ilike('username', clean)
        .maybeSingle();

      if (error) {
        return !isLocalCallSignTaken(clean);
      }
      return !data;
    } catch {
      return !isLocalCallSignTaken(clean);
    }
  }

  return !isLocalCallSignTaken(clean);
}

/**
 * Register a new student investigator.
 */
export async function registerUser(params: RegisterParams): Promise<AuthResult> {
  // Enforce registration window timing
  if (!isRegistrationOpen()) {
    return {
      success: false,
      error: `Registration is not open yet. Student intake begins on ${REGISTRATION_OPEN_IST}.`,
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  const { fullName, email, studentClass, admissionNumber, callSign, passwordPlain, school } = params;

  if (
    !fullName.trim() ||
    !email.trim() ||
    !studentClass.trim() ||
    !admissionNumber.trim() ||
    !callSign.trim() ||
    !passwordPlain
  ) {
    return {
      success: false,
      error: 'All fields including student email are strictly required.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  const cleanEmail = email.trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(cleanEmail)) {
    return {
      success: false,
      error: 'Please enter a valid student email address (e.g. operative@school.edu).',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  const cleanCallSign = callSign.trim();
  if (cleanCallSign.length < 3 || cleanCallSign.length > 24) {
    return {
      success: false,
      error: 'Call-sign must be between 3 and 24 characters.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  if (!/^[A-Za-z0-9_]+$/.test(cleanCallSign)) {
    return {
      success: false,
      error: 'Call-sign can only contain letters, numbers, and underscores.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  const reserved = ['admin', 'administrator', 'director', 'zodiac', 'cipher', 'system', 'moderator', 'staff', 'owner'];
  if (reserved.includes(cleanCallSign.toLowerCase())) {
    return {
      success: false,
      error: 'This call-sign is reserved by the investigation authority.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  if (passwordPlain.length < 6) {
    return {
      success: false,
      error: 'Password must be at least 6 characters long.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  // Pre-calculate cryptographic hashes for privacy
  const [admissionHash, passwordHash] = await Promise.all([
    hashString(admissionNumber),
    hashString(passwordPlain),
  ]);
  const maskedAdmission = maskAdmissionNumber(admissionNumber);

  // If Supabase is live, register via Supabase Auth
  if (isSupabaseConfigured && supabase) {
    try {
      const { data, error } = await supabase.auth.signUp({
        email: cleanEmail,
        password: passwordPlain,
        options: {
          data: {
            username: cleanCallSign,
            callSign: cleanCallSign,
            fullName: fullName.trim(),
            full_name: fullName.trim(),
            school: school?.trim() || 'School Division',
            school_name: school?.trim() || 'School Division',
            studentClass,
            student_class: studentClass,
            admissionHash,
            admission_hash: admissionHash,
            admissionNumberMasked: maskedAdmission,
            admission_masked: maskedAdmission,
            email: cleanEmail,
          },
        },
      });

      if (error) {
        let userMessage = error.message;
        const msgLower = (error.message || '').toLowerCase();
        const status = (error as { status?: number }).status;

        if (
          msgLower.includes('already registered') ||
          msgLower.includes('user already exists') ||
          status === 422
        ) {
          userMessage = 'This email address is already registered. Please log in with your credentials or use a different email.';
        } else if (
          msgLower.includes('rate limit') ||
          status === 429
        ) {
          userMessage = 'Email rate limit exceeded (HTTP 429). Please wait a few moments before trying again.';
        } else if (
          msgLower.includes('database error saving new user') ||
          msgLower.includes('profiles_username_ci') ||
          msgLower.includes('unique constraint')
        ) {
          userMessage = `Registration conflict: Call-sign "${cleanCallSign}" or this admission number is already enrolled in Case 17. Please check your credentials or choose a different call-sign.`;
        } else if (
          msgLower.includes('invalid format') ||
          msgLower.includes('validate email') ||
          status === 400
        ) {
          userMessage = 'The provided email address format is invalid. Please check your email and try again.';
        }

        return {
          success: false,
          error: userMessage,
          mode: 'live_supabase',
        };
      }

      if (data.user) {
        // Cache callsign -> email mapping for fast username login on this device
        try {
          localStorage.setItem('tls_callsign_email_' + cleanCallSign.toLowerCase(), cleanEmail);
        } catch {}

        const isDevOrExcluded =
          cleanEmail === 'rudrapratapj.0562@gmail.com' ||
          cleanEmail === 'rudrapratapf.0562@gmail.com';

        // Defensively ensure public.profiles record exists with email if supported
        try {
          await supabase.from('profiles').upsert(
            {
              id: data.user.id,
              username: cleanCallSign,
              email: cleanEmail,
              full_name: fullName.trim(),
              student_class: studentClass,
              admission_hash: admissionHash,
              admission_masked: maskedAdmission,
              exclude_from_leaderboard: isDevOrExcluded,
            },
            { onConflict: 'id' }
          );
        } catch {
          try {
            await supabase.from('profiles').upsert(
              {
                id: data.user.id,
                username: cleanCallSign,
                full_name: fullName.trim(),
                student_class: studentClass,
                admission_hash: admissionHash,
                admission_masked: maskedAdmission,
                exclude_from_leaderboard: isDevOrExcluded,
              },
              { onConflict: 'id' }
            );
          } catch (profileErr) {
            console.warn('[authService] Defensive profile check notice:', profileErr);
          }
        }

        const userObj: PrototypeUser = {
          id: data.user.id,
          fullName: fullName.trim(),
          email: cleanEmail,
          school: school?.trim() || 'School Division',
          studentClass,
          admissionNumberMasked: maskedAdmission,
          admissionHash,
          callSign: cleanCallSign,
          passwordHash,
          excludeFromLeaderboard: isDevOrExcluded,
          registeredAt: data.user.created_at || new Date().toISOString(),
        };

        // Cache locally for fast UI hydration and instant username login
        cacheUserLocally(userObj);
        setLocalActiveSession(userObj);
        const initProg = createInitialProgress(cleanCallSign);
        if (isDevOrExcluded) {
          initProg.excludeFromLeaderboard = true;
        }
        saveUserProgress(initProg);

        return {
          success: true,
          user: userObj,
          mode: 'live_supabase',
        };
      }
    } catch (err: unknown) {
      console.error('[authService] Supabase registration failure:', err);
      return {
        success: false,
        error: err instanceof Error ? err.message : 'Registration failed on secure server.',
        mode: 'live_supabase',
      };
    }
  }

  // Fallback / Prototype mode
  const localResult = await registerPrototypeUser({
    fullName,
    email: cleanEmail,
    school,
    studentClass,
    admissionNumber,
    callSign: cleanCallSign,
    passwordPlain,
  });

  if (
    localResult.user &&
    (cleanEmail === 'rudrapratapj.0562@gmail.com' || cleanEmail === 'rudrapratapf.0562@gmail.com')
  ) {
    localResult.user.excludeFromLeaderboard = true;
  }

  return {
    ...localResult,
    mode: 'prototype_local',
  };
}

/**
 * Authenticate an existing student investigator.
 * Supports login via Call-Sign / Username OR registered Email.
 */
export async function loginUser(
  callSignOrEmail: string,
  passwordPlain: string
): Promise<AuthResult> {
  const cleanInput = callSignOrEmail.trim();
  if (!cleanInput || !passwordPlain) {
    return {
      success: false,
      error: 'Please enter both your call-sign/email and password.',
      mode: isSupabaseConfigured ? 'live_supabase' : 'prototype_local',
    };
  }

  if (isSupabaseConfigured && supabase) {
    try {
      let authUser: any = null;
      // Strip leading @ if entered by operative (e.g. "@Cipher_echo" -> "Cipher_echo")
      const normalizedInput = cleanInput.replace(/^@+/, '').trim();
      const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanInput);

      if (isEmail) {
        // Direct email login
        const { data, error } = await supabase.auth.signInWithPassword({
          email: cleanInput.toLowerCase(),
          password: passwordPlain,
        });
        if (error || !data?.user) {
          // Check local prototype fallback if live email sign in failed
          const localCheck = await loginPrototypeUser(cleanInput, passwordPlain);
          if (localCheck.success && localCheck.user) {
            return {
              ...localCheck,
              mode: 'prototype_local',
            };
          }
          return {
            success: false,
            error: error?.message || 'Invalid case credentials. Please check your email and password.',
            mode: 'live_supabase',
          };
        }
        authUser = data.user;
      } else {
        // Multi-tier username-to-email resolution in client
        let candidateEmail: string | null = null;

        // Tier 1: Check device local mapping
        try {
          candidateEmail = localStorage.getItem('tls_callsign_email_' + normalizedInput.toLowerCase());
        } catch {}

        // Tier 2: Scan prototype user store
        if (!candidateEmail) {
          try {
            const allProto = getAllUsers();
            const protoMatch = allProto.find(
              (u) => u.callSign.trim().replace(/^@+/, '').toLowerCase() === normalizedInput.toLowerCase()
            );
            if (protoMatch?.email && protoMatch.email.includes('@')) {
              candidateEmail = protoMatch.email.toLowerCase().trim();
            }
          } catch {}
        }

        // Tier 3: Query Supabase RPC lookup function if deployed
        if (!candidateEmail) {
          try {
            const { data: rpcEmail, error: rpcErr } = await supabase.rpc('lookup_auth_email_by_username', {
              p_username: normalizedInput,
            });
            if (!rpcErr && rpcEmail && typeof rpcEmail === 'string' && rpcEmail.includes('@')) {
              candidateEmail = rpcEmail.toLowerCase().trim();
            }
          } catch {}
        }

        // Tier 4: Query public.profiles directly by username
        if (!candidateEmail) {
          try {
            const { data: profRow } = await supabase
              .from('profiles')
              .select('email')
              .ilike('username', normalizedInput)
              .maybeSingle();
            if (profRow?.email && typeof profRow.email === 'string' && profRow.email.includes('@')) {
              candidateEmail = profRow.email.toLowerCase().trim();
            }
          } catch {}
        }

        // If candidateEmail was identified, attempt direct Supabase authentication
        if (candidateEmail) {
          const { data: directAuth, error: directErr } = await supabase.auth.signInWithPassword({
            email: candidateEmail,
            password: passwordPlain,
          });
          if (!directErr && directAuth?.user) {
            authUser = directAuth.user;
            try {
              localStorage.setItem('tls_callsign_email_' + normalizedInput.toLowerCase(), candidateEmail);
            } catch {}
          }
        }

        // Tier 5: Try internal legacy auth email format (@case17.internal)
        if (!authUser) {
          const internalEmail = callSignToInternalEmail(normalizedInput);
          try {
            const { data: internalAuth, error: internalErr } = await supabase.auth.signInWithPassword({
              email: internalEmail,
              password: passwordPlain,
            });
            if (!internalErr && internalAuth?.user) {
              authUser = internalAuth.user;
            }
          } catch {}
        }

        // Tier 6: Use secure server proxy with client credentials passed for resilience
        if (!authUser) {
          let json: any = null;
          try {
            const clientUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_URL) || undefined;
            const clientAnon = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_ANON_KEY) || undefined;

            const res = await fetch('/api/auth/username-login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: normalizedInput,
                password: passwordPlain,
                supabaseUrl: clientUrl,
                supabaseAnonKey: clientAnon,
              }),
            });
            json = await res.json().catch(() => null);

            if (res.ok && json?.success && json?.session) {
              const { error: sessionError } = await supabase.auth.setSession({
                access_token: json.session.access_token,
                refresh_token: json.session.refresh_token,
              });

              if (sessionError) {
                console.warn('[authService] Failed setting Supabase session from username login:', sessionError);
              }

              authUser = json.user;
            }
          } catch (netErr) {
            console.warn('[authService] Username-login proxy network error:', netErr);
          }

          if (!authUser) {
            // Check local prototype fallback if server username lookup failed
            const localCheck = await loginPrototypeUser(normalizedInput, passwordPlain);
            if (localCheck.success && localCheck.user) {
              return {
                ...localCheck,
                mode: 'prototype_local',
              };
            }

            return {
              success: false,
              error: json?.error || 'Invalid case credentials. Please check your username/call-sign and password.',
              mode: 'live_supabase',
            };
          }
        }
      }

      if (!authUser) {
        return {
          success: false,
          error: 'Authentication failed. Please verify your credentials and network connection.',
          mode: 'live_supabase',
        };
      }

      const data = { user: authUser };

      // Fetch profile
      const { data: profile } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', data.user.id)
        .maybeSingle();

      // Check staff authorization table
      const { data: staffData } = await supabase
        .from('staff')
        .select('role')
        .eq('user_id', data.user.id)
        .maybeSingle();

      const isStaff = Boolean(staffData?.role);
      const staffRole = (staffData?.role as 'owner' | 'organiser') || undefined;

      const resolvedCallSign =
        profile?.username ||
        (data.user.user_metadata?.username as string) ||
        (data.user.user_metadata?.callSign as string) ||
        cleanInput;

      // Remember call-sign -> email association for future logins on this machine
      const userEmail = (data.user.email || '').toLowerCase().trim();
      if (userEmail) {
        try {
          localStorage.setItem('tls_callsign_email_' + resolvedCallSign.toLowerCase(), userEmail);
          localStorage.setItem('tls_callsign_email_' + normalizedInput.toLowerCase(), userEmail);
          if (data.user.user_metadata?.username) {
            localStorage.setItem('tls_callsign_email_' + String(data.user.user_metadata.username).toLowerCase(), userEmail);
          }
          if (data.user.user_metadata?.callSign) {
            localStorage.setItem('tls_callsign_email_' + String(data.user.user_metadata.callSign).toLowerCase(), userEmail);
          }
        } catch {}

        // Defensively update profiles.email in Supabase if supported and missing
        if (profile && (!profile.email || !profile.email.includes('@'))) {
          Promise.resolve(supabase.from('profiles').update({ email: userEmail }).eq('id', data.user.id)).catch(() => {});
        }
      }

      // Verify individual stage-access override from Supabase participant_stage_overrides table
      const hasStageOverride = await verifyParticipantStageOverride();
      const isDeveloperAccount = userEmail === 'rudrapratapf.0562@gmail.com';
      const excludeFromLeaderboard =
        Boolean(isStaff) ||
        Boolean(hasStageOverride) ||
        isDeveloperAccount ||
        (await verifyParticipantLeaderboardExclusion(data.user.id)) ||
        Boolean((profile as { exclude_from_leaderboard?: boolean })?.exclude_from_leaderboard);

      const passwordHash = await hashString(passwordPlain);
      const userObj: PrototypeUser = {
        id: data.user.id,
        fullName: profile?.full_name || (data.user.user_metadata?.full_name as string) || resolvedCallSign,
        email: data.user.email,
        school: (data.user.user_metadata?.school as string) || 'School Division',
        studentClass: profile?.student_class || (data.user.user_metadata?.student_class as string) || 'Class 9',
        admissionNumberMasked: profile?.admission_masked || (data.user.user_metadata?.admission_masked as string) || 'ADM-••••0000',
        admissionHash: profile?.admission_hash || '',
        callSign: resolvedCallSign,
        passwordHash,
        registeredAt: data.user.created_at || new Date().toISOString(),
        role: staffRole,
        isStaff,
        hasStageOverride,
        excludeFromLeaderboard,
      };

      // Cache locally for instant username recognition and offline support
      cacheUserLocally(userObj);
      setLocalActiveSession(userObj);

      // Synchronize verified override, team membership, and completions from Supabase
      try {
        const currentProg = getUserProgress(resolvedCallSign);
        let nextProg = { ...currentProg };
        if (nextProg.hasStageOverride !== hasStageOverride) {
          nextProg.hasStageOverride = hasStageOverride;
        }
        if (nextProg.excludeFromLeaderboard !== excludeFromLeaderboard) {
          nextProg.excludeFromLeaderboard = excludeFromLeaderboard;
        }
        nextProg = await syncUserDatabaseState(data.user.id, resolvedCallSign, nextProg);
        saveUserProgress(nextProg);
      } catch {}

      return {
        success: true,
        user: userObj,
        mode: 'live_supabase',
      };
    } catch (err: unknown) {
      console.error('[authService] Supabase login error:', err);
      return {
        success: false,
        error: 'Authentication failed. Please verify your credentials and network connection.',
        mode: 'live_supabase',
      };
    }
  }

  // Fallback / Prototype mode
  const localResult = await loginPrototypeUser(cleanInput, passwordPlain);
  return {
    ...localResult,
    mode: 'prototype_local',
  };
}

/**
 * Verify whether the currently authenticated participant has an active stage override in Supabase.
 * Uses public.participant_stage_overrides as the authoritative source of truth.
 * Fails closed (returns false) if Supabase is unreachable, unconfigured, or verification fails.
 */
export async function verifyParticipantStageOverride(): Promise<boolean> {
  if (!isSupabaseConfigured || !supabase) {
    return false;
  }

  try {
    // 1. Primary check: Call database RPC function if available
    const { data: rpcData, error: rpcError } = await supabase.rpc('has_stage_override');
    if (!rpcError && typeof rpcData === 'boolean') {
      return rpcData;
    }

    // 2. Direct table query: RLS automatically scopes select to (participant_id = my_participant() OR is_staff())
    const { data, error } = await supabase
      .from('participant_stage_overrides')
      .select('enabled')
      .eq('enabled', true)
      .limit(1);

    if (!error && Array.isArray(data) && data.length > 0) {
      return data[0].enabled === true;
    }

    // 3. Fallback: Inspect get_my_state() hydration payload
    const { data: stateData, error: stateError } = await supabase.rpc('get_my_state');
    if (!stateError && stateData && typeof stateData === 'object' && 'has_stage_override' in stateData) {
      return Boolean((stateData as { has_stage_override: boolean }).has_stage_override);
    }

    return false;
  } catch (err) {
    console.warn('[authService] Failed to verify participant stage override (failing closed):', err);
    return false;
  }
}

/**
 * Check whether the active user or participant has been flagged to be excluded from public leaderboards.
 */
export async function verifyParticipantLeaderboardExclusion(userId?: string): Promise<boolean> {
  if (!isSupabaseConfigured || !supabase) {
    return false;
  }
  try {
    const targetUserId = userId || (await supabase.auth.getUser()).data.user?.id;
    if (!targetUserId) return false;

    // 1. Direct profile check
    const { data: prof } = await supabase
      .from('profiles')
      .select('exclude_from_leaderboard')
      .eq('id', targetUserId)
      .maybeSingle();

    if (prof && typeof (prof as { exclude_from_leaderboard?: boolean }).exclude_from_leaderboard === 'boolean') {
      if ((prof as { exclude_from_leaderboard?: boolean }).exclude_from_leaderboard) return true;
    }

    // 2. Participant check
    const { data: memberData } = await supabase
      .from('participant_members')
      .select('participant_id, participants(exclude_from_leaderboard)')
      .eq('user_id', targetUserId)
      .is('left_at', null)
      .limit(1)
      .maybeSingle();

    if (memberData?.participants && typeof (memberData.participants as any).exclude_from_leaderboard === 'boolean') {
      return (memberData.participants as any).exclude_from_leaderboard === true;
    }

    return false;
  } catch (err) {
    console.warn('[authService] Failed to check leaderboard exclusion:', err);
    return false;
  }
}

/**
 * Synchronize authoritative completions and team membership from Supabase into local progress.
 * Non-destructive:
 * 1. Resolves ALL participant records for this user (active team, retired team, active solo, retired solo).
 * 2. Bridges via application server (/api/progress/state) if client queries face RLS lockouts.
 * 3. Never treats query errors or empty responses as proof that an existing player has no progress.
 * 4. Reconciles scores stage-by-stage against authoritative completions to prevent duplicate awards.
 */
async function syncUserDatabaseState(userId: string, callSign: string, nextProg: UserProgress): Promise<UserProgress> {
  const cleanCall = callSign.trim();
  const allParticipantIds = new Set<string>();
  let activeTeamName: string | null = null;
  let activeTeamCode: string | null = null;
  let hadQueryError = false;

  // 1. Client-side Supabase resolution (if configured)
  if (isSupabaseConfigured && supabase) {
    // 1a. Query participant_members (team memberships)
    try {
      const { data: memberRows, error: memberErr } = await supabase
        .from('participant_members')
        .select('participant_id, left_at, participants(id, kind, name, invite_code, retired)')
        .eq('user_id', userId);

      if (memberErr) {
        console.warn('[authService] participant_members lookup notice (RLS may apply):', memberErr.message);
        hadQueryError = true;
      } else if (Array.isArray(memberRows)) {
        for (const m of memberRows) {
          if (m.participant_id) {
            allParticipantIds.add(m.participant_id);
            const p = m.participants as any;
            if (!m.left_at && p && !p.retired && p.kind === 'team') {
              activeTeamName = p.name || activeTeamName;
              activeTeamCode = p.invite_code || activeTeamCode;
            }
          }
        }
      }
    } catch (err) {
      console.warn('[authService] Exception checking participant_members:', err);
      hadQueryError = true;
    }

    // 1b. Query participants table directly for solo participant IDs (active and retired)
    try {
      const { data: soloRows, error: soloErr } = await supabase
        .from('participants')
        .select('id, kind, name, invite_code, retired')
        .eq('solo_user_id', userId);

      if (soloErr) {
        console.warn('[authService] participants solo lookup notice:', soloErr.message);
      } else if (Array.isArray(soloRows)) {
        for (const s of soloRows) {
          if (s.id) {
            allParticipantIds.add(s.id);
          }
        }
      }
    } catch (err) {
      console.warn('[authService] Exception checking solo participants:', err);
    }

    // 1c. Try my_participant() RPC if available
    try {
      const { data: rpcPid, error: rpcErr } = await supabase.rpc('my_participant');
      if (!rpcErr && rpcPid && typeof rpcPid === 'string') {
        allParticipantIds.add(rpcPid);
      }
    } catch {}
  }

  // 2. Authoritative Application Server Bridge (/api/progress/state)
  // Bypasses browser RLS policies using verified Bearer session token (no client-supplied IDs trusted)
  let serverCompletions: any[] = [];
  try {
    let accessToken: string | null = null;
    if (isSupabaseConfigured && supabase) {
      const { data: sessData } = await supabase.auth.getSession();
      accessToken = sessData?.session?.access_token || null;
    }

    if (accessToken) {
      const res = await fetch('/api/progress/state', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (res.ok) {
        const json = await res.json();
        if (json.success && json.data) {
          if (Array.isArray(json.data.participantIds)) {
            json.data.participantIds.forEach((pid: string) => pid && allParticipantIds.add(pid));
          }
          if (json.data.teamName && !activeTeamName) {
            activeTeamName = json.data.teamName;
            activeTeamCode = json.data.teamCode;
          }
          if (Array.isArray(json.data.completions)) {
            serverCompletions = json.data.completions;
          }
        }
      } else {
        console.warn(`[authService] /api/progress/state returned HTTP ${res.status}`);
        hadQueryError = true;
      }
    }
  } catch (netErr) {
    console.warn('[authService] Server progress state fallback notice:', netErr);
    hadQueryError = true;
  }

  // Update active team information if confirmed
  if (activeTeamName && nextProg.teamName !== activeTeamName) {
    nextProg.teamName = activeTeamName;
  }
  if (activeTeamCode && nextProg.teamCode !== activeTeamCode) {
    nextProg.teamCode = activeTeamCode;
  }

  // 3. Query authoritative completions from stage_completions
  const pids = Array.from(allParticipantIds);
  let dbCompletions: any[] = [...serverCompletions];

  if (isSupabaseConfigured && supabase && pids.length > 0) {
    try {
      const { data: completions, error: compErr } = await supabase
        .from('stage_completions')
        .select('stage_id, points_earned, completed_at, participant_id')
        .in('participant_id', pids);

      if (compErr) {
        console.warn('[authService] stage_completions query error (RLS may apply):', compErr.message);
        hadQueryError = true;
      } else if (Array.isArray(completions) && completions.length > 0) {
        for (const c of completions) {
          const already = dbCompletions.some(
            (existing) => Number(existing.stage_id) === Number(c.stage_id) && existing.participant_id === c.participant_id
          );
          if (!already) {
            dbCompletions.push(c);
          }
        }
      }
    } catch (err) {
      console.warn('[authService] Error querying stage_completions:', err);
      hadQueryError = true;
    }
  }

  // 4. Safe non-destructive reconciliation
  // A query failure or empty response must never downgrade an existing investigator's progress!
  if (dbCompletions.length > 0) {
    // Reconcile stage scores per stage without duplicate awards
    const stageScoresMap: Record<number, number> = { ...(nextProg.stageScores || {}) };
    const stageTimestamps: Record<number, string> = { ...(nextProg.stageSolveTimestamps || {}) };

    for (const c of dbCompletions) {
      const sId = Number(c.stage_id);
      const pts = Number(c.points_earned) || 100;
      // For each unique stage, take the highest awarded score (avoid duplicate addition)
      stageScoresMap[sId] = Math.max(stageScoresMap[sId] || 0, pts);
      if (c.completed_at && !stageTimestamps[sId]) {
        stageTimestamps[sId] = c.completed_at;
      }
    }

    const completedStageIds = Object.keys(stageScoresMap).map(Number);
    const maxCompletedStage = Math.max(nextProg.stagesCompleted || 0, ...completedStageIds);
    // Score is the sum of unique stage scores
    const totalAuthoritativeScore = Object.values(stageScoresMap).reduce((sum, pts) => sum + (Number(pts) || 0), 0);

    nextProg.stagesCompleted = maxCompletedStage;
    nextProg.activeStage = Math.max(nextProg.activeStage || 1, Math.min(7, maxCompletedStage + 1));
    nextProg.score = Math.max(nextProg.score || 0, totalAuthoritativeScore);
    nextProg.stageScores = stageScoresMap;
    nextProg.stageSolveTimestamps = stageTimestamps;

    // Unpack canonical unlocks based on completed stages
    if (maxCompletedStage >= 1) {
      const stage1Evidence = ['EV-0102', 'EV-0103', 'EV-0201', 'EV-0202', 'EV-0203', 'EV-0204'];
      for (const ev of stage1Evidence) {
        if (!nextProg.unlockedEvidenceIds.includes(ev)) nextProg.unlockedEvidenceIds.push(ev);
      }
      if (!nextProg.solvedChallengeKeys.includes('gate_zk_login')) {
        nextProg.solvedChallengeKeys.push('gate_zk_login');
      }
    }

    if (maxCompletedStage >= 2) {
      nextProg.stage2DeductionSolved = true;
      if (!nextProg.unlockedEvidenceIds.includes('CAS-017')) nextProg.unlockedEvidenceIds.push('CAS-017');
      if (!nextProg.unlockedEvidenceIds.includes('EV-0301')) nextProg.unlockedEvidenceIds.push('EV-0301');
      if (!nextProg.solvedChallengeKeys.includes('stage2_coords')) {
        nextProg.solvedChallengeKeys.push('stage2_coords');
      }
    }

    if (maxCompletedStage >= 3) {
      nextProg.mapGateUnlocked = true;
      if (!nextProg.unlockedEvidenceIds.includes('MAP-001')) nextProg.unlockedEvidenceIds.push('MAP-001');
      if (!nextProg.unlockedEvidenceIds.includes('EV-0302')) nextProg.unlockedEvidenceIds.push('EV-0302');
      if (!nextProg.solvedChallengeKeys.includes('gate_map')) {
        nextProg.solvedChallengeKeys.push('gate_map');
      }
    }

    if (maxCompletedStage >= 4) {
      nextProg.targetChoiceLocked = true;
    }

    if (maxCompletedStage >= 5) {
      nextProg.suspectDbUnlocked = true;
      const s5Evidence = ['SUSP-001', 'SUSP-002', 'SUSP-003', 'SUSP-004'];
      for (const ev of s5Evidence) {
        if (!nextProg.unlockedEvidenceIds.includes(ev)) nextProg.unlockedEvidenceIds.push(ev);
      }
      if (!nextProg.solvedChallengeKeys.includes('gate_suspect_db')) {
        nextProg.solvedChallengeKeys.push('gate_suspect_db');
      }
    }

    if (maxCompletedStage >= 6) {
      nextProg.systemFreezeTriggered = true;
      if (!nextProg.unlockedEvidenceIds.includes('AUD-001')) nextProg.unlockedEvidenceIds.push('AUD-001');
      if (!nextProg.unlockedEvidenceIds.includes('EV-0601')) nextProg.unlockedEvidenceIds.push('EV-0601');
      if (!nextProg.solvedChallengeKeys.includes('gate_audio')) {
        nextProg.solvedChallengeKeys.push('gate_audio');
      }
    }

    if (maxCompletedStage >= 7) {
      nextProg.stage7Step = 'completed';
      nextProg.status = 'COMPLETED';
    } else if (maxCompletedStage > 0) {
      nextProg.status = 'IN PROGRESS';
    }
  } else if (hadQueryError) {
    console.warn(`[authService] Queries encountered errors during progress sync for @${cleanCall}. Preserving existing local state.`);
  }

  return nextProg;
}

/**
 * Restore current session on page refresh.
 */
export async function restoreSession(): Promise<PrototypeUser | null> {
  if (isSupabaseConfigured && supabase) {
    try {
      const { data } = await supabase.auth.getSession();
      if (data.session?.user) {
        const { data: profile } = await supabase
          .from('profiles')
          .select('*')
          .eq('id', data.session.user.id)
          .maybeSingle();

        const { data: staffData } = await supabase
          .from('staff')
          .select('role')
          .eq('user_id', data.session.user.id)
          .maybeSingle();

        const isStaff = Boolean(staffData?.role);
        const staffRole = (staffData?.role as 'owner' | 'organiser') || undefined;

        const callSign = profile?.username || (data.session.user.user_metadata?.username as string) || 'Operative';

        const userEmail = (data.session.user.email || '').toLowerCase().trim();
        if (userEmail) {
          try {
            if (callSign) localStorage.setItem('tls_callsign_email_' + callSign.toLowerCase(), userEmail);
            if (data.session.user.user_metadata?.username) {
              localStorage.setItem('tls_callsign_email_' + String(data.session.user.user_metadata.username).toLowerCase(), userEmail);
            }
            if (data.session.user.user_metadata?.callSign) {
              localStorage.setItem('tls_callsign_email_' + String(data.session.user.user_metadata.callSign).toLowerCase(), userEmail);
            }
          } catch {}
        }

        // Verify individual stage-access override from Supabase participant_stage_overrides
        const hasStageOverride = await verifyParticipantStageOverride();
        const sessionUserEmail = (data.session.user.email || '').toLowerCase().trim();
        const isDeveloperAccount = sessionUserEmail === 'rudrapratapf.0562@gmail.com';
        const excludeFromLeaderboard =
          Boolean(isStaff) ||
          Boolean(hasStageOverride) ||
          isDeveloperAccount ||
          (await verifyParticipantLeaderboardExclusion(data.session.user.id)) ||
          Boolean((profile as { exclude_from_leaderboard?: boolean })?.exclude_from_leaderboard);

        const userObj: PrototypeUser = {
          id: data.session.user.id,
          fullName: profile?.full_name || (data.session.user.user_metadata?.full_name as string) || callSign,
          email: data.session.user.email,
          school: (data.session.user.user_metadata?.school as string) || 'School Division',
          studentClass: profile?.student_class || (data.session.user.user_metadata?.student_class as string) || 'Class 9',
          admissionNumberMasked: profile?.admission_masked || (data.session.user.user_metadata?.admission_masked as string) || 'ADM-••••0000',
          admissionHash: profile?.admission_hash || '',
          callSign,
          passwordHash: '',
          registeredAt: data.session.user.created_at || new Date().toISOString(),
          role: staffRole,
          isStaff,
          hasStageOverride,
          excludeFromLeaderboard,
        };

        cacheUserLocally(userObj);
        setLocalActiveSession(userObj);

        // Synchronize verified override, team membership, and completions from Supabase
        try {
          const currentProg = getUserProgress(callSign);
          let nextProg = { ...currentProg };
          if (nextProg.hasStageOverride !== hasStageOverride) {
            nextProg.hasStageOverride = hasStageOverride;
          }
          if (nextProg.excludeFromLeaderboard !== excludeFromLeaderboard) {
            nextProg.excludeFromLeaderboard = excludeFromLeaderboard;
          }
          nextProg = await syncUserDatabaseState(data.session.user.id, callSign, nextProg);
          saveUserProgress(nextProg);
        } catch {}

        return userObj;
      }
    } catch (err) {
      console.warn('[authService] Session restoration check failed:', err);
    }
  }

  return getLocalActiveUser();
}

/**
 * Log out the active session.
 */
export async function logoutUser(): Promise<void> {
  if (isSupabaseConfigured && supabase) {
    try {
      await supabase.auth.signOut();
    } catch (err) {
      console.warn('[authService] Supabase sign out error:', err);
    }
  }
  clearLocalActiveSession();
}
