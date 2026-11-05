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

        // Defensively ensure public.profiles record exists if DB trigger execution had an issue
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

        // Cache locally for fast UI hydration
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
        // Check if there is a cached callsign -> email mapping on this device
        let cachedEmail: string | null = null;
        try {
          cachedEmail = localStorage.getItem('tls_callsign_email_' + normalizedInput.toLowerCase());
        } catch {}

        if (cachedEmail) {
          const { data: cachedAuthData, error: cachedAuthError } = await supabase.auth.signInWithPassword({
            email: cachedEmail.toLowerCase(),
            password: passwordPlain,
          });
          if (!cachedAuthError && cachedAuthData?.user) {
            authUser = cachedAuthData.user;
          }
        }

        if (!authUser) {
          // Username-based login via secure server proxy that resolves username to auth identity
          let json: any = null;
          try {
            const res = await fetch('/api/auth/username-login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: normalizedInput,
                password: passwordPlain,
              }),
            });
            json = await res.json().catch(() => null);

            if (res.ok && json?.success && json?.session) {
              // Establish the real Supabase Auth session in the browser client
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
              error: json?.error || 'Invalid case credentials. Please check your call-sign and password.',
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
      if (data.user.email) {
        try {
          localStorage.setItem('tls_callsign_email_' + resolvedCallSign.toLowerCase(), data.user.email);
        } catch {}
      }

      // Verify individual stage-access override from Supabase participant_stage_overrides table
      const hasStageOverride = await verifyParticipantStageOverride();
      const userEmail = (data.user.email || '').toLowerCase().trim();
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
 */
async function syncUserDatabaseState(userId: string, _callSign: string, nextProg: UserProgress): Promise<UserProgress> {
  if (!isSupabaseConfigured || !supabase) return nextProg;
  try {
    // 1. Fetch active participant and team membership
    const { data: memberRows } = await supabase
      .from('participant_members')
      .select('participant_id, participants(id, kind, name, invite_code, retired)')
      .eq('user_id', userId)
      .is('left_at', null)
      .limit(1);

    const activeMember = memberRows?.[0];
    const participant = activeMember?.participants as any;
    const participantId = activeMember?.participant_id;

    if (participant && !participant.retired && participant.kind === 'team') {
      if (participant.name && nextProg.teamName !== participant.name) {
        nextProg.teamName = participant.name;
      }
      if (participant.invite_code && nextProg.teamCode !== participant.invite_code) {
        nextProg.teamCode = participant.invite_code;
      }
    }

    // 2. Fetch authoritative completions from stage_completions
    if (participantId) {
      const { data: completions } = await supabase
        .from('stage_completions')
        .select('stage_id, points_earned')
        .eq('participant_id', participantId);

      if (Array.isArray(completions) && completions.length > 0) {
        let maxStage = 0;
        let totalDbScore = 0;
        const stageScoresMap: Record<number, number> = { ...nextProg.stageScores };

        for (const c of completions) {
          const sId = Number(c.stage_id);
          const pts = Number(c.points_earned) || 100;
          if (sId > maxStage) maxStage = sId;
          totalDbScore += pts;
          stageScoresMap[sId] = Math.max(stageScoresMap[sId] || 0, pts);
        }

        if (maxStage > nextProg.stagesCompleted) {
          nextProg.stagesCompleted = maxStage;
          nextProg.activeStage = Math.max(nextProg.activeStage, Math.min(7, maxStage + 1));
        }
        if (maxStage >= 2) {
          nextProg.stage2DeductionSolved = true;
          if (!nextProg.unlockedEvidenceIds.includes('CAS-017')) {
            nextProg.unlockedEvidenceIds.push('CAS-017');
          }
          if (!nextProg.unlockedEvidenceIds.includes('EV-0301')) {
            nextProg.unlockedEvidenceIds.push('EV-0301');
          }
          if (!nextProg.solvedChallengeKeys.includes('stage2_coords')) {
            nextProg.solvedChallengeKeys.push('stage2_coords');
          }
        }
        if (totalDbScore > nextProg.score) {
          nextProg.score = totalDbScore;
        }
        nextProg.stageScores = stageScoresMap;
      }
    }
  } catch (err) {
    console.warn('[authService] Error syncing database progress/team state:', err);
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

        if (data.session.user.email && callSign) {
          try {
            localStorage.setItem('tls_callsign_email_' + callSign.toLowerCase(), data.session.user.email);
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
