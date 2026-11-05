/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * THE LAST SIGNAL (CASE TLS-0017) — AUTHORITATIVE COMMUNICATIONS SERVICE
 * 
 * Dedicated persistent staff-to-player communication engine:
 * 1. Global & targeted announcements (Broadcasts).
 * 2. Private direct staff-to-player conversations.
 * 3. Bidirectional messaging with unread status tracking.
 * 4. Full Supabase PostgreSQL persistence with server-side proxy fallback.
 */

export interface StaffAnnouncement {
  id: string;
  title: string;
  message: string;
  targetType: 'all' | 'stage' | 'team' | 'player';
  targetValue?: string;
  createdBy: string;
  createdAt: string;
  pinned?: boolean;
}

export interface ConversationMessage {
  id: string;
  conversationId: string;
  senderType: 'staff' | 'player';
  senderCallSign: string;
  senderName: string;
  message: string;
  readByStaff: boolean;
  readByPlayer: boolean;
  createdAt: string;
}

export interface StaffConversation {
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
  messages?: ConversationMessage[];
}

/**
 * Fetch announcements accessible to the current player.
 */
export async function fetchPlayerAnnouncements(params: {
  callSign?: string;
  stage?: number;
  teamName?: string | null;
}): Promise<StaffAnnouncement[]> {
  try {
    const q = new URLSearchParams();
    if (params.callSign) q.set('callSign', params.callSign);
    if (params.stage !== undefined) q.set('stage', String(params.stage));
    if (params.teamName) q.set('team', params.teamName);

    const res = await fetch(`/api/communications/announcements?${q.toString()}`);
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.announcements)) {
        return data.announcements;
      }
    }
  } catch (err) {
    console.warn('[commService] Failed fetching player announcements:', err);
  }
  return [];
}

/**
 * Fetch player's active direct conversation with staff.
 */
export async function fetchPlayerConversation(callSign: string): Promise<{
  conversation: StaffConversation | null;
  messages: ConversationMessage[];
}> {
  if (!callSign) return { conversation: null, messages: [] };
  try {
    const res = await fetch(`/api/communications/conversation?callSign=${encodeURIComponent(callSign.trim())}`);
    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        return {
          conversation: data.conversation || null,
          messages: Array.isArray(data.messages) ? data.messages : [],
        };
      }
    }
  } catch (err) {
    console.warn('[commService] Failed fetching player conversation:', err);
  }
  return { conversation: null, messages: [] };
}

/**
 * Send a message from a player to staff.
 */
export async function sendPlayerMessage(params: {
  callSign: string;
  fullName: string;
  studentClass?: string;
  message: string;
}): Promise<{ success: boolean; message?: ConversationMessage; error?: string }> {
  try {
    const res = await fetch('/api/communications/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    const data = await res.json();
    return data;
  } catch (err: any) {
    return { success: false, error: err?.message || 'Network error sending dispatch.' };
  }
}

/**
 * Mark player conversation messages as read.
 */
export async function markPlayerMessagesRead(callSign: string): Promise<void> {
  if (!callSign) return;
  try {
    await fetch('/api/communications/read', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callSign, role: 'player' }),
    });
  } catch {}
}

/* =========================================================================
   STAFF ENDPOINTS (Guarded by staffToken)
   ========================================================================= */

/**
 * Fetch all announcements (Staff Console).
 */
export async function fetchStaffAnnouncements(staffToken: string): Promise<StaffAnnouncement[]> {
  try {
    const res = await fetch('/api/staff/announcements', {
      headers: { Authorization: `Bearer ${staffToken}` },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.announcements)) {
        return data.announcements;
      }
    }
  } catch (err) {
    console.warn('[commService] Failed fetching staff announcements:', err);
  }
  return [];
}

/**
 * Post a new staff announcement.
 */
export async function createStaffAnnouncement(
  staffToken: string,
  payload: {
    title: string;
    message: string;
    targetType: 'all' | 'stage' | 'team' | 'player';
    targetValue?: string;
    pinned?: boolean;
  }
): Promise<{ success: boolean; announcement?: StaffAnnouncement; error?: string }> {
  try {
    const res = await fetch('/api/staff/announcements', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${staffToken}`,
      },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch (err: any) {
    return { success: false, error: err?.message || 'Network transmission error.' };
  }
}

/**
 * Delete a staff announcement.
 */
export async function deleteStaffAnnouncement(staffToken: string, id: string): Promise<boolean> {
  try {
    const res = await fetch(`/api/staff/announcements/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${staffToken}` },
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Fetch all player conversations for staff inbox.
 */
export async function fetchStaffConversations(staffToken: string): Promise<StaffConversation[]> {
  try {
    const res = await fetch('/api/staff/conversations', {
      headers: { Authorization: `Bearer ${staffToken}` },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.conversations)) {
        return data.conversations;
      }
    }
  } catch (err) {
    console.warn('[commService] Failed fetching staff conversations:', err);
  }
  return [];
}

/**
 * Fetch messages for a specific conversation (Staff).
 */
export async function fetchConversationMessages(staffToken: string, conversationId: string): Promise<ConversationMessage[]> {
  try {
    const res = await fetch(`/api/staff/conversations/${encodeURIComponent(conversationId)}/messages`, {
      headers: { Authorization: `Bearer ${staffToken}` },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.messages)) {
        return data.messages;
      }
    }
  } catch (err) {
    console.warn('[commService] Failed fetching conversation messages:', err);
  }
  return [];
}

/**
 * Start or open a conversation with a specific player (Staff).
 */
export async function startStaffConversation(
  staffToken: string,
  playerCallSign: string
): Promise<{ success: boolean; conversation?: StaffConversation; error?: string }> {
  try {
    const res = await fetch('/api/staff/conversations/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${staffToken}`,
      },
      body: JSON.stringify({ playerCallSign }),
    });
    return await res.json();
  } catch (err: any) {
    return { success: false, error: err?.message || 'Error opening conversation.' };
  }
}

/**
 * Send a reply from staff to a player conversation.
 */
export async function sendStaffMessage(
  staffToken: string,
  conversationId: string,
  message: string
): Promise<{ success: boolean; message?: ConversationMessage; error?: string }> {
  try {
    const res = await fetch(`/api/staff/conversations/${encodeURIComponent(conversationId)}/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${staffToken}`,
      },
      body: JSON.stringify({ message }),
    });
    return await res.json();
  } catch (err: any) {
    return { success: false, error: err?.message || 'Error transmitting message.' };
  }
}

/**
 * Update conversation status (open / resolved).
 */
export async function updateConversationStatus(
  staffToken: string,
  conversationId: string,
  status: 'open' | 'resolved'
): Promise<boolean> {
  try {
    const res = await fetch(`/api/staff/conversations/${encodeURIComponent(conversationId)}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${staffToken}`,
      },
      body: JSON.stringify({ status }),
    });
    return res.ok;
  } catch {
    return false;
  }
}
