# THE LAST SIGNAL (TLS-0017) — PRE-LAUNCH CLEAN PURGE PROCEDURE
**Target Database:** Supabase (`xwlbjgbtbppvabmrvenp`)  
**Status:** DRAFT / AUDIT ONLY — **DO NOT EXECUTE AUTOMATICALLY**

---

## 1. PURPOSE & PRINCIPLES
Before official public kickoff, all prototype testing traces, demo stage solves, temporary test tickets, and test team groupings must be purged so all students start at Stage 1 with 0 points.
However, game infrastructure, official challenge definitions, static narrative evidence, staff accounts, and application settings must remain completely intact.

---

## 2. DATA TABLE INVENTORY

### A. Tables to PURGE (Dynamic Player State & Test Data)
| Table | Description | Purge Action |
| :--- | :--- | :--- |
| `public.stage_completions` | Player solve milestones and points | `DELETE FROM public.stage_completions;` |
| `public.solves` | Challenge solve records | `DELETE FROM public.solves;` |
| `public.submissions` | Raw submission attempts (audit log) | `DELETE FROM public.submissions;` |
| `public.location_choices` | Player map deductions / candidate pins | `DELETE FROM public.location_choices;` |
| `public.participant_stage_overrides` | Staff test overrides | `DELETE FROM public.participant_stage_overrides WHERE participant_id NOT IN (SELECT id FROM public.participants WHERE name ILIKE '%staff%');` |
| `public.membership_events` | Team join/leave audit trail | `DELETE FROM public.membership_events;` |
| `public.participant_members` | Team membership associations | `DELETE FROM public.participant_members WHERE participant_id IN (SELECT id FROM public.participants WHERE kind = 'team');` |
| `public.participants` | Team participant records | `DELETE FROM public.participants WHERE kind = 'team';` |
| `public.support_tickets` | Test support tickets | `DELETE FROM public.support_tickets WHERE call_sign ILIKE '%test%' OR message ILIKE '%test%';` (Or full purge) |
| `public.score_adjustments` | Manual test score points | `DELETE FROM public.score_adjustments;` |
| `data/player_scores.json` | Local dev server score cache | Reset to `{}` |
| `data/teams.json` | Local dev server team cache | Reset to `[]` |
| `data/support_tickets.json` | Local dev server ticket cache | Reset to `[]` |

---

### B. Tables to PRESERVE (Core Game Engine, Content & Staff)
| Table | Description | Preservation Rationale |
| :--- | :--- | :--- |
| `public.stages` | 7 official game stages & timeline configs | Required for game engine operation |
| `public.challenges` | Stage puzzle hashes, keys & verification data | Core cryptographic verification rules |
| `public.game_settings` | Registration open / closed, team max size | System control & configuration |
| `public.evidence` | Classified documents, audio transcripts, media | In-game student evidence inventory |
| `public.profiles` | Registered student accounts (or reset progress) | Preserve registered credentials so students do not need to re-register |
| `public.participants` (Solo) | 1-to-1 Solo participant rows for registered users | Required for immediate login into Stage 1 |
| `public.announcements` | System announcements & broadcast notices | Official competition broadcasts |
| `auth.users` | Supabase Authentication user identities | Passwords & emails remain valid |

---

## 3. STRICT FOREIGN-KEY SAFE DELETION ORDER
PostgreSQL enforces foreign-key constraints. Attempting to delete tables out of order will result in FK constraint violations. The authoritative execution order is:

```sql
BEGIN;

-- 1. Dependent Child Records (Solve Activity & Deductions)
DELETE FROM public.submissions;
DELETE FROM public.solves;
DELETE FROM public.location_choices;
DELETE FROM public.stage_completions;
DELETE FROM public.score_adjustments;

-- 2. Stage Overrides for testing
DELETE FROM public.participant_stage_overrides;

-- 3. Team Membership & Events
DELETE FROM public.membership_events;
DELETE FROM public.participant_members 
WHERE participant_id IN (SELECT id FROM public.participants WHERE kind = 'team');

-- 4. Team Participants (Retain solo participants so registered students stay enrolled)
DELETE FROM public.participants WHERE kind = 'team';

-- 5. Restore Solo Participants to active (retired = false)
UPDATE public.participants 
SET retired = false 
WHERE kind = 'solo';

-- 6. Ensure solo membership links are active
UPDATE public.participant_members 
SET left_at = NULL 
WHERE participant_id IN (SELECT id FROM public.participants WHERE kind = 'solo');

-- 7. Support Tickets (Purge test tickets)
DELETE FROM public.support_tickets;

COMMIT;
```

---

## 4. PRE-PURGE BACKUP SAFEGUARD
Before executing the purge on Supabase production:
1. Export a full project database dump via Supabase Dashboard -> Database -> Backups or SQL dump:
   ```bash
   pg_dump -h db.xwlbjgbtbppvabmrvenp.supabase.co -U postgres -d postgres > tls0017_pre_purge_backup.sql
   ```
2. Export local files `data/player_scores.json`, `data/teams.json`, and `data/support_tickets.json` to `.bak` copies.
3. Test the transaction inside a `ROLLBACK` block first:
   ```sql
   BEGIN;
   -- Run delete commands
   -- Inspect affected rows
   ROLLBACK;
   ```
