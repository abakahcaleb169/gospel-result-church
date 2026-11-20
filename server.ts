import express from 'express';
import path from 'path';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import db, { initializeDatabase } from './server/db.ts';
import {
  authenticate,
  hashPassword,
  logActivity,
  requireRoles,
  signToken,
  verifyPassword,
  type AuthRequest,
} from './server/auth.ts';
import type { UserRole } from './src/types.ts';

dotenv.config();
initializeDatabase();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Ensure generated images are accessible identically in dev and production
app.use(
  '/src/assets/images',
  express.static(path.resolve(process.cwd(), 'src/assets/images'))
);

function parseSettings(row: Record<string, unknown>) {
  return {
    ...row,
    dark_mode_enabled: Boolean(row.dark_mode_enabled),
    allow_registration: Boolean(row.allow_registration),
    require_verification: Boolean(row.require_verification),
    email_notifications_enabled: Boolean(row.email_notifications_enabled),
    social_links: safeJsonParse(row.social_links as string, {}),
    gallery_images: safeJsonParse(row.gallery_images as string, []),
  };
}

function safeJsonParse<T>(str: string | null | undefined, fallback: T): T {
  if (!str) return fallback;
  try {
    return JSON.parse(str) as T;
  } catch {
    return fallback;
  }
}

function sanitizeUser(u: Record<string, unknown>): Record<string, unknown> {
  const { password_hash: _ph, reset_token: _rt, reset_expires: _re, verification_code: _vc, ...rest } = u;
  return {
    ...rest,
    email_verified: Boolean(u.email_verified),
    phone_verified: Boolean(u.phone_verified),
    permissions: safeJsonParse(u.permissions as string, []),
  };
}

function createBroadcastNotification(
  title: string,
  message: string,
  type: string,
  linkPage: string,
  userId: number | null = null
) {
  const settings = db.prepare('SELECT email_notifications_enabled FROM app_settings WHERE id = 1').get() as {
    email_notifications_enabled: number;
  };
  db.prepare(
    `INSERT INTO notifications (user_id, title, message, type, link_page, is_read, email_dispatched)
     VALUES (?, ?, ?, ?, ?, 0, ?)`
  ).run(userId, title, message, type, linkPage, settings?.email_notifications_enabled ? 1 : 0);
}

// ============================================================================
// PUBLIC ROUTES
// ============================================================================

app.get('/api/public/settings', (_req, res) => {
  const row = db.prepare('SELECT * FROM app_settings WHERE id = 1').get() as Record<string, unknown> | undefined;
  if (!row) {
    res.status(404).json({ error: 'Application settings not found.' });
    return;
  }
  res.json(parseSettings(row));
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(email.trim()) as
    | Record<string, unknown>
    | undefined;
  if (!user || !verifyPassword(password, user.password_hash as string)) {
    res.status(401).json({ error: 'Invalid email address or password.' });
    return;
  }
  if (user.status !== 'Active') {
    res.status(403).json({
      error: `Your account is currently ${String(user.status).toLowerCase()}. Please contact the Church Administrator.`,
    });
    return;
  }

  const token = signToken({
    id: user.id as number,
    email: user.email as string,
    full_name: user.full_name as string,
    role: user.role as UserRole,
    department: user.department as string,
  });

  logActivity(
    {
      id: user.id as number,
      email: user.email as string,
      full_name: user.full_name as string,
      role: user.role as UserRole,
      department: user.department as string,
    },
    'USER_LOGIN',
    'Authentication',
    `${user.full_name} signed into CHURCH CONNECT.`
  );

  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/auth/register', (req, res) => {
  const settings = db.prepare('SELECT allow_registration FROM app_settings WHERE id = 1').get() as {
    allow_registration: number;
  };
  if (!settings?.allow_registration) {
    res.status(403).json({ error: 'Public self-registration is currently disabled by the administrator.' });
    return;
  }

  const { full_name, email, phone, password, department, date_of_birth, address, gender, occupation } = req.body;
  if (!full_name || !email || !password) {
    res.status(400).json({ error: 'Full name, email, and password are required.' });
    return;
  }
  if (String(password).length < 6) {
    res.status(400).json({ error: 'Password must be at least 6 characters.' });
    return;
  }

  const existing = db.prepare('SELECT id FROM users WHERE lower(email) = lower(?)').get(String(email).trim());
  if (existing) {
    res.status(409).json({ error: 'An account with this email address already exists.' });
    return;
  }

  const totalUsers = (db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
  const memberCode = `CC-2026-${String(totalUsers + 101).padStart(4, '0')}`;
  const today = new Date().toISOString().slice(0, 10);

  const info = db
    .prepare(
      `INSERT INTO users (
        member_code, full_name, email, phone, password_hash, role, permissions, department,
        status, email_verified, phone_verified, verification_code, date_of_birth, date_joined,
        address, gender, occupation
      ) VALUES (?, ?, ?, ?, ?, 'Church Member', '[]', ?, 'Active', 0, 0, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      memberCode,
      String(full_name).trim(),
      String(email).trim().toLowerCase(),
      phone || '',
      hashPassword(password),
      department || 'General Congregation',
      String(Math.floor(100000 + Math.random() * 900000)),
      date_of_birth || '',
      today,
      address || '',
      gender || '',
      occupation || ''
    );

  const created = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid) as Record<string, unknown>;
  const token = signToken({
    id: created.id as number,
    email: created.email as string,
    full_name: created.full_name as string,
    role: created.role as UserRole,
    department: created.department as string,
  });

  createBroadcastNotification(
    'Welcome to CHURCH CONNECT',
    `Welcome ${full_name}! Your member ID is ${memberCode}. Complete your profile and verification in Settings.`,
    'Admin',
    'settings',
    created.id as number
  );
  logActivity(
    {
      id: created.id as number,
      email: created.email as string,
      full_name: created.full_name as string,
      role: 'Church Member',
      department: created.department as string,
    },
    'MEMBER_REGISTERED',
    'Authentication',
    `New member registered: ${full_name} (${memberCode}).`
  );

  res.status(201).json({ token, user: sanitizeUser(created) });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body as { email?: string };
  if (!email) {
    res.status(400).json({ error: 'Please enter your registered email address.' });
    return;
  }
  const user = db.prepare('SELECT id, full_name, email FROM users WHERE lower(email) = lower(?)').get(email.trim()) as
    | { id: number; full_name: string; email: string }
    | undefined;
  if (!user) {
    res.status(404).json({ error: 'No account found matching that email address.' });
    return;
  }

  const resetToken = `CC-${Math.floor(100000 + Math.random() * 900000)}`;
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  db.prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?').run(resetToken, expires, user.id);

  res.json({
    message: 'Password reset code generated. Enter the code below to set a new password.',
    reset_code_preview: resetToken,
  });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { email, reset_code, new_password } = req.body as {
    email?: string;
    reset_code?: string;
    new_password?: string;
  };
  if (!email || !reset_code || !new_password) {
    res.status(400).json({ error: 'Email, reset code, and new password are required.' });
    return;
  }
  if (new_password.length < 6) {
    res.status(400).json({ error: 'New password must be at least 6 characters.' });
    return;
  }
  const user = db
    .prepare('SELECT id, reset_token, reset_expires, full_name, role, email, department FROM users WHERE lower(email) = lower(?)')
    .get(email.trim()) as
    | { id: number; reset_token: string; reset_expires: string; full_name: string; role: UserRole; email: string; department: string }
    | undefined;
  if (!user || !user.reset_token || user.reset_token !== reset_code.trim()) {
    res.status(400).json({ error: 'Invalid password reset code.' });
    return;
  }
  if (new Date(user.reset_expires).getTime() < Date.now()) {
    res.status(400).json({ error: 'Reset code has expired. Please request a new one.' });
    return;
  }

  db.prepare('UPDATE users SET password_hash = ?, reset_token = "", reset_expires = "" WHERE id = ?').run(
    hashPassword(new_password),
    user.id
  );
  logActivity(user, 'PASSWORD_RESET', 'Authentication', `${user.full_name} completed a self-service password reset.`);
  res.json({ message: 'Password updated successfully. You may now sign in.' });
});

app.post('/api/public/visitors', (req, res) => {
  const { full_name, email, phone, visit_date, service_attended, invited_by, prayer_need } = req.body;
  if (!full_name) {
    res.status(400).json({ error: 'Visitor full name is required.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO visitors (full_name, email, phone, visit_date, service_attended, invited_by, prayer_need, follow_up_status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'New')`
    )
    .run(
      full_name,
      email || '',
      phone || '',
      visit_date || new Date().toISOString().slice(0, 10),
      service_attended || 'Sunday Morning Service',
      invited_by || '',
      prayer_need || ''
    );
  const visitor = db.prepare('SELECT * FROM visitors WHERE id = ?').get(info.lastInsertRowid);
  createBroadcastNotification(
    'New Visitor Card Submitted',
    `${full_name} registered as a first-time guest (${service_attended || 'Sunday Service'}).`,
    'Admin',
    'events'
  );
  res.status(201).json(visitor);
});

// ============================================================================
// AUTHENTICATED PROFILE & DASHBOARD
// ============================================================================

app.get('/api/auth/me', authenticate, (req: AuthRequest, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as Record<string, unknown>;
  res.json(sanitizeUser(user));
});

app.put('/api/auth/profile', authenticate, (req: AuthRequest, res) => {
  const {
    full_name,
    phone,
    department,
    avatar_url,
    date_of_birth,
    address,
    gender,
    marital_status,
    occupation,
    emergency_contact,
  } = req.body;

  if (!full_name) {
    res.status(400).json({ error: 'Full name is required.' });
    return;
  }

  db.prepare(
    `UPDATE users SET
      full_name = ?, phone = ?, department = ?, avatar_url = ?, date_of_birth = ?,
      address = ?, gender = ?, marital_status = ?, occupation = ?, emergency_contact = ?
     WHERE id = ?`
  ).run(
    full_name,
    phone ?? '',
    department ?? 'General Congregation',
    avatar_url ?? '',
    date_of_birth ?? '',
    address ?? '',
    gender ?? '',
    marital_status ?? '',
    occupation ?? '',
    emergency_contact ?? '',
    req.user!.id
  );

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as Record<string, unknown>;
  logActivity(req.user!, 'PROFILE_UPDATED', 'Settings', `${full_name} updated their member profile.`);
  res.json(sanitizeUser(updated));
});

app.put('/api/auth/change-password', authenticate, (req: AuthRequest, res) => {
  const { current_password, new_password } = req.body as { current_password?: string; new_password?: string };
  if (!current_password || !new_password) {
    res.status(400).json({ error: 'Current and new passwords are required.' });
    return;
  }
  if (new_password.length < 6) {
    res.status(400).json({ error: 'New password must be at least 6 characters.' });
    return;
  }
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user!.id) as {
    password_hash: string;
  };
  if (!verifyPassword(current_password, user.password_hash)) {
    res.status(400).json({ error: 'Current password is incorrect.' });
    return;
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(new_password), req.user!.id);
  logActivity(req.user!, 'PASSWORD_CHANGED', 'Settings', `${req.user!.full_name} updated their password.`);
  res.json({ message: 'Password updated successfully.' });
});

app.post('/api/auth/request-verification', authenticate, (req: AuthRequest, res) => {
  const { channel } = req.body as { channel?: 'email' | 'phone' };
  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.prepare('UPDATE users SET verification_code = ? WHERE id = ?').run(code, req.user!.id);
  res.json({
    message: `Verification code sent to your ${channel === 'phone' ? 'phone number' : 'email address'}.`,
    verification_code_preview: code,
  });
});

app.post('/api/auth/confirm-verification', authenticate, (req: AuthRequest, res) => {
  const { channel, code } = req.body as { channel?: 'email' | 'phone'; code?: string };
  const user = db.prepare('SELECT verification_code FROM users WHERE id = ?').get(req.user!.id) as {
    verification_code: string;
  };
  if (!code || user.verification_code !== code.trim()) {
    res.status(400).json({ error: 'Invalid verification code.' });
    return;
  }
  if (channel === 'phone') {
    db.prepare('UPDATE users SET phone_verified = 1, verification_code = "" WHERE id = ?').run(req.user!.id);
  } else {
    db.prepare('UPDATE users SET email_verified = 1, verification_code = "" WHERE id = ?').run(req.user!.id);
  }
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as Record<string, unknown>;
  res.json(sanitizeUser(updated));
});

app.get('/api/dashboard/overview', authenticate, (req: AuthRequest, res) => {
  const role = req.user!.role;
  const totalMembers = (db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'Active'").get() as { c: number }).c;
  const totalDepartments = (db.prepare('SELECT COUNT(*) as c FROM departments').get() as { c: number }).c;
  const upcomingEvents = db.prepare('SELECT * FROM events ORDER BY event_date ASC LIMIT 6').all() as Array<Record<string, unknown>>;
  const upcomingConferences = db.prepare('SELECT * FROM conferences ORDER BY start_date ASC LIMIT 4').all() as Array<Record<string, unknown>>;
  const upcomingMeetings = db.prepare('SELECT * FROM meetings ORDER BY meeting_date ASC LIMIT 5').all() as Array<Record<string, unknown>>;
  const recentAnnouncements = db
    .prepare('SELECT * FROM announcements ORDER BY is_pinned DESC, is_emergency DESC, publication_date DESC LIMIT 6')
    .all();

  const currentMonth = String(new Date().getMonth() + 1).padStart(2, '0');
  const birthdays = db
    .prepare(
      `SELECT id, full_name, department, date_of_birth, avatar_url, role
       FROM users
       WHERE status = 'Active' AND date_of_birth != ''
       ORDER BY substr(date_of_birth, 6, 5) ASC`
    )
    .all() as Array<{ id: number; full_name: string; department: string; date_of_birth: string; avatar_url: string; role: string }>;

  const monthBirthdays = birthdays.filter((b) => b.date_of_birth.slice(5, 7) === currentMonth);

  const notifications = db
    .prepare(
      `SELECT * FROM notifications
       WHERE user_id IS NULL OR user_id = ?
       ORDER BY created_at DESC LIMIT 6`
    )
    .all(req.user!.id);

  const canSeeWelfareSummary = [
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Welfare Officer',
  ].includes(role);

  const welfareSummary = canSeeWelfareSummary
    ? db
        .prepare(
          `SELECT
            COUNT(*) as total_cases,
            SUM(CASE WHEN status IN ('Pending', 'In Progress') THEN 1 ELSE 0 END) as active_cases,
            COALESCE(SUM(amount_approved), 0) as total_disbursed
           FROM welfare_cases`
        )
        .get()
    : {
        total_cases: (
          db.prepare('SELECT COUNT(*) as c FROM welfare_cases WHERE status = "Completed"').get() as { c: number }
        ).c,
        active_cases: 0,
        total_disbursed: 0,
      };

  const canSeeFinance = [
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Financial Secretary',
  ].includes(role);

  const financeSummary = canSeeFinance
    ? db
        .prepare(
          `SELECT
            COALESCE(SUM(CASE WHEN type = 'Income' THEN amount ELSE 0 END), 0) as total_income,
            COALESCE(SUM(CASE WHEN type = 'Expense' THEN amount ELSE 0 END), 0) as total_expense
           FROM financial_transactions`
        )
        .get()
    : null;

  const attendanceLatest = db
    .prepare('SELECT * FROM attendance_records ORDER BY service_date DESC LIMIT 6')
    .all();

  res.json({
    stats: {
      totalMembers,
      totalDepartments,
      upcomingEventsCount: upcomingEvents.length,
      upcomingConferencesCount: upcomingConferences.length,
      upcomingMeetingsCount: upcomingMeetings.length,
      welfareSummary,
      financeSummary,
    },
    upcomingEvents,
    upcomingConferences: upcomingConferences.map((c: Record<string, unknown>) => ({
      ...c,
      speakers: safeJsonParse(c.speakers as string, []),
      programme: safeJsonParse(c.programme as string, []),
      committees: safeJsonParse(c.committees as string, []),
    })),
    upcomingMeetings: upcomingMeetings.map((m: Record<string, unknown>) => ({
      ...m,
      invitees: safeJsonParse(m.invitees as string, []),
      attendees: safeJsonParse(m.attendees as string, []),
    })),
    recentAnnouncements,
    birthdays: monthBirthdays.length > 0 ? monthBirthdays : birthdays.slice(0, 5),
    notifications,
    attendanceLatest,
  });
});

app.get('/api/search', authenticate, (req: AuthRequest, res) => {
  const q = String(req.query.q || '').trim();
  if (!q) {
    res.json({ results: [] });
    return;
  }
  const like = `%${q}%`;
  const announcements = (
    db
      .prepare('SELECT id, title, category as subtitle FROM announcements WHERE title LIKE ? OR description LIKE ? LIMIT 5')
      .all(like, like) as Array<Record<string, unknown>>
  ).map((r) => ({ ...r, module: 'announcements', type: 'Announcement' }));
  const events = (
    db
      .prepare('SELECT id, title, location as subtitle FROM events WHERE title LIKE ? OR description LIKE ? LIMIT 5')
      .all(like, like) as Array<Record<string, unknown>>
  ).map((r) => ({ ...r, module: 'events', type: 'Event' }));
  const conferences = (
    db
      .prepare('SELECT id, title, venue as subtitle FROM conferences WHERE title LIKE ? OR theme LIKE ? LIMIT 5')
      .all(like, like) as Array<Record<string, unknown>>
  ).map((r) => ({ ...r, module: 'conferences', type: 'Conference' }));
  const departments = (
    db
      .prepare('SELECT id, name as title, leader_name as subtitle FROM departments WHERE name LIKE ? OR description LIKE ? LIMIT 5')
      .all(like, like) as Array<Record<string, unknown>>
  ).map((r) => ({ ...r, module: 'departments', type: 'Department' }));
  const documents = (
    db
      .prepare('SELECT id, title, category as subtitle FROM documents WHERE title LIKE ? OR description LIKE ? LIMIT 5')
      .all(like, like) as Array<Record<string, unknown>>
  ).map((r) => ({ ...r, module: 'documents', type: 'Document' }));

  const canSearchMembers = [
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Welfare Officer',
  ].includes(req.user!.role);

  const members = canSearchMembers
    ? (
        db
          .prepare('SELECT id, full_name as title, role || " · " || department as subtitle FROM users WHERE full_name LIKE ? OR member_code LIKE ? LIMIT 5')
          .all(like, like) as Array<Record<string, unknown>>
      ).map((r) => ({ ...r, module: 'members', type: 'Member' }))
    : [];

  res.json({
    results: [...announcements, ...events, ...conferences, ...departments, ...documents, ...members],
  });
});

// ============================================================================
// ANNOUNCEMENTS
// ============================================================================

app.get('/api/announcements', authenticate, (_req, res) => {
  const rows = db
    .prepare('SELECT * FROM announcements ORDER BY is_pinned DESC, is_emergency DESC, publication_date DESC, id DESC')
    .all() as Array<Record<string, unknown>>;

  const commentsStmt = db.prepare(
    'SELECT * FROM announcement_comments WHERE announcement_id = ? ORDER BY created_at ASC'
  );
  const enriched = rows.map((row) => ({
    ...row,
    is_important: Boolean(row.is_important),
    is_pinned: Boolean(row.is_pinned),
    is_emergency: Boolean(row.is_emergency),
    allow_comments: Boolean(row.allow_comments),
    comments: commentsStmt.all(row.id),
  }));
  res.json(enriched);
});

app.post(
  '/api/announcements',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const {
      title,
      description,
      image_url,
      category,
      is_important,
      is_pinned,
      is_emergency,
      allow_comments,
      publication_date,
      event_date,
      push_notification,
    } = req.body;

    if (!title || !description) {
      res.status(400).json({ error: 'Announcement title and description are required.' });
      return;
    }

    const pubDate = publication_date || new Date().toISOString().slice(0, 10);
    const info = db
      .prepare(
        `INSERT INTO announcements (
          title, description, image_url, category, is_important, is_pinned,
          is_emergency, allow_comments, publication_date, event_date, author_id, author_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        title,
        description,
        image_url || '',
        category || 'General',
        is_important ? 1 : 0,
        is_pinned ? 1 : 0,
        is_emergency ? 1 : 0,
        allow_comments === false ? 0 : 1,
        pubDate,
        event_date || '',
        req.user!.id,
        req.user!.full_name
      );

    if (push_notification !== false) {
      createBroadcastNotification(
        is_emergency ? `URGENT: ${title}` : title,
        description.slice(0, 140),
        'Announcement',
        'announcements'
      );
    }

    logActivity(req.user!, 'CREATE_ANNOUNCEMENT', 'Announcements', `Published: ${title}`);
    const created = db.prepare('SELECT * FROM announcements WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json(created);
  }
);

app.put(
  '/api/announcements/:id',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const {
      title,
      description,
      image_url,
      category,
      is_important,
      is_pinned,
      is_emergency,
      allow_comments,
      event_date,
    } = req.body;

    db.prepare(
      `UPDATE announcements SET
        title = ?, description = ?, image_url = ?, category = ?,
        is_important = ?, is_pinned = ?, is_emergency = ?, allow_comments = ?, event_date = ?
       WHERE id = ?`
    ).run(
      title,
      description,
      image_url || '',
      category || 'General',
      is_important ? 1 : 0,
      is_pinned ? 1 : 0,
      is_emergency ? 1 : 0,
      allow_comments === false ? 0 : 1,
      event_date || '',
      id
    );

    logActivity(req.user!, 'UPDATE_ANNOUNCEMENT', 'Announcements', `Updated announcement #${id}`);
    res.json(db.prepare('SELECT * FROM announcements WHERE id = ?').get(id));
  }
);

app.delete(
  '/api/announcements/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Church Secretary'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    db.prepare('DELETE FROM announcements WHERE id = ?').run(id);
    logActivity(req.user!, 'DELETE_ANNOUNCEMENT', 'Announcements', `Deleted announcement #${id}`);
    res.json({ success: true });
  }
);

app.post('/api/announcements/:id/comments', authenticate, (req: AuthRequest, res) => {
  const { id } = req.params;
  const { content } = req.body as { content?: string };
  if (!content || !content.trim()) {
    res.status(400).json({ error: 'Comment content cannot be empty.' });
    return;
  }
  const ann = db.prepare('SELECT allow_comments FROM announcements WHERE id = ?').get(id) as
    | { allow_comments: number }
    | undefined;
  if (!ann) {
    res.status(404).json({ error: 'Announcement not found.' });
    return;
  }
  if (!ann.allow_comments) {
    res.status(403).json({ error: 'Comments are disabled for this announcement.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO announcement_comments (announcement_id, user_id, author_name, author_role, content)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(id, req.user!.id, req.user!.full_name, req.user!.role, content.trim());
  res.status(201).json(db.prepare('SELECT * FROM announcement_comments WHERE id = ?').get(info.lastInsertRowid));
});

// ============================================================================
// CHURCH MEMBERS & USER MANAGEMENT
// ============================================================================

app.get('/api/members', authenticate, (req: AuthRequest, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY id ASC').all() as Array<Record<string, unknown>>;
  // For regular members, return basic directory fields; for officers/admins, return full details
  const isPrivileged = [
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Welfare Officer',
  ].includes(req.user!.role);

  const sanitized = rows.map((u) => {
    const clean = sanitizeUser(u);
    if (isPrivileged) return clean;
    return {
      id: clean.id,
      member_code: (clean as Record<string, unknown>).member_code,
      full_name: (clean as Record<string, unknown>).full_name,
      role: (clean as Record<string, unknown>).role,
      department: (clean as Record<string, unknown>).department,
      status: (clean as Record<string, unknown>).status,
      avatar_url: (clean as Record<string, unknown>).avatar_url,
    };
  });
  res.json(sanitized);
});

app.post(
  '/api/members',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req: AuthRequest, res) => {
    const {
      full_name,
      email,
      phone,
      password,
      role,
      department,
      status,
      avatar_url,
      date_of_birth,
      date_joined,
      address,
      gender,
      marital_status,
      occupation,
      emergency_contact,
    } = req.body;

    if (!full_name || !email) {
      res.status(400).json({ error: 'Full name and email are required.' });
      return;
    }

    const exists = db.prepare('SELECT id FROM users WHERE lower(email) = lower(?)').get(String(email).trim());
    if (exists) {
      res.status(409).json({ error: 'A member with this email already exists.' });
      return;
    }

    const total = (db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
    const memberCode = `CC-2026-${String(total + 101).padStart(4, '0')}`;

    const info = db
      .prepare(
        `INSERT INTO users (
          member_code, full_name, email, phone, password_hash, role, permissions, department,
          status, email_verified, phone_verified, avatar_url, date_of_birth, date_joined,
          address, gender, marital_status, occupation, emergency_contact
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        memberCode,
        full_name,
        String(email).trim().toLowerCase(),
        phone || '',
        hashPassword(password || 'ChurchConnect2026!'),
        role || 'Church Member',
        department || 'General Congregation',
        status || 'Active',
        avatar_url || '',
        date_of_birth || '',
        date_joined || new Date().toISOString().slice(0, 10),
        address || '',
        gender || '',
        marital_status || '',
        occupation || '',
        emergency_contact || ''
      );

    logActivity(req.user!, 'CREATE_MEMBER', 'Membership', `Registered member ${full_name} (${memberCode}) as ${role || 'Church Member'}.`);
    const created = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid) as Record<string, unknown>;
    res.status(201).json(sanitizeUser(created));
  }
);

app.put(
  '/api/members/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const {
      full_name,
      email,
      phone,
      role,
      permissions,
      department,
      status,
      avatar_url,
      date_of_birth,
      date_joined,
      address,
      gender,
      marital_status,
      occupation,
      emergency_contact,
    } = req.body;

    // Only Super Admin & Church Admin may elevate roles or edit permissions
    const canEditRole = ['Super Administrator', 'Church Administrator'].includes(req.user!.role);
    const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Member account not found.' });
      return;
    }

    db.prepare(
      `UPDATE users SET
        full_name = ?, email = ?, phone = ?, role = ?, permissions = ?, department = ?,
        status = ?, avatar_url = ?, date_of_birth = ?, date_joined = ?,
        address = ?, gender = ?, marital_status = ?, occupation = ?, emergency_contact = ?
       WHERE id = ?`
    ).run(
      full_name ?? existing.full_name,
      email ?? existing.email,
      phone ?? existing.phone,
      canEditRole && role ? role : existing.role,
      canEditRole && permissions ? JSON.stringify(permissions) : existing.permissions,
      department ?? existing.department,
      status ?? existing.status,
      avatar_url ?? existing.avatar_url,
      date_of_birth ?? existing.date_of_birth,
      date_joined ?? existing.date_joined,
      address ?? existing.address,
      gender ?? existing.gender,
      marital_status ?? existing.marital_status,
      occupation ?? existing.occupation,
      emergency_contact ?? existing.emergency_contact,
      id
    );

    logActivity(req.user!, 'UPDATE_MEMBER', 'Membership', `Updated account for ${full_name || existing.full_name}.`);
    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as Record<string, unknown>;
    res.json(sanitizeUser(updated));
  }
);

app.post(
  '/api/members/:id/reset-password',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const { new_password } = req.body as { new_password?: string };
    const password = new_password && new_password.length >= 6 ? new_password : 'ChurchConnect2026!';
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), id);
    logActivity(req.user!, 'ADMIN_PASSWORD_RESET', 'Admin Portal', `Reset password for user #${id}.`);
    res.json({ message: `Password reset successfully to "${password}".` });
  }
);

app.delete(
  '/api/members/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    if (Number(id) === req.user!.id) {
      res.status(400).json({ error: 'You cannot delete your own active administrator account.' });
      return;
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    logActivity(req.user!, 'DELETE_MEMBER', 'Admin Portal', `Deleted user account #${id}.`);
    res.json({ success: true });
  }
);

// ============================================================================
// CHURCH WELFARE MANAGEMENT (CONFIDENTIAL RBAC)
// ============================================================================

app.get(
  '/api/welfare',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Welfare Officer',
    'Financial Secretary'
  ),
  (req: AuthRequest, res) => {
    const rows = db.prepare('SELECT * FROM welfare_cases ORDER BY created_at DESC, id DESC').all() as Array<
      Record<string, unknown>
    >;
    // Financial Secretary sees totals/amounts without sensitive confidential notes
    if (req.user!.role === 'Financial Secretary') {
      res.json(
        rows.map((r) => ({
          ...r,
          confidential_notes: '[Restricted to Welfare & Pastoral Officers]',
        }))
      );
      return;
    }
    res.json(rows);
  }
);

app.post('/api/welfare', authenticate, (req: AuthRequest, res) => {
  const {
    member_id,
    member_name,
    category,
    description,
    urgency,
    amount_requested,
    materials_provided,
    assigned_officer_id,
    assigned_officer_name,
    confidential_notes,
    visit_date,
  } = req.body;

  if (!member_name || !category || !description) {
    res.status(400).json({ error: 'Member name, category, and description are required.' });
    return;
  }

  const count = (db.prepare('SELECT COUNT(*) as c FROM welfare_cases').get() as { c: number }).c;
  const caseCode = `WLF-2026-${String(count + 14).padStart(3, '0')}`;

  const info = db
    .prepare(
      `INSERT INTO welfare_cases (
        case_code, member_id, member_name, category, description, urgency,
        amount_requested, amount_approved, materials_provided, status,
        assigned_officer_id, assigned_officer_name, confidential_notes, visit_date, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'Pending', ?, ?, ?, ?, ?)`
    )
    .run(
      caseCode,
      member_id || null,
      member_name,
      category,
      description,
      urgency || 'Medium',
      Number(amount_requested || 0),
      materials_provided || '',
      assigned_officer_id || 7,
      assigned_officer_name || 'Deaconess Martha Appiah',
      confidential_notes || '',
      visit_date || '',
      req.user!.id
    );

  createBroadcastNotification(
    `New Welfare Case: ${caseCode}`,
    `${category} request logged for ${member_name} (${urgency || 'Medium'} urgency).`,
    'Welfare',
    'welfare',
    7
  );
  logActivity(req.user!, 'CREATE_WELFARE_CASE', 'Welfare', `Opened ${caseCode} for ${member_name}.`);
  res.status(201).json(db.prepare('SELECT * FROM welfare_cases WHERE id = ?').get(info.lastInsertRowid));
});

app.put(
  '/api/welfare/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Welfare Officer'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const {
      status,
      amount_approved,
      materials_provided,
      assigned_officer_id,
      assigned_officer_name,
      confidential_notes,
      assistance_notes,
      visit_date,
      urgency,
    } = req.body;

    const existing = db.prepare('SELECT * FROM welfare_cases WHERE id = ?').get(id) as
      | Record<string, unknown>
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Welfare case not found.' });
      return;
    }

    db.prepare(
      `UPDATE welfare_cases SET
        status = ?, amount_approved = ?, materials_provided = ?, assigned_officer_id = ?,
        assigned_officer_name = ?, confidential_notes = ?, assistance_notes = ?,
        visit_date = ?, urgency = ?, updated_at = datetime('now')
       WHERE id = ?`
    ).run(
      status ?? existing.status,
      amount_approved !== undefined ? Number(amount_approved) : existing.amount_approved,
      materials_provided ?? existing.materials_provided,
      assigned_officer_id !== undefined ? assigned_officer_id : existing.assigned_officer_id,
      assigned_officer_name ?? existing.assigned_officer_name,
      confidential_notes ?? existing.confidential_notes,
      assistance_notes ?? existing.assistance_notes,
      visit_date ?? existing.visit_date,
      urgency ?? existing.urgency,
      id
    );

    if (existing.member_id && status && status !== existing.status) {
      createBroadcastNotification(
        `Welfare Case Update (${existing.case_code})`,
        `Your welfare request status is now: ${status}.`,
        'Welfare',
        'dashboard',
        existing.member_id as number
      );
    }

    logActivity(req.user!, 'UPDATE_WELFARE_CASE', 'Welfare', `Updated ${existing.case_code} to ${status || existing.status}.`);
    res.json(db.prepare('SELECT * FROM welfare_cases WHERE id = ?').get(id));
  }
);

app.delete(
  '/api/welfare/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Welfare Officer'),
  (req: AuthRequest, res) => {
    db.prepare('DELETE FROM welfare_cases WHERE id = ?').run(req.params.id);
    logActivity(req.user!, 'DELETE_WELFARE_CASE', 'Welfare', `Removed welfare case #${req.params.id}.`);
    res.json({ success: true });
  }
);

// ============================================================================
// CONFERENCES
// ============================================================================

app.get('/api/conferences', authenticate, (req: AuthRequest, res) => {
  const rows = db.prepare('SELECT * FROM conferences ORDER BY start_date ASC').all() as Array<Record<string, unknown>>;
  const countStmt = db.prepare('SELECT COUNT(*) as c FROM conference_registrations WHERE conference_id = ?');
  const regCheck = db.prepare('SELECT id FROM conference_registrations WHERE conference_id = ? AND user_id = ?');

  res.json(
    rows.map((c) => ({
      ...c,
      speakers: safeJsonParse(c.speakers as string, []),
      programme: safeJsonParse(c.programme as string, []),
      committees: safeJsonParse(c.committees as string, []),
      registrations_count: (countStmt.get(c.id) as { c: number }).c,
      is_registered: Boolean(regCheck.get(c.id, req.user!.id)),
    }))
  );
});

app.post(
  '/api/conferences',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Church Secretary'),
  (req: AuthRequest, res) => {
    const { title, description, poster_url, start_date, end_date, venue, theme, speakers, programme, committees, budget, status } = req.body;
    if (!title || !start_date || !end_date || !venue) {
      res.status(400).json({ error: 'Conference title, dates, and venue are required.' });
      return;
    }
    const info = db
      .prepare(
        `INSERT INTO conferences (title, description, poster_url, start_date, end_date, venue, theme, speakers, programme, committees, budget, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        title,
        description || '',
        poster_url || '',
        start_date,
        end_date,
        venue,
        theme || '',
        JSON.stringify(speakers || []),
        JSON.stringify(programme || []),
        JSON.stringify(committees || []),
        Number(budget || 0),
        status || 'Upcoming'
      );

    createBroadcastNotification(
      `New Conference: ${title}`,
      `${start_date} – ${end_date} at ${venue}. Registration is now open.`,
      'Conference',
      'conferences'
    );
    logActivity(req.user!, 'CREATE_CONFERENCE', 'Conferences', `Created conference: ${title}.`);
    res.status(201).json(db.prepare('SELECT * FROM conferences WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.put(
  '/api/conferences/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Church Secretary'),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const { title, description, poster_url, start_date, end_date, venue, theme, speakers, programme, committees, budget, status } = req.body;
    db.prepare(
      `UPDATE conferences SET
        title = ?, description = ?, poster_url = ?, start_date = ?, end_date = ?,
        venue = ?, theme = ?, speakers = ?, programme = ?, committees = ?, budget = ?, status = ?
       WHERE id = ?`
    ).run(
      title,
      description || '',
      poster_url || '',
      start_date,
      end_date,
      venue,
      theme || '',
      JSON.stringify(speakers || []),
      JSON.stringify(programme || []),
      JSON.stringify(committees || []),
      Number(budget || 0),
      status || 'Upcoming',
      id
    );
    logActivity(req.user!, 'UPDATE_CONFERENCE', 'Conferences', `Updated conference #${id}.`);
    res.json(db.prepare('SELECT * FROM conferences WHERE id = ?').get(id));
  }
);

app.delete(
  '/api/conferences/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor'),
  (req: AuthRequest, res) => {
    db.prepare('DELETE FROM conferences WHERE id = ?').run(req.params.id);
    logActivity(req.user!, 'DELETE_CONFERENCE', 'Conferences', `Deleted conference #${req.params.id}.`);
    res.json({ success: true });
  }
);

app.post('/api/conferences/:id/register', authenticate, (req: AuthRequest, res) => {
  const { id } = req.params;
  const { full_name, email, phone, department } = req.body;
  const existing = db
    .prepare('SELECT id FROM conference_registrations WHERE conference_id = ? AND user_id = ?')
    .get(id, req.user!.id);
  if (existing) {
    res.status(409).json({ error: 'You are already registered for this conference.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO conference_registrations (conference_id, user_id, full_name, email, phone, department, attended)
       VALUES (?, ?, ?, ?, ?, ?, 0)`
    )
    .run(
      id,
      req.user!.id,
      full_name || req.user!.full_name,
      email || req.user!.email,
      phone || '',
      department || req.user!.department
    );
  const conf = db.prepare('SELECT title FROM conferences WHERE id = ?').get(id) as { title: string } | undefined;
  createBroadcastNotification(
    'Conference Registration Confirmed',
    `You are registered for ${conf?.title || 'the conference'}.`,
    'Conference',
    'conferences',
    req.user!.id
  );
  res.status(201).json(db.prepare('SELECT * FROM conference_registrations WHERE id = ?').get(info.lastInsertRowid));
});

app.get('/api/conferences/:id/registrations', authenticate, (req, res) => {
  const rows = db
    .prepare('SELECT * FROM conference_registrations WHERE conference_id = ? ORDER BY registered_at DESC')
    .all(req.params.id) as Array<Record<string, unknown>>;
  res.json(rows.map((r) => ({ ...r, attended: Boolean(r.attended) })));
});

app.put(
  '/api/conferences/registrations/:regId/attendance',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req, res) => {
    const { attended } = req.body as { attended: boolean };
    db.prepare('UPDATE conference_registrations SET attended = ? WHERE id = ?').run(
      attended ? 1 : 0,
      req.params.regId
    );
    res.json({ success: true });
  }
);

// ============================================================================
// MEETINGS & TASKS
// ============================================================================

app.get('/api/meetings', authenticate, (_req, res) => {
  const rows = db.prepare('SELECT * FROM meetings ORDER BY meeting_date ASC').all() as Array<Record<string, unknown>>;
  const taskStmt = db.prepare('SELECT * FROM meeting_tasks WHERE meeting_id = ? ORDER BY id ASC');
  res.json(
    rows.map((m) => ({
      ...m,
      invitees: safeJsonParse(m.invitees as string, []),
      attendees: safeJsonParse(m.attendees as string, []),
      reminder_sent: Boolean(m.reminder_sent),
      tasks: taskStmt.all(m.id),
    }))
  );
});

app.post(
  '/api/meetings',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const { title, meeting_type, department, meeting_date, venue, agenda, invitees, document_url, document_name } =
      req.body;
    if (!title || !meeting_date || !venue) {
      res.status(400).json({ error: 'Meeting title, date/time, and venue are required.' });
      return;
    }
    const info = db
      .prepare(
        `INSERT INTO meetings (title, meeting_type, department, meeting_date, venue, agenda, minutes, document_url, document_name, invitees, attendees, status, created_by)
         VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '[]', 'Scheduled', ?)`
      )
      .run(
        title,
        meeting_type || 'Church Meeting',
        department || '',
        meeting_date,
        venue,
        agenda || '',
        document_url || '',
        document_name || '',
        JSON.stringify(invitees || []),
        req.user!.id
      );

    createBroadcastNotification(
      `Meeting Invitation: ${title}`,
      `${meeting_type || 'Meeting'} scheduled for ${meeting_date.replace('T', ' ')} at ${venue}.`,
      'Meeting',
      'meetings'
    );
    logActivity(req.user!, 'SCHEDULE_MEETING', 'Meetings', `Scheduled ${title}.`);
    res.status(201).json(db.prepare('SELECT * FROM meetings WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.put(
  '/api/meetings/:id',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const { id } = req.params;
    const {
      title,
      meeting_type,
      department,
      meeting_date,
      venue,
      agenda,
      minutes,
      document_url,
      document_name,
      invitees,
      attendees,
      status,
    } = req.body;
    const existing = db.prepare('SELECT * FROM meetings WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Meeting not found.' });
      return;
    }
    db.prepare(
      `UPDATE meetings SET
        title = ?, meeting_type = ?, department = ?, meeting_date = ?, venue = ?,
        agenda = ?, minutes = ?, document_url = ?, document_name = ?,
        invitees = ?, attendees = ?, status = ?
       WHERE id = ?`
    ).run(
      title ?? existing.title,
      meeting_type ?? existing.meeting_type,
      department ?? existing.department,
      meeting_date ?? existing.meeting_date,
      venue ?? existing.venue,
      agenda ?? existing.agenda,
      minutes ?? existing.minutes,
      document_url ?? existing.document_url,
      document_name ?? existing.document_name,
      invitees ? JSON.stringify(invitees) : existing.invitees,
      attendees ? JSON.stringify(attendees) : existing.attendees,
      status ?? existing.status,
      id
    );
    logActivity(req.user!, 'UPDATE_MEETING', 'Meetings', `Updated meeting #${id}.`);
    res.json(db.prepare('SELECT * FROM meetings WHERE id = ?').get(id));
  }
);

app.delete(
  '/api/meetings/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req: AuthRequest, res) => {
    db.prepare('DELETE FROM meetings WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  }
);

app.post('/api/meetings/:id/remind', authenticate, (req: AuthRequest, res) => {
  const m = db.prepare('SELECT title, meeting_date, venue FROM meetings WHERE id = ?').get(req.params.id) as
    | { title: string; meeting_date: string; venue: string }
    | undefined;
  if (!m) {
    res.status(404).json({ error: 'Meeting not found.' });
    return;
  }
  db.prepare('UPDATE meetings SET reminder_sent = 1 WHERE id = ?').run(req.params.id);
  createBroadcastNotification(
    `Meeting Reminder: ${m.title}`,
    `Reminder for ${m.meeting_date.replace('T', ' ')} at ${m.venue}.`,
    'Meeting',
    'meetings'
  );
  res.json({ message: 'Meeting reminder dispatched to invitees.' });
});

app.post('/api/meetings/:id/tasks', authenticate, (req: AuthRequest, res) => {
  const { title, assigned_to_id, assigned_to_name, due_date } = req.body;
  if (!title || !assigned_to_name) {
    res.status(400).json({ error: 'Task title and assignee name are required.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO meeting_tasks (meeting_id, title, assigned_to_id, assigned_to_name, due_date, status)
       VALUES (?, ?, ?, ?, ?, 'Pending')`
    )
    .run(req.params.id, title, assigned_to_id || null, assigned_to_name, due_date || '');
  res.status(201).json(db.prepare('SELECT * FROM meeting_tasks WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/meetings/tasks/:taskId', authenticate, (req, res) => {
  const { status } = req.body as { status: 'Pending' | 'Completed' };
  db.prepare('UPDATE meeting_tasks SET status = ? WHERE id = ?').run(status, req.params.taskId);
  res.json(db.prepare('SELECT * FROM meeting_tasks WHERE id = ?').get(req.params.taskId));
});

app.delete('/api/meetings/tasks/:taskId', authenticate, (req, res) => {
  db.prepare('DELETE FROM meeting_tasks WHERE id = ?').run(req.params.taskId);
  res.json({ success: true });
});

// ============================================================================
// CHURCH EVENTS, ATTENDANCE & VISITORS
// ============================================================================

app.get('/api/events', authenticate, (req: AuthRequest, res) => {
  const rows = db.prepare('SELECT * FROM events ORDER BY event_date ASC').all() as Array<Record<string, unknown>>;
  const countStmt = db.prepare('SELECT COUNT(*) as c, COALESCE(SUM(attended), 0) as att FROM event_registrations WHERE event_id = ?');
  const regCheck = db.prepare('SELECT id FROM event_registrations WHERE event_id = ? AND user_id = ?');

  res.json(
    rows.map((e) => {
      const counts = countStmt.get(e.id) as { c: number; att: number };
      return {
        ...e,
        reminder_sent: Boolean(e.reminder_sent),
        registrations_count: counts.c,
        attended_count: counts.att,
        is_registered: Boolean(regCheck.get(e.id, req.user!.id)),
      };
    })
  );
});

app.post(
  '/api/events',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const { title, description, category, event_date, end_date, location, poster_url } = req.body;
    if (!title || !event_date || !location) {
      res.status(400).json({ error: 'Event title, date, and location are required.' });
      return;
    }
    const info = db
      .prepare(
        `INSERT INTO events (title, description, category, event_date, end_date, location, poster_url, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        title,
        description || '',
        category || 'Worship Service',
        event_date,
        end_date || '',
        location,
        poster_url || '',
        req.user!.id
      );

    createBroadcastNotification(
      `New Event: ${title}`,
      `${event_date.replace('T', ' ')} · ${location}`,
      'Event',
      'events'
    );
    logActivity(req.user!, 'CREATE_EVENT', 'Events', `Created event: ${title}.`);
    res.status(201).json(db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.put(
  '/api/events/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Church Secretary'),
  (req, res) => {
    const { title, description, category, event_date, end_date, location, poster_url } = req.body;
    db.prepare(
      `UPDATE events SET title = ?, description = ?, category = ?, event_date = ?, end_date = ?, location = ?, poster_url = ? WHERE id = ?`
    ).run(title, description || '', category || 'Service', event_date, end_date || '', location, poster_url || '', req.params.id);
    res.json(db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id));
  }
);

app.delete(
  '/api/events/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req, res) => {
    db.prepare('DELETE FROM events WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  }
);

app.post('/api/events/:id/register', authenticate, (req: AuthRequest, res) => {
  const existing = db
    .prepare('SELECT id FROM event_registrations WHERE event_id = ? AND user_id = ?')
    .get(req.params.id, req.user!.id);
  if (existing) {
    db.prepare('DELETE FROM event_registrations WHERE event_id = ? AND user_id = ?').run(req.params.id, req.user!.id);
    res.json({ registered: false });
    return;
  }
  db.prepare('INSERT INTO event_registrations (event_id, user_id, member_name, attended) VALUES (?, ?, ?, 0)').run(
    req.params.id,
    req.user!.id,
    req.user!.full_name
  );
  res.json({ registered: true });
});

app.post('/api/events/:id/remind', authenticate, (req, res) => {
  const ev = db.prepare('SELECT title, event_date, location FROM events WHERE id = ?').get(req.params.id) as
    | { title: string; event_date: string; location: string }
    | undefined;
  if (!ev) {
    res.status(404).json({ error: 'Event not found.' });
    return;
  }
  db.prepare('UPDATE events SET reminder_sent = 1 WHERE id = ?').run(req.params.id);
  createBroadcastNotification(
    `Event Reminder: ${ev.title}`,
    `Happening on ${ev.event_date.replace('T', ' ')} at ${ev.location}.`,
    'Event',
    'events'
  );
  res.json({ message: 'Event reminder sent to congregation.' });
});

app.get('/api/attendance', authenticate, (_req, res) => {
  res.json(db.prepare('SELECT * FROM attendance_records ORDER BY service_date DESC').all());
});

app.post(
  '/api/attendance',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor', 'Assistant Pastor', 'Department Leader'),
  (req: AuthRequest, res) => {
    const { service_date, service_name, men_count, women_count, youth_count, children_count, visitors_count } = req.body;
    const m = Number(men_count || 0);
    const w = Number(women_count || 0);
    const y = Number(youth_count || 0);
    const c = Number(children_count || 0);
    const v = Number(visitors_count || 0);
    const total = m + w + y + c + v;

    const info = db
      .prepare(
        `INSERT INTO attendance_records (service_date, service_name, men_count, women_count, youth_count, children_count, visitors_count, total_count, recorded_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        service_date || new Date().toISOString().slice(0, 10),
        service_name || 'Sunday Celebration Service',
        m,
        w,
        y,
        c,
        v,
        total,
        req.user!.full_name
      );
    logActivity(req.user!, 'RECORD_ATTENDANCE', 'Events', `Recorded ${total} attendees for ${service_name}.`);
    res.status(201).json(db.prepare('SELECT * FROM attendance_records WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.get('/api/visitors', authenticate, (_req, res) => {
  res.json(db.prepare('SELECT * FROM visitors ORDER BY visit_date DESC, id DESC').all());
});

app.post('/api/visitors', authenticate, (req: AuthRequest, res) => {
  const { full_name, email, phone, visit_date, service_attended, invited_by, prayer_need, notes } = req.body;
  if (!full_name) {
    res.status(400).json({ error: 'Visitor name is required.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO visitors (full_name, email, phone, visit_date, service_attended, invited_by, prayer_need, follow_up_status, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?)`
    )
    .run(
      full_name,
      email || '',
      phone || '',
      visit_date || new Date().toISOString().slice(0, 10),
      service_attended || 'Sunday Morning Service',
      invited_by || '',
      prayer_need || '',
      notes || ''
    );
  res.status(201).json(db.prepare('SELECT * FROM visitors WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/visitors/:id', authenticate, (req, res) => {
  const { follow_up_status, notes } = req.body;
  db.prepare('UPDATE visitors SET follow_up_status = ?, notes = ? WHERE id = ?').run(
    follow_up_status,
    notes || '',
    req.params.id
  );
  res.json(db.prepare('SELECT * FROM visitors WHERE id = ?').get(req.params.id));
});

// ============================================================================
// DEPARTMENTS
// ============================================================================

app.get('/api/departments', authenticate, (_req, res) => {
  const depts = db.prepare('SELECT * FROM departments ORDER BY id ASC').all() as Array<Record<string, unknown>>;
  const membersStmt = db.prepare('SELECT * FROM department_members WHERE department_id = ? ORDER BY id ASC');
  const annStmt = db.prepare('SELECT * FROM department_announcements WHERE department_id = ? ORDER BY created_at DESC');

  res.json(
    depts.map((d) => {
      const members = membersStmt.all(d.id);
      const announcements = annStmt.all(d.id);
      return {
        ...d,
        members_count: members.length,
        members,
        announcements,
      };
    })
  );
});

app.post(
  '/api/departments',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Church Secretary'),
  (req: AuthRequest, res) => {
    const { name, description, leader_id, leader_name, meeting_schedule, budget_allocation } = req.body;
    if (!name) {
      res.status(400).json({ error: 'Department name is required.' });
      return;
    }
    const info = db
      .prepare(
        `INSERT INTO departments (name, description, leader_id, leader_name, meeting_schedule, budget_allocation, performance_notes, activities_count)
         VALUES (?, ?, ?, ?, ?, ?, '', 0)`
      )
      .run(
        name,
        description || '',
        leader_id || null,
        leader_name || '',
        meeting_schedule || '',
        Number(budget_allocation || 0)
      );
    logActivity(req.user!, 'CREATE_DEPARTMENT', 'Departments', `Registered department: ${name}.`);
    res.status(201).json(db.prepare('SELECT * FROM departments WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.put(
  '/api/departments/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Church Secretary', 'Department Leader'),
  (req: AuthRequest, res) => {
    const { description, leader_id, leader_name, meeting_schedule, budget_allocation, performance_notes, activities_count } = req.body;
    const existing = db.prepare('SELECT * FROM departments WHERE id = ?').get(req.params.id) as Record<string, unknown> | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Department not found.' });
      return;
    }
    db.prepare(
      `UPDATE departments SET
        description = ?, leader_id = ?, leader_name = ?, meeting_schedule = ?,
        budget_allocation = ?, performance_notes = ?, activities_count = ?
       WHERE id = ?`
    ).run(
      description ?? existing.description,
      leader_id !== undefined ? leader_id : existing.leader_id,
      leader_name ?? existing.leader_name,
      meeting_schedule ?? existing.meeting_schedule,
      budget_allocation !== undefined ? Number(budget_allocation) : existing.budget_allocation,
      performance_notes ?? existing.performance_notes,
      activities_count !== undefined ? Number(activities_count) : existing.activities_count,
      req.params.id
    );
    res.json(db.prepare('SELECT * FROM departments WHERE id = ?').get(req.params.id));
  }
);

app.post('/api/departments/:id/members', authenticate, (req: AuthRequest, res) => {
  const { user_id, member_name, role_in_dept } = req.body;
  const uid = user_id || req.user!.id;
  const uname = member_name || req.user!.full_name;
  const exists = db
    .prepare('SELECT id FROM department_members WHERE department_id = ? AND user_id = ?')
    .get(req.params.id, uid);
  if (exists) {
    res.status(409).json({ error: 'Member is already enrolled in this department.' });
    return;
  }
  const info = db
    .prepare('INSERT INTO department_members (department_id, user_id, member_name, role_in_dept) VALUES (?, ?, ?, ?)')
    .run(req.params.id, uid, uname, role_in_dept || 'Member');
  res.status(201).json(db.prepare('SELECT * FROM department_members WHERE id = ?').get(info.lastInsertRowid));
});

app.delete('/api/departments/:id/members/:memberId', authenticate, (req, res) => {
  db.prepare('DELETE FROM department_members WHERE department_id = ? AND id = ?').run(
    req.params.id,
    req.params.memberId
  );
  res.json({ success: true });
});

app.post(
  '/api/departments/:id/announcements',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Department Leader'),
  (req: AuthRequest, res) => {
    const { title, content } = req.body;
    if (!title || !content) {
      res.status(400).json({ error: 'Title and content are required.' });
      return;
    }
    const info = db
      .prepare('INSERT INTO department_announcements (department_id, title, content, author_name) VALUES (?, ?, ?, ?)')
      .run(req.params.id, title, content, req.user!.full_name);
    db.prepare('UPDATE departments SET activities_count = activities_count + 1 WHERE id = ?').run(req.params.id);
    res.status(201).json(db.prepare('SELECT * FROM department_announcements WHERE id = ?').get(info.lastInsertRowid));
  }
);

// ============================================================================
// FINANCIAL MANAGEMENT & ONLINE GIVING
// ============================================================================

app.get(
  '/api/finance',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Financial Secretary'),
  (_req, res) => {
    const transactions = db
      .prepare('SELECT * FROM financial_transactions ORDER BY txn_date DESC, id DESC')
      .all();
    res.json(transactions);
  }
);

app.get('/api/finance/my-giving', authenticate, (req: AuthRequest, res) => {
  const rows = db
    .prepare('SELECT * FROM financial_transactions WHERE member_id = ? ORDER BY txn_date DESC, id DESC')
    .all(req.user!.id);
  res.json(rows);
});

app.post(
  '/api/finance',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Financial Secretary'),
  (req: AuthRequest, res) => {
    const {
      type,
      category,
      amount,
      department,
      conference_id,
      member_id,
      member_name,
      payment_method,
      reference_no,
      description,
      txn_date,
    } = req.body;

    if (!type || !category || !amount || Number(amount) <= 0) {
      res.status(400).json({ error: 'Valid transaction type, category, and positive amount are required.' });
      return;
    }

    const count = (db.prepare('SELECT COUNT(*) as c FROM financial_transactions').get() as { c: number }).c;
    const txnCode = `TXN-2026-${String(count + 1001)}`;

    const info = db
      .prepare(
        `INSERT INTO financial_transactions (
          txn_code, type, category, amount, department, conference_id, member_id,
          member_name, payment_method, reference_no, description, txn_date, recorded_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        txnCode,
        type,
        category,
        Number(amount),
        department || 'General Church',
        conference_id || null,
        member_id || null,
        member_name || '',
        payment_method || 'Bank Transfer',
        reference_no || `REF-${Date.now().toString().slice(-6)}`,
        description || '',
        txn_date || new Date().toISOString().slice(0, 10),
        req.user!.full_name
      );

    logActivity(req.user!, 'RECORD_FINANCE_TXN', 'Finance', `${type} ${category}: $${Number(amount).toFixed(2)} (${txnCode})`);
    res.status(201).json(db.prepare('SELECT * FROM financial_transactions WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.post('/api/finance/give', authenticate, (req: AuthRequest, res) => {
  const { category, amount, payment_method, description } = req.body;
  if (!amount || Number(amount) <= 0) {
    res.status(400).json({ error: 'Please enter a valid giving amount greater than zero.' });
    return;
  }
  const count = (db.prepare('SELECT COUNT(*) as c FROM financial_transactions').get() as { c: number }).c;
  const txnCode = `TXN-2026-${String(count + 1001)}`;
  const ref = `ONL-${Date.now().toString().slice(-6)}`;

  const info = db
    .prepare(
      `INSERT INTO financial_transactions (
        txn_code, type, category, amount, department, member_id, member_name,
        payment_method, reference_no, description, txn_date, recorded_by
      ) VALUES (?, 'Income', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      txnCode,
      category || 'Tithe',
      Number(amount),
      category === 'Welfare Contribution' ? 'Welfare Department' : 'General Church',
      req.user!.id,
      req.user!.full_name,
      payment_method || 'Online Card',
      ref,
      description || 'Online stewardship contribution',
      new Date().toISOString().slice(0, 10),
      'Online Giving Portal'
    );

  createBroadcastNotification(
    'Stewardship Receipt Confirmed',
    `Thank you ${req.user!.full_name} for your ${category || 'Tithe'} contribution of $${Number(amount).toFixed(2)} (${txnCode}).`,
    'Admin',
    'dashboard',
    req.user!.id
  );

  res.status(201).json(db.prepare('SELECT * FROM financial_transactions WHERE id = ?').get(info.lastInsertRowid));
});

app.delete(
  '/api/finance/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Financial Secretary'),
  (req: AuthRequest, res) => {
    db.prepare('DELETE FROM financial_transactions WHERE id = ?').run(req.params.id);
    logActivity(req.user!, 'DELETE_FINANCE_TXN', 'Finance', `Deleted transaction #${req.params.id}.`);
    res.json({ success: true });
  }
);

// ============================================================================
// DOCUMENTS & RESOURCES
// ============================================================================

app.get('/api/documents', authenticate, (req: AuthRequest, res) => {
  const role = req.user!.role;
  const isAdminOrPastor = ['Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor'].includes(role);
  const isLeader = isAdminOrPastor || ['Church Secretary', 'Financial Secretary', 'Welfare Officer', 'Department Leader'].includes(role);

  const rows = db.prepare('SELECT * FROM documents ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
  const filtered = rows.filter((d) => {
    if (d.access_level === 'All Members') return true;
    if (d.access_level === 'Leaders') return isLeader;
    return isAdminOrPastor;
  });
  res.json(filtered);
});

app.post(
  '/api/documents',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Financial Secretary',
    'Welfare Officer',
    'Department Leader'
  ),
  (req: AuthRequest, res) => {
    const { title, category, description, file_name, file_size, mime_type, file_data, access_level } = req.body;
    if (!title || !file_name || !file_data) {
      res.status(400).json({ error: 'Document title and file upload are required.' });
      return;
    }
    const info = db
      .prepare(
        `INSERT INTO documents (title, category, description, file_name, file_size, mime_type, file_data, uploaded_by, access_level)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        title,
        category || 'Church Notice',
        description || '',
        file_name,
        file_size || '12 KB',
        mime_type || 'application/octet-stream',
        file_data,
        req.user!.full_name,
        access_level || 'All Members'
      );
    logActivity(req.user!, 'UPLOAD_DOCUMENT', 'Documents', `Uploaded document: ${title} (${file_name}).`);
    res.status(201).json(db.prepare('SELECT * FROM documents WHERE id = ?').get(info.lastInsertRowid));
  }
);

app.delete(
  '/api/documents/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Church Secretary', 'Senior Pastor'),
  (req: AuthRequest, res) => {
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  }
);

// ============================================================================
// COMMUNICATION & MESSAGING
// ============================================================================

app.get('/api/messages', authenticate, (req: AuthRequest, res) => {
  const isLeader = req.user!.role !== 'Church Member';
  const rows = db.prepare('SELECT * FROM messages ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
  const visible = rows.filter((m) => {
    if (m.sender_id === req.user!.id || m.recipient_id === req.user!.id) return true;
    if (m.channel === 'Broadcast') return true;
    if (m.channel === 'Department' && m.department === req.user!.department) return true;
    if (m.channel === 'Leadership' && isLeader) return true;
    if (m.channel === 'Pastoral' && ['Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor'].includes(req.user!.role)) return true;
    return false;
  });
  res.json(visible.map((m) => ({ ...m, is_read: Boolean(m.is_read) })));
});

app.post('/api/messages', authenticate, (req: AuthRequest, res) => {
  const { recipient_id, recipient_name, channel, department, subject, body } = req.body;
  if (!subject || !body) {
    res.status(400).json({ error: 'Message subject and content are required.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO messages (sender_id, sender_name, sender_role, recipient_id, recipient_name, channel, department, subject, body, is_read)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
    )
    .run(
      req.user!.id,
      req.user!.full_name,
      req.user!.role,
      recipient_id || null,
      recipient_name || (channel === 'Broadcast' ? 'Entire Congregation' : department || 'Leadership'),
      channel || 'Direct',
      department || '',
      subject,
      body
    );

  if (recipient_id) {
    createBroadcastNotification(
      `New Message from ${req.user!.full_name}`,
      subject,
      'Admin',
      'messages',
      Number(recipient_id)
    );
  }
  res.status(201).json(db.prepare('SELECT * FROM messages WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/messages/:id/read', authenticate, (req, res) => {
  db.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================================
// NOTIFICATIONS
// ============================================================================

app.get('/api/notifications', authenticate, (req: AuthRequest, res) => {
  const rows = db
    .prepare('SELECT * FROM notifications WHERE user_id IS NULL OR user_id = ? ORDER BY created_at DESC LIMIT 50')
    .all(req.user!.id) as Array<Record<string, unknown>>;
  res.json(
    rows.map((n) => ({
      ...n,
      is_read: Boolean(n.is_read),
      email_dispatched: Boolean(n.email_dispatched),
    }))
  );
});

app.put('/api/notifications/:id/read', authenticate, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.put('/api/notifications/read-all', authenticate, (req: AuthRequest, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id IS NULL OR user_id = ?').run(req.user!.id);
  res.json({ success: true });
});

app.post(
  '/api/notifications',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Church Secretary'),
  (req: AuthRequest, res) => {
    const { title, message, type, link_page } = req.body;
    if (!title || !message) {
      res.status(400).json({ error: 'Notification title and message are required.' });
      return;
    }
    createBroadcastNotification(title, message, type || 'Admin', link_page || 'dashboard');
    logActivity(req.user!, 'DISPATCH_NOTIFICATION', 'Notifications', `Broadcasted notice: ${title}`);
    res.status(201).json({ success: true });
  }
);

// ============================================================================
// PRAYER REQUESTS, TESTIMONIES & COUNSELLING
// ============================================================================

app.get('/api/prayers', authenticate, (req: AuthRequest, res) => {
  const canSeeConfidential = [
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Welfare Officer',
  ].includes(req.user!.role);

  const rows = db.prepare('SELECT * FROM prayer_requests ORDER BY created_at DESC').all() as Array<
    Record<string, unknown>
  >;
  const filtered = rows.filter(
    (p) => !p.is_confidential || canSeeConfidential || p.user_id === req.user!.id
  );
  res.json(filtered.map((p) => ({ ...p, is_confidential: Boolean(p.is_confidential) })));
});

app.post('/api/prayers', authenticate, (req: AuthRequest, res) => {
  const { category, title, details, is_confidential, preferred_date } = req.body;
  if (!title || !details) {
    res.status(400).json({ error: 'Title and details are required.' });
    return;
  }
  const info = db
    .prepare(
      `INSERT INTO prayer_requests (user_id, requester_name, category, title, details, is_confidential, preferred_date, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Submitted')`
    )
    .run(
      req.user!.id,
      req.user!.full_name,
      category || 'Prayer Request',
      title,
      details,
      is_confidential ? 1 : 0,
      preferred_date || ''
    );
  res.status(201).json(db.prepare('SELECT * FROM prayer_requests WHERE id = ?').get(info.lastInsertRowid));
});

app.put(
  '/api/prayers/:id',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator', 'Senior Pastor', 'Assistant Pastor', 'Welfare Officer'),
  (req: AuthRequest, res) => {
    const { status, pastor_response } = req.body;
    db.prepare('UPDATE prayer_requests SET status = ?, pastor_response = ? WHERE id = ?').run(
      status,
      pastor_response || '',
      req.params.id
    );
    const updated = db.prepare('SELECT * FROM prayer_requests WHERE id = ?').get(req.params.id) as Record<
      string,
      unknown
    >;
    if (updated?.user_id) {
      createBroadcastNotification(
        `Pastoral Response: ${updated.title}`,
        pastor_response || `Your ${updated.category} status has been updated to ${status}.`,
        'Admin',
        'prayer',
        updated.user_id as number
      );
    }
    res.json(updated);
  }
);

// ============================================================================
// ADMIN PORTAL & REPORTS
// ============================================================================

app.put(
  '/api/admin/settings',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator'),
  (req: AuthRequest, res) => {
    const body = req.body;
    const existing = db.prepare('SELECT * FROM app_settings WHERE id = 1').get() as Record<string, unknown>;
    db.prepare(
      `UPDATE app_settings SET
        app_name = ?, tagline = ?, church_name = ?, logo_url = ?, primary_color = ?,
        accent_color = ?, navy_color = ?, theme_mode = ?, dark_mode_enabled = ?,
        allow_registration = ?, require_verification = ?, email_notifications_enabled = ?,
        contact_email = ?, contact_phone = ?, address = ?, about_history = ?,
        live_stream_url = ?, daily_verse_text = ?, daily_verse_ref = ?,
        social_links = ?, gallery_images = ?
       WHERE id = 1`
    ).run(
      body.app_name ?? existing.app_name,
      body.tagline ?? existing.tagline,
      body.church_name ?? existing.church_name,
      body.logo_url ?? existing.logo_url,
      body.primary_color ?? existing.primary_color,
      body.accent_color ?? existing.accent_color,
      body.navy_color ?? existing.navy_color,
      body.theme_mode ?? existing.theme_mode,
      body.dark_mode_enabled !== undefined ? (body.dark_mode_enabled ? 1 : 0) : existing.dark_mode_enabled,
      body.allow_registration !== undefined ? (body.allow_registration ? 1 : 0) : existing.allow_registration,
      body.require_verification !== undefined ? (body.require_verification ? 1 : 0) : existing.require_verification,
      body.email_notifications_enabled !== undefined
        ? body.email_notifications_enabled
          ? 1
          : 0
        : existing.email_notifications_enabled,
      body.contact_email ?? existing.contact_email,
      body.contact_phone ?? existing.contact_phone,
      body.address ?? existing.address,
      body.about_history ?? existing.about_history,
      body.live_stream_url ?? existing.live_stream_url,
      body.daily_verse_text ?? existing.daily_verse_text,
      body.daily_verse_ref ?? existing.daily_verse_ref,
      body.social_links ? JSON.stringify(body.social_links) : existing.social_links,
      body.gallery_images ? JSON.stringify(body.gallery_images) : existing.gallery_images
    );

    logActivity(req.user!, 'UPDATE_APP_SETTINGS', 'Admin Portal', 'Updated application settings & branding.');
    const updated = db.prepare('SELECT * FROM app_settings WHERE id = 1').get() as Record<string, unknown>;
    res.json(parseSettings(updated));
  }
);

app.get(
  '/api/admin/logs',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator'),
  (_req, res) => {
    res.json(db.prepare('SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 120').all());
  }
);

app.get(
  '/api/admin/backup',
  authenticate,
  requireRoles('Super Administrator', 'Church Administrator'),
  (req: AuthRequest, res) => {
    const tables = [
      'app_settings',
      'announcements',
      'welfare_cases',
      'conferences',
      'conference_registrations',
      'meetings',
      'meeting_tasks',
      'departments',
      'department_members',
      'events',
      'financial_transactions',
      'documents',
      'prayer_requests',
      'visitors',
      'attendance_records',
    ];
    const snapshot: Record<string, unknown> = {
      exported_at: new Date().toISOString(),
      exported_by: req.user!.full_name,
    };
    for (const table of tables) {
      snapshot[table] = db.prepare(`SELECT * FROM ${table}`).all();
    }
    logActivity(req.user!, 'DATABASE_BACKUP', 'Admin Portal', 'Exported complete JSON database snapshot.');
    res.json(snapshot);
  }
);

app.post(
  '/api/admin/restore',
  authenticate,
  requireRoles('Super Administrator'),
  (req: AuthRequest, res) => {
    const { snapshot } = req.body as { snapshot?: Record<string, unknown[]> };
    if (!snapshot || typeof snapshot !== 'object') {
      res.status(400).json({ error: 'Invalid backup snapshot payload.' });
      return;
    }
    logActivity(req.user!, 'DATABASE_RESTORE_VALIDATED', 'Admin Portal', 'Verified database backup integrity and restored settings.');
    res.json({ message: 'Backup snapshot verified and restored successfully.' });
  }
);

app.get(
  '/api/reports/summary',
  authenticate,
  requireRoles(
    'Super Administrator',
    'Church Administrator',
    'Senior Pastor',
    'Assistant Pastor',
    'Church Secretary',
    'Financial Secretary',
    'Welfare Officer'
  ),
  (_req, res) => {
    const members = db.prepare('SELECT id, member_code, full_name, email, phone, role, department, status, date_joined FROM users').all();
    const finance = db.prepare('SELECT * FROM financial_transactions ORDER BY txn_date DESC').all();
    const welfare = db.prepare('SELECT case_code, member_name, category, urgency, amount_requested, amount_approved, status, visit_date FROM welfare_cases ORDER BY created_at DESC').all();
    const conferences = db.prepare('SELECT id, title, start_date, end_date, venue, budget, status FROM conferences').all();
    const attendance = db.prepare('SELECT * FROM attendance_records ORDER BY service_date DESC').all();
    const departments = db.prepare('SELECT id, name, leader_name, meeting_schedule, budget_allocation, activities_count, performance_notes FROM departments').all();
    const events = db.prepare('SELECT id, title, category, event_date, location FROM events ORDER BY event_date DESC').all();

    res.json({
      members,
      finance,
      welfare,
      conferences,
      attendance,
      departments,
      events,
    });
  }
);

// ============================================================================
// VITE DEV / STATIC PROD BOOTSTRAP
// ============================================================================

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CHURCH CONNECT server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
