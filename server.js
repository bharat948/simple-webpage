const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuid } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ACCESS_TOKEN_TTL = Number(process.env.ACCESS_TOKEN_TTL || 15 * 60); // seconds
const REFRESH_TOKEN_TTL = Number(
  process.env.REFRESH_TOKEN_TTL || 7 * 24 * 60 * 60,
); // seconds
const MAX_UPLOAD_SIZE_BYTES = Number(
  process.env.MAX_UPLOAD_SIZE_BYTES || 10 * 1024 * 1024,
);

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { fallthrough: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_SIZE_BYTES },
});

// In-memory data store
const db = {
  users: new Map(),
  refreshTokens: new Map(),
  passwordResetTokens: new Map(),
  mfaChallenges: new Map(),
  pages: new Map(),
  projects: new Map(),
  posts: new Map(),
  contactMessages: new Map(),
  media: new Map(),
  uploads: new Map(),
  assistantSessions: new Map(),
  assistantMessages: new Map(), // sessionId -> [messages]
  personas: new Map(),
  knowledgeSources: new Map(),
  notifications: new Map(), // userId -> [notifications]
  analyticsEvents: [],
  webhookSubscriptions: new Map(),
  webhookEvents: [],
  paymentIntents: new Map(),
  siteConfig: {
    theme: 'light',
    socials: {},
    integrations: {},
  },
};

// Utilities
const nowIso = () => new Date().toISOString();

const sendSuccess = (res, status, data) =>
  res.status(status).json({ status: 'success', data });

const sendError = (res, status, code, message) =>
  res.status(status).json({ status: 'error', error: { code, message } });

const findUserByEmail = (email) =>
  email
    ? [...db.users.values()].find(
        (candidate) => candidate.email.toLowerCase() === email.toLowerCase(),
      )
    : undefined;

const findUserByUsername = (username) =>
  username
    ? [...db.users.values()].find(
        (candidate) =>
          candidate.username &&
          candidate.username.toLowerCase() === username.toLowerCase(),
      )
    : undefined;

const serializeUser = (user, { includePrivate = false } = {}) => {
  if (!user) return null;
  const base = {
    id: user.id,
    email: user.email,
    username: user.username,
    name: user.name,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
    location: user.location,
    socials: user.socials,
    roles: user.roles,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    mfaEnabled: user.mfa?.enabled ?? false,
  };

  if (!includePrivate) {
    return {
      id: base.id,
      name: base.name,
      displayName: base.displayName,
      avatarUrl: base.avatarUrl,
      bio: base.bio,
      socials: base.socials,
      createdAt: base.createdAt,
    };
  }

  return base;
};

const createUser = ({
  email,
  password,
  name,
  displayName,
  roles = ['user'],
  username,
}) => {
  const id = uuid();
  const hashedPassword = password ? bcrypt.hashSync(password, 10) : null;
  const user = {
    id,
    email,
    username: username || email.split('@')[0],
    passwordHash: hashedPassword,
    name: name || '',
    displayName: displayName || name || '',
    avatarUrl: null,
    bio: '',
    location: null,
    socials: {},
    roles,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    mfa: {
      enabled: false,
      secret: null,
      backupCodes: [],
    },
  };

  db.users.set(id, user);
  return user;
};

const issueTokens = (user, context = {}) => {
  const payload = {
    sub: user.id,
    roles: user.roles,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });

  const refreshToken = uuid();
  const expiresAt = Date.now() + REFRESH_TOKEN_TTL * 1000;

  db.refreshTokens.set(refreshToken, {
    userId: user.id,
    expiresAt,
    userAgent: context.userAgent || null,
    issuedAt: nowIso(),
  });

  return {
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_TTL,
  };
};

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendError(res, 401, 'AUTH_REQUIRED', 'Authorization token missing.');
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.users.get(decoded.sub);

    if (!user) {
      return sendError(res, 401, 'AUTH_USER_MISSING', 'User not found.');
    }

    req.auth = { user };
    return next();
  } catch (error) {
    return sendError(res, 401, 'AUTH_INVALID_TOKEN', 'Invalid or expired token.');
  }
};

const optionalAuthenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.auth = null;
    return next();
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.users.get(decoded.sub);
    if (user) {
      req.auth = { user };
    } else {
      req.auth = null;
    }
  } catch (error) {
    req.auth = null;
  }
  return next();
};

const requireRoles = (roles) => (req, res, next) => {
  if (!req.auth?.user) {
    return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required.');
  }

  const userRoles = req.auth.user.roles || [];
  const allowed = roles.some((role) => userRoles.includes(role));

  if (!allowed) {
    return sendError(res, 403, 'AUTH_FORBIDDEN', 'Insufficient permissions.');
  }

  return next();
};

const ensureUniqueSlug = (collection, slug) =>
  ![...collection.values()].some((item) => item.slug === slug);

const upsertNotification = (userId, notification) => {
  const existing = db.notifications.get(userId) || [];
  existing.push(notification);
  db.notifications.set(userId, existing);
};

const seedPersona = (id, persona) => {
  db.personas.set(id, {
    id,
    name: persona.name,
    description: persona.description,
    instructions: persona.instructions,
    visibility: persona.visibility || 'public',
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
};

// Seed default admin user and persona
const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
if (!findUserByEmail(adminEmail)) {
  createUser({
    email: adminEmail,
    password: adminPassword,
    name: 'Site Admin',
    displayName: 'Admin',
    roles: ['admin', 'editor'],
    username: 'admin',
  });
}

seedPersona('dev-assistant', {
  name: 'Developer Assistant',
  description: 'Helps with coding queries and portfolio guidance.',
  instructions:
    'Provide concise, actionable technical assistance tailored to portfolio development.',
});

// Routers
const authRouter = express.Router();
const usersRouter = express.Router();
const pagesRouter = express.Router();
const projectsRouter = express.Router();
const postsRouter = express.Router();
const contactRouter = express.Router();
const mediaRouter = express.Router();
const assistantRouter = express.Router();
const uploadsRouter = express.Router();
const searchRouter = express.Router();
const notificationsRouter = express.Router();
const analyticsRouter = express.Router();
const adminRouter = express.Router();
const webhooksRouter = express.Router();
const paymentsRouter = express.Router();

// Authentication routes
const handleSignup = (req, res) => {
  const {
    email,
    password,
    name,
    displayName,
    username,
    roles: requestedRoles,
  } = req.body || {};

  const normalizedEmail = (email || '').trim().toLowerCase();
  const normalizedUsername = (username || '').trim().toLowerCase();

  if (!normalizedEmail && !normalizedUsername) {
    return sendError(
      res,
      400,
      'AUTH_EMAIL_REQUIRED',
      'Email or username is required.',
    );
  }

  if (!password || typeof password !== 'string' || password.length < 6) {
    return sendError(
      res,
      400,
      'AUTH_PASSWORD_INVALID',
      'Password must be at least 6 characters.',
    );
  }

  const finalEmail =
    normalizedEmail || `${normalizedUsername}@example.localdomain`;
  const finalUsername = normalizedUsername || finalEmail.split('@')[0];

  if (findUserByEmail(finalEmail)) {
    return sendError(res, 409, 'AUTH_DUPLICATE_EMAIL', 'Email already in use.');
  }

  if (findUserByUsername(finalUsername)) {
    return sendError(
      res,
      409,
      'AUTH_DUPLICATE_USERNAME',
      'Username already in use.',
    );
  }

  const roles =
    Array.isArray(requestedRoles) && requestedRoles.length > 0
      ? requestedRoles
      : ['user'];

  const user = createUser({
    email: finalEmail,
    password,
    name,
    displayName,
    roles,
    username: finalUsername,
  });

  const responsePayload = {
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      createdAt: user.createdAt,
    },
  };

  if (req.baseUrl && req.baseUrl.startsWith('/api/')) {
    return sendSuccess(res, 201, responsePayload);
  }

  return res.status(201).json(responsePayload);
};

const handleLogin = (req, res) => {
  const { email, username, password } = req.body || {};
  const identifier = (email || username || '').trim().toLowerCase();

  if (!identifier || !password) {
    return sendError(
      res,
      400,
      'AUTH_CREDENTIALS_REQUIRED',
      'Email/username and password are required.',
    );
  }

  const user =
    findUserByEmail(identifier) || findUserByUsername(identifier) || null;

  if (!user || !user.passwordHash) {
    return sendError(res, 401, 'AUTH_INVALID_CREDENTIALS', 'Invalid login.');
  }

  const passwordValid = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordValid) {
    return sendError(res, 401, 'AUTH_INVALID_CREDENTIALS', 'Invalid login.');
  }

  const tokens = issueTokens(user, { userAgent: req.headers['user-agent'] });

  const responsePayload = {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: tokens.expiresIn,
    user: serializeUser(user, { includePrivate: true }),
  };

  if (req.baseUrl && req.baseUrl.startsWith('/api/')) {
    return sendSuccess(res, 200, responsePayload);
  }

  return res.json({ user: responsePayload.user });
};

authRouter.post('/signup', handleSignup);
authRouter.post('/login', handleLogin);

authRouter.post('/refresh', (req, res) => {
  const { refreshToken } = req.body || {};

  if (!refreshToken) {
    return sendError(
      res,
      400,
      'AUTH_REFRESH_REQUIRED',
      'Refresh token is required.',
    );
  }

  const stored = db.refreshTokens.get(refreshToken);

  if (!stored) {
    return sendError(res, 401, 'AUTH_REFRESH_INVALID', 'Token not recognized.');
  }

  if (stored.expiresAt < Date.now()) {
    db.refreshTokens.delete(refreshToken);
    return sendError(res, 401, 'AUTH_REFRESH_EXPIRED', 'Token expired.');
  }

  const user = db.users.get(stored.userId);
  if (!user) {
    db.refreshTokens.delete(refreshToken);
    return sendError(res, 404, 'AUTH_USER_MISSING', 'User not found.');
  }

  db.refreshTokens.delete(refreshToken);
  const tokens = issueTokens(user, { userAgent: req.headers['user-agent'] });

  return sendSuccess(res, 200, {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: tokens.expiresIn,
  });
});

authRouter.post('/logout', (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken && db.refreshTokens.has(refreshToken)) {
    db.refreshTokens.delete(refreshToken);
  }
  return sendSuccess(res, 200, { message: 'Logged out.' });
});

authRouter.post('/oauth/:provider', (req, res) => {
  const { provider } = req.params;
  const supportedProviders = ['google', 'github', 'linkedin'];

  if (!supportedProviders.includes(provider)) {
    return sendError(
      res,
      400,
      'AUTH_OAUTH_PROVIDER_UNSUPPORTED',
      'Provider not supported.',
    );
  }

  return sendSuccess(res, 200, {
    authorizationUrl: `https://auth.example.com/${provider}/start`,
    provider,
  });
});

authRouter.post('/password-reset/request', (req, res) => {
  const { email } = req.body || {};
  const user = findUserByEmail(email);

  if (!email || !user) {
    // Avoid leaking which emails exist
    return sendSuccess(res, 200, { message: 'If the email exists, a reset link will be sent.' });
  }

  const token = uuid();
  db.passwordResetTokens.set(token, {
    userId: user.id,
    expiresAt: Date.now() + 15 * 60 * 1000,
  });

  return sendSuccess(res, 200, {
    message: 'Password reset initiated.',
    token, // In a real implementation you would send via email
  });
});

authRouter.post('/password-reset/confirm', (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return sendError(
      res,
      400,
      'AUTH_RESET_DATA_REQUIRED',
      'Token and new password are required.',
    );
  }

  const stored = db.passwordResetTokens.get(token);
  if (!stored) {
    return sendError(res, 400, 'AUTH_RESET_INVALID', 'Invalid token.');
  }

  if (stored.expiresAt < Date.now()) {
    db.passwordResetTokens.delete(token);
    return sendError(res, 400, 'AUTH_RESET_EXPIRED', 'Token expired.');
  }

  if (newPassword.length < 6) {
    return sendError(
      res,
      400,
      'AUTH_RESET_WEAK_PASSWORD',
      'Password must be at least 6 characters.',
    );
  }

  const user = db.users.get(stored.userId);
  if (!user) {
    return sendError(res, 404, 'AUTH_USER_MISSING', 'User not found.');
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  user.updatedAt = nowIso();
  db.passwordResetTokens.delete(token);

  return sendSuccess(res, 200, { message: 'Password updated.' });
});

authRouter.post('/mfa/enable', authenticate, (req, res) => {
  const user = req.auth.user;
  const secret = uuid().replace(/-/g, '').slice(0, 16);
  const backupCodes = Array.from({ length: 5 }, () =>
    uuid().slice(0, 8).toUpperCase(),
  );

  user.mfa = {
    enabled: false,
    secret,
    backupCodes,
  };
  user.updatedAt = nowIso();

  return sendSuccess(res, 200, {
    secret,
    backupCodes,
    message: 'MFA pending verification.',
  });
});

authRouter.post('/mfa/verify', authenticate, (req, res) => {
  const user = req.auth.user;
  const { code } = req.body || {};

  if (!code) {
    return sendError(
      res,
      400,
      'AUTH_MFA_CODE_REQUIRED',
      'MFA code is required.',
    );
  }

  if (!user.mfa?.secret) {
    return sendError(res, 400, 'AUTH_MFA_NOT_ENABLED', 'MFA not initiated.');
  }

  const backupCodeIndex = user.mfa.backupCodes.indexOf(code);
  const isSecretMatch = code === user.mfa.secret;

  if (!isSecretMatch && backupCodeIndex === -1) {
    return sendError(res, 400, 'AUTH_MFA_INVALID_CODE', 'Invalid MFA code.');
  }

  if (backupCodeIndex >= 0) {
    user.mfa.backupCodes.splice(backupCodeIndex, 1);
  }

  user.mfa.enabled = true;
  user.mfa.verifiedAt = nowIso();
  user.updatedAt = nowIso();

  return sendSuccess(res, 200, { message: 'MFA enabled.' });
});

// User routes
usersRouter.get('/me', authenticate, (req, res) =>
  sendSuccess(res, 200, { user: serializeUser(req.auth.user, { includePrivate: true }) }),
);

usersRouter.patch('/me', authenticate, (req, res) => {
  const user = req.auth.user;
  const allowedFields = ['bio', 'location', 'socials', 'displayName', 'name'];
  const updates = req.body || {};

  allowedFields.forEach((field) => {
    if (Object.prototype.hasOwnProperty.call(updates, field)) {
      user[field] = updates[field];
    }
  });

  user.updatedAt = nowIso();
  return sendSuccess(res, 200, { user: serializeUser(user, { includePrivate: true }) });
});

usersRouter.post(
  '/me/avatar',
  authenticate,
  upload.single('avatar'),
  (req, res) => {
    if (!req.file) {
      return sendError(
        res,
        400,
        'USERS_AVATAR_REQUIRED',
        'Avatar file is required.',
      );
    }

    const user = req.auth.user;
    const mediaId = uuid();
    const mediaRecord = {
      id: mediaId,
      ownerId: user.id,
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
      buffer: req.file.buffer,
      createdAt: nowIso(),
    };

    db.media.set(mediaId, mediaRecord);
    user.avatarUrl = `/api/media/${mediaId}`;
    user.updatedAt = nowIso();

    return sendSuccess(res, 200, {
      avatarUrl: user.avatarUrl,
      mediaId,
    });
  },
);

usersRouter.get('/:id/public', (req, res) => {
  const user = db.users.get(req.params.id);
  if (!user) {
    return sendError(res, 404, 'USERS_NOT_FOUND', 'User not found.');
  }

  return sendSuccess(res, 200, {
    user: serializeUser(user, { includePrivate: false }),
  });
});

// Pages routes
pagesRouter.get('/', (req, res) => {
  const pages = [...db.pages.values()]
    .filter((page) => page.status === 'published')
    .map((page) => ({
      id: page.id,
      slug: page.slug,
      title: page.title,
      summary: page.summary,
      publishedAt: page.publishedAt,
      seo: page.seo,
    }));

  return sendSuccess(res, 200, { pages });
});

pagesRouter.get('/:slug', (req, res) => {
  const page = [...db.pages.values()].find(
    (candidate) => candidate.slug === req.params.slug,
  );

  if (!page || page.status !== 'published') {
    return sendError(res, 404, 'PAGES_NOT_FOUND', 'Page not found.');
  }

  return sendSuccess(res, 200, { page });
});

pagesRouter.post('/', authenticate, requireRoles(['editor', 'admin']), (req, res) => {
  const { title, slug, content, status = 'draft', seo, summary } = req.body || {};

  if (!title || !slug) {
    return sendError(
      res,
      400,
      'PAGES_DATA_REQUIRED',
      'Title and slug are required.',
    );
  }

  if (!ensureUniqueSlug(db.pages, slug)) {
    return sendError(res, 409, 'PAGES_DUPLICATE_SLUG', 'Slug already in use.');
  }

  const page = {
    id: uuid(),
    title,
    slug,
    content: content || null,
    summary: summary || null,
    status,
    seo: seo || {},
    publishedAt: status === 'published' ? nowIso() : null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    authorId: req.auth.user.id,
  };

  db.pages.set(page.id, page);
  return sendSuccess(res, 201, { page });
});

pagesRouter.patch(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    const page = db.pages.get(req.params.id);
    if (!page) {
      return sendError(res, 404, 'PAGES_NOT_FOUND', 'Page not found.');
    }

    const updates = req.body || {};
    if (
      updates.slug &&
      updates.slug !== page.slug &&
      !ensureUniqueSlug(db.pages, updates.slug)
    ) {
      return sendError(res, 409, 'PAGES_DUPLICATE_SLUG', 'Slug already in use.');
    }

    Object.assign(page, updates);
    if (updates.status === 'published' && !page.publishedAt) {
      page.publishedAt = nowIso();
    }

    page.updatedAt = nowIso();
    return sendSuccess(res, 200, { page });
  },
);

pagesRouter.delete(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    if (!db.pages.has(req.params.id)) {
      return sendError(res, 404, 'PAGES_NOT_FOUND', 'Page not found.');
    }
    db.pages.delete(req.params.id);
    return sendSuccess(res, 200, { message: 'Page deleted.' });
  },
);

// Projects routes
projectsRouter.get('/', (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const start = (Number(page) - 1) * Number(limit);
  const end = start + Number(limit);
  const projects = [...db.projects.values()]
    .filter((project) => project.published)
    .slice(start, end);

  return sendSuccess(res, 200, {
    projects,
    pagination: {
      page: Number(page),
      limit: Number(limit),
      total: [...db.projects.values()].filter((project) => project.published)
        .length,
    },
  });
});

projectsRouter.post('/', authenticate, requireRoles(['editor', 'admin']), (req, res) => {
  const {
    title,
    slug,
    description,
    techStack = [],
    images = [],
    repoUrl,
    liveUrl,
    featured = false,
    published = true,
  } = req.body || {};

  if (!title || !slug) {
    return sendError(
      res,
      400,
      'PROJECTS_DATA_REQUIRED',
      'Title and slug are required.',
    );
  }

  if (!ensureUniqueSlug(db.projects, slug)) {
    return sendError(
      res,
      409,
      'PROJECTS_DUPLICATE_SLUG',
      'Slug already in use.',
    );
  }

  const project = {
    id: uuid(),
    title,
    slug,
    description: description || '',
    techStack,
    images,
    repoUrl: repoUrl || null,
    liveUrl: liveUrl || null,
    featured,
    published,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };

  db.projects.set(project.id, project);
  return sendSuccess(res, 201, { project });
});

projectsRouter.patch(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    const project = db.projects.get(req.params.id);
    if (!project) {
      return sendError(res, 404, 'PROJECTS_NOT_FOUND', 'Project not found.');
    }

    const updates = req.body || {};
    if (
      updates.slug &&
      updates.slug !== project.slug &&
      !ensureUniqueSlug(db.projects, updates.slug)
    ) {
      return sendError(
        res,
        409,
        'PROJECTS_DUPLICATE_SLUG',
        'Slug already in use.',
      );
    }
    Object.assign(project, updates);
    project.updatedAt = nowIso();
    return sendSuccess(res, 200, { project });
  },
);

projectsRouter.delete(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    if (!db.projects.has(req.params.id)) {
      return sendError(res, 404, 'PROJECTS_NOT_FOUND', 'Project not found.');
    }
    db.projects.delete(req.params.id);
    return sendSuccess(res, 200, { message: 'Project deleted.' });
  },
);

// Blog posts
postsRouter.get('/', (req, res) => {
  const { tag, search, page = 1, limit = 20 } = req.query || {};
  let posts = [...db.posts.values()].filter((post) => post.status === 'published');

  if (tag) {
    posts = posts.filter((post) => post.tags?.includes(tag));
  }

  if (search) {
    const q = search.toLowerCase();
    posts = posts.filter(
      (post) =>
        post.title.toLowerCase().includes(q) ||
        post.content.toLowerCase().includes(q),
    );
  }

  const start = (Number(page) - 1) * Number(limit);
  const end = start + Number(limit);

  return sendSuccess(res, 200, {
    posts: posts.slice(start, end),
    pagination: {
      page: Number(page),
      limit: Number(limit),
      total: posts.length,
    },
  });
});

postsRouter.get('/:slug', (req, res) => {
  const post = [...db.posts.values()].find(
    (candidate) => candidate.slug === req.params.slug,
  );

  if (!post || post.status !== 'published') {
    return sendError(res, 404, 'POSTS_NOT_FOUND', 'Post not found.');
  }

  return sendSuccess(res, 200, { post });
});

postsRouter.post('/', authenticate, requireRoles(['editor', 'admin']), (req, res) => {
  const {
    title,
    slug,
    excerpt,
    content,
    tags = [],
    status = 'draft',
  } = req.body || {};

  if (!title || !slug || !content) {
    return sendError(
      res,
      400,
      'POSTS_DATA_REQUIRED',
      'Title, slug, and content are required.',
    );
  }

  if (!ensureUniqueSlug(db.posts, slug)) {
    return sendError(res, 409, 'POSTS_DUPLICATE_SLUG', 'Slug already in use.');
  }

  const post = {
    id: uuid(),
    title,
    slug,
    excerpt: excerpt || '',
    content,
    tags,
    status,
    publishedAt: status === 'published' ? nowIso() : null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    authorId: req.auth.user.id,
  };

  db.posts.set(post.id, post);
  return sendSuccess(res, 201, { post });
});

postsRouter.patch(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    const post = db.posts.get(req.params.id);
    if (!post) {
      return sendError(res, 404, 'POSTS_NOT_FOUND', 'Post not found.');
    }

    const updates = req.body || {};
    if (
      updates.slug &&
      updates.slug !== post.slug &&
      !ensureUniqueSlug(db.posts, updates.slug)
    ) {
      return sendError(res, 409, 'POSTS_DUPLICATE_SLUG', 'Slug already in use.');
    }

    Object.assign(post, updates);

    if (updates.status === 'published' && !post.publishedAt) {
      post.publishedAt = nowIso();
    }

    post.updatedAt = nowIso();
    return sendSuccess(res, 200, { post });
  },
);

postsRouter.delete(
  '/:id',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    if (!db.posts.has(req.params.id)) {
      return sendError(res, 404, 'POSTS_NOT_FOUND', 'Post not found.');
    }
    db.posts.delete(req.params.id);
    return sendSuccess(res, 200, { message: 'Post deleted.' });
  },
);

// Contact
contactRouter.post('/', (req, res) => {
  const { name, email, message, topic } = req.body || {};

  if (!name || !email || !message) {
    return sendError(
      res,
      400,
      'CONTACT_DATA_REQUIRED',
      'Name, email, and message are required.',
    );
  }

  const id = uuid();
  const record = {
    id,
    name,
    email,
    message,
    topic: topic || null,
    receivedAt: nowIso(),
    handled: false,
  };

  db.contactMessages.set(id, record);
  const adminUser = findUserByUsername('admin');
  if (adminUser) {
    upsertNotification(adminUser.id, {
      id: uuid(),
      type: 'contact',
      payload: { name, email, topic },
      createdAt: nowIso(),
      readAt: null,
    });
  }

  return sendSuccess(res, 201, { message: 'Message received.', id });
});

contactRouter.get(
  '/messages',
  authenticate,
  requireRoles(['admin']),
  (req, res) =>
    sendSuccess(res, 200, {
      messages: [...db.contactMessages.values()],
    }),
);

// Media
mediaRouter.post(
  '/upload',
  authenticate,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return sendError(
        res,
        400,
        'MEDIA_FILE_REQUIRED',
        'File is required.',
      );
    }

    const id = uuid();
    const record = {
      id,
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
      buffer: req.file.buffer,
      createdAt: nowIso(),
      ownerId: req.auth?.user?.id || null,
    };

    db.media.set(id, record);
    return sendSuccess(res, 201, {
      media: {
        id,
        url: `/api/media/${id}`,
        fileName: record.fileName,
        mimeType: record.mimeType,
        size: record.size,
        createdAt: record.createdAt,
      },
    });
  },
);

mediaRouter.get('/:id', (req, res) => {
  const media = db.media.get(req.params.id);

  if (!media) {
    return sendError(res, 404, 'MEDIA_NOT_FOUND', 'Media not found.');
  }

  res.setHeader('Content-Type', media.mimeType || 'application/octet-stream');
  return res.send(media.buffer);
});

// Assistant
assistantRouter.post(
  '/sessions',
  optionalAuthenticate,
  (req, res) => {
    const { title, persona: personaId = 'dev-assistant' } = req.body || {};
    const persona = db.personas.get(personaId) || db.personas.get('dev-assistant');
    if (!persona) {
      return sendError(res, 404, 'ASSISTANT_PERSONA_NOT_FOUND', 'Persona not found.');
    }

    const id = uuid();
    const session = {
      id,
      title: title || persona.name,
      personaId: persona.id,
      userId: req.auth?.user?.id || null,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };

    db.assistantSessions.set(id, session);
    db.assistantMessages.set(id, []);

    return sendSuccess(res, 201, { session });
  },
);

assistantRouter.post(
  '/sessions/:sessionId/messages',
  optionalAuthenticate,
  (req, res) => {
    const session = db.assistantSessions.get(req.params.sessionId);
    if (!session) {
      return sendError(res, 404, 'ASSISTANT_SESSION_NOT_FOUND', 'Session not found.');
    }

    const { role = 'user', text, attachments = [], metadata = {} } = req.body || {};
    if (!text) {
      return sendError(
        res,
        400,
        'ASSISTANT_MESSAGE_TEXT_REQUIRED',
        'Message text is required.',
      );
    }

    const messages = db.assistantMessages.get(session.id) || [];

    const userMessage = {
      id: uuid(),
      sessionId: session.id,
      role,
      text,
      attachments,
      metadata,
      createdAt: nowIso(),
    };

    messages.push(userMessage);

    const persona = db.personas.get(session.personaId);
    const assistantReply = {
      id: uuid(),
      sessionId: session.id,
      role: 'assistant',
      text: `(${persona?.name || 'Assistant'}) received: ${text}`,
      attachments: [],
      metadata: { generated: true },
      createdAt: nowIso(),
    };

    messages.push(assistantReply);
    db.assistantMessages.set(session.id, messages);
    session.updatedAt = nowIso();

    return sendSuccess(res, 201, {
      messages: [userMessage, assistantReply],
    });
  },
);

assistantRouter.get('/sessions/:sessionId/messages', (req, res) => {
  const session = db.assistantSessions.get(req.params.sessionId);
  if (!session) {
    return sendError(res, 404, 'ASSISTANT_SESSION_NOT_FOUND', 'Session not found.');
  }

  const messages = db.assistantMessages.get(session.id) || [];
  return sendSuccess(res, 200, { messages });
});

assistantRouter.delete('/sessions/:sessionId', (req, res) => {
  if (!db.assistantSessions.has(req.params.sessionId)) {
    return sendError(res, 404, 'ASSISTANT_SESSION_NOT_FOUND', 'Session not found.');
  }

  db.assistantSessions.delete(req.params.sessionId);
  db.assistantMessages.delete(req.params.sessionId);
  return sendSuccess(res, 200, { message: 'Session deleted.' });
});

assistantRouter.get('/personas', (req, res) =>
  sendSuccess(res, 200, { personas: [...db.personas.values()] }),
);

assistantRouter.post(
  '/personas',
  authenticate,
  requireRoles(['admin']),
  (req, res) => {
    const { name, description, instructions, visibility = 'private' } =
      req.body || {};

    if (!name || !instructions) {
      return sendError(
        res,
        400,
        'ASSISTANT_PERSONA_DATA_REQUIRED',
        'Name and instructions are required.',
      );
    }

    const id = uuid();
    const persona = {
      id,
      name,
      description: description || '',
      instructions,
      visibility,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };

    db.personas.set(id, persona);
    return sendSuccess(res, 201, { persona });
  },
);

assistantRouter.post(
  '/kb/sources',
  authenticate,
  requireRoles(['editor', 'admin']),
  (req, res) => {
    const { type, content, title, visibility = 'private' } = req.body || {};

    if (!type || !content || !title) {
      return sendError(
        res,
        400,
        'ASSISTANT_KB_DATA_REQUIRED',
        'Type, content, and title are required.',
      );
    }

    const id = uuid();
    const source = {
      id,
      type,
      content,
      title,
      visibility,
      status: 'indexed',
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };

    db.knowledgeSources.set(id, source);
    return sendSuccess(res, 201, { source });
  },
);

assistantRouter.get('/kb/search', (req, res) => {
  const { q = '', limit = 5 } = req.query || {};
  const term = q.toLowerCase();

  const matches = [...db.knowledgeSources.values()]
    .filter((source) =>
      [source.title, source.content]
        .join(' ')
        .toLowerCase()
        .includes(term),
    )
    .slice(0, Number(limit))
    .map((source) => ({
      id: source.id,
      title: source.title,
      score: Math.random().toFixed(2),
      snippet: source.content.slice(0, 160),
    }));

  return sendSuccess(res, 200, { matches });
});

assistantRouter.post('/embeddings', (req, res) => {
  const { text } = req.body || {};
  if (!text) {
    return sendError(
      res,
      400,
      'ASSISTANT_EMBEDDING_TEXT_REQUIRED',
      'Text is required.',
    );
  }

  const vector = Array.from({ length: 8 }, () => Math.random());

  return sendSuccess(res, 200, {
    embedding: {
      id: uuid(),
      vector,
    },
  });
});

assistantRouter.post('/retrieve', (req, res) => {
  const { query, limit = 3 } = req.body || {};
  if (!query) {
    return sendError(
      res,
      400,
      'ASSISTANT_RETRIEVE_QUERY_REQUIRED',
      'Query is required.',
    );
  }

  const matches = [...db.knowledgeSources.values()]
    .filter((source) =>
      [source.title, source.content]
        .join(' ')
        .toLowerCase()
        .includes(query.toLowerCase()),
    )
    .slice(0, Number(limit))
    .map((source) => ({
      id: source.id,
      title: source.title,
      snippet: source.content.slice(0, 120),
    }));

  return sendSuccess(res, 200, { matches });
});

assistantRouter.post('/agent/run', (req, res) => {
  const { sessionId, personaId, prompt, options = {}, useKb = true } =
    req.body || {};

  if (!sessionId && !personaId) {
    return sendError(
      res,
      400,
      'ASSISTANT_AGENT_CONTEXT_REQUIRED',
      'Session or persona is required.',
    );
  }

  const persona =
    db.personas.get(personaId) ||
    (sessionId && db.assistantSessions.get(sessionId)
      ? db.personas.get(db.assistantSessions.get(sessionId).personaId)
      : null);

  if (!persona) {
    return sendError(res, 404, 'ASSISTANT_PERSONA_NOT_FOUND', 'Persona not found.');
  }

  const knowledge = useKb
    ? [...db.knowledgeSources.values()]
        .slice(0, 3)
        .map((source) => ({ id: source.id, title: source.title }))
    : [];

  const response = {
    id: uuid(),
    text: `Persona ${persona.name} responding to: ${prompt || 'No prompt provided.'}`,
    meta: {
      options,
      knowledgeUsed: knowledge,
    },
    createdAt: nowIso(),
  };

  return sendSuccess(res, 200, { response });
});

// Uploads
uploadsRouter.post(
  '/',
  authenticate,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return sendError(
        res,
        400,
        'UPLOADS_FILE_REQUIRED',
        'File is required.',
      );
    }

    const id = uuid();
    const record = {
      id,
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
      buffer: req.file.buffer,
      ownerId: req.auth.user.id,
      createdAt: nowIso(),
    };

    db.uploads.set(id, record);
    return sendSuccess(res, 201, {
      upload: {
        id,
        url: `/api/uploads/${id}`,
        mimeType: record.mimeType,
        size: record.size,
      },
    });
  },
);

uploadsRouter.get('/:id', (req, res) => {
  const uploadRecord = db.uploads.get(req.params.id);
  if (!uploadRecord) {
    return sendError(res, 404, 'UPLOADS_NOT_FOUND', 'Upload not found.');
  }
  res.setHeader(
    'Content-Type',
    uploadRecord.mimeType || 'application/octet-stream',
  );
  return res.send(uploadRecord.buffer);
});

uploadsRouter.delete('/:id', authenticate, requireRoles(['admin']), (req, res) => {
  if (!db.uploads.has(req.params.id)) {
    return sendError(res, 404, 'UPLOADS_NOT_FOUND', 'Upload not found.');
  }
  db.uploads.delete(req.params.id);
  return sendSuccess(res, 200, { message: 'Upload deleted.' });
});

// Search
searchRouter.get('/', (req, res) => {
  const { q = '', type, limit = 20, page = 1 } = req.query || {};
  const query = q.toLowerCase();

  const sources = [];
  const pushResults = (items, itemType) => {
    items.forEach((item) => {
      const text = JSON.stringify(item).toLowerCase();
      if (!query || text.includes(query)) {
        sources.push({
          type: itemType,
          id: item.id,
          title: item.title || item.name || item.displayName || item.fileName,
          summary: item.summary || item.description || item.excerpt || '',
        });
      }
    });
  };

  if (!type || type.includes('projects')) {
    pushResults(
      [...db.projects.values()].filter((project) => project.published),
      'projects',
    );
  }

  if (!type || type.includes('posts')) {
    pushResults(
      [...db.posts.values()].filter((post) => post.status === 'published'),
      'posts',
    );
  }

  if (!type || type.includes('pages')) {
    pushResults(
      [...db.pages.values()].filter((page) => page.status === 'published'),
      'pages',
    );
  }

  if (!type || type.includes('files')) {
    pushResults([...db.uploads.values()], 'files');
  }

  const start = (Number(page) - 1) * Number(limit);
  const end = start + Number(limit);

  return sendSuccess(res, 200, {
    results: sources.slice(start, end),
    pagination: {
      page: Number(page),
      limit: Number(limit),
      total: sources.length,
    },
  });
});

// Notifications
notificationsRouter.get(
  '/',
  authenticate,
  (req, res) => {
    const notifications = db.notifications.get(req.auth.user.id) || [];
    return sendSuccess(res, 200, { notifications });
  },
);

notificationsRouter.post(
  '/send',
  authenticate,
  requireRoles(['admin']),
  (req, res) => {
    const { userIds = [], type = 'general', payload = {} } = req.body || {};
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return sendError(
        res,
        400,
        'NOTIFICATIONS_RECIPIENTS_REQUIRED',
        'At least one recipient required.',
      );
    }

    userIds.forEach((userId) => {
      if (db.users.has(userId)) {
        upsertNotification(userId, {
          id: uuid(),
          type,
          payload,
          createdAt: nowIso(),
          readAt: null,
        });
      }
    });

    return sendSuccess(res, 200, { message: 'Notifications queued.' });
  },
);

// Analytics
analyticsRouter.post('/event', (req, res) => {
  const { userId, anonId, eventType, payload = {}, ts } = req.body || {};
  if (!eventType) {
    return sendError(
      res,
      400,
      'ANALYTICS_EVENT_REQUIRED',
      'Event type is required.',
    );
  }

  const event = {
    id: uuid(),
    userId: userId || null,
    anonId: anonId || uuid(),
    eventType,
    payload,
    occurredAt: ts || nowIso(),
  };

  db.analyticsEvents.push(event);
  return sendSuccess(res, 201, { event });
});

analyticsRouter.get(
  '/summary',
  authenticate,
  requireRoles(['admin']),
  (req, res) => {
    const events = db.analyticsEvents;
    const totalEvents = events.length;
    const byType = events.reduce((acc, event) => {
      acc[event.eventType] = (acc[event.eventType] || 0) + 1;
      return acc;
    }, {});

    return sendSuccess(res, 200, {
      totalEvents,
      eventsByType: byType,
    });
  },
);

// Admin routes
adminRouter.get('/users', authenticate, requireRoles(['admin']), (req, res) =>
  sendSuccess(res, 200, {
    users: [...db.users.values()].map((user) =>
      serializeUser(user, { includePrivate: true }),
    ),
  }),
);

adminRouter.patch(
  '/users/:id/roles',
  authenticate,
  requireRoles(['admin']),
  (req, res) => {
    const { roles } = req.body || {};
    const user = db.users.get(req.params.id);
    if (!user) {
      return sendError(res, 404, 'ADMIN_USER_NOT_FOUND', 'User not found.');
    }

    if (!Array.isArray(roles) || roles.length === 0) {
      return sendError(
        res,
        400,
        'ADMIN_ROLES_REQUIRED',
        'Roles array is required.',
      );
    }

    user.roles = roles;
    user.updatedAt = nowIso();
    return sendSuccess(res, 200, {
      user: serializeUser(user, { includePrivate: true }),
    });
  },
);

adminRouter.get(
  '/site-config',
  authenticate,
  requireRoles(['admin']),
  (req, res) => sendSuccess(res, 200, { config: db.siteConfig }),
);

adminRouter.patch(
  '/site-config',
  authenticate,
  requireRoles(['admin']),
  (req, res) => {
    const updates = req.body || {};
    db.siteConfig = {
      ...db.siteConfig,
      ...updates,
      updatedAt: nowIso(),
    };
    return sendSuccess(res, 200, { config: db.siteConfig });
  },
);

// Webhooks & Integrations
webhooksRouter.post(
  '/subscribe',
  authenticate,
  (req, res) => {
    const { url, events = [] } = req.body || {};
    if (!url || !Array.isArray(events) || events.length === 0) {
      return sendError(
        res,
        400,
        'WEBHOOK_SUBSCRIPTION_DATA_REQUIRED',
        'URL and events are required.',
      );
    }

    const id = uuid();
    const record = {
      id,
      userId: req.auth.user.id,
      url,
      events,
      createdAt: nowIso(),
    };

    db.webhookSubscriptions.set(id, record);
    return sendSuccess(res, 201, { subscription: record });
  },
);

webhooksRouter.post('/events', (req, res) => {
  const { eventType, payload = {} } = req.body || {};

  if (!eventType) {
    return sendError(
      res,
      400,
      'WEBHOOK_EVENT_TYPE_REQUIRED',
      'Event type is required.',
    );
  }

  const event = {
    id: uuid(),
    eventType,
    payload,
    createdAt: nowIso(),
  };

  db.webhookEvents.push(event);
  return sendSuccess(res, 201, { event });
});

// Payments
paymentsRouter.post('/create-intent', optionalAuthenticate, (req, res) => {
  const { amount, currency = 'usd', description } = req.body || {};

  if (!amount || amount <= 0) {
    return sendError(
      res,
      400,
      'PAYMENTS_AMOUNT_REQUIRED',
      'Valid amount is required.',
    );
  }

  const id = uuid();
  const intent = {
    id,
    amount,
    currency,
    description: description || '',
    status: 'requires_payment_method',
    createdAt: nowIso(),
    clientSecret: `${id}_secret`,
    userId: req.auth?.user?.id || null,
  };

  db.paymentIntents.set(id, intent);
  return sendSuccess(res, 201, { paymentIntent: intent });
});

paymentsRouter.get('/:id/status', (req, res) => {
  const intent = db.paymentIntents.get(req.params.id);
  if (!intent) {
    return sendError(res, 404, 'PAYMENTS_INTENT_NOT_FOUND', 'Payment intent not found.');
  }

  return sendSuccess(res, 200, {
    paymentIntent: {
      id: intent.id,
      status: intent.status,
      amount: intent.amount,
      currency: intent.currency,
    },
  });
});

// Public & SEO routes
app.get('/', (req, res) => {
  res.send(
    'Portfolio + Personal Assistant API is running. Refer to /api for endpoints.',
  );
});

app.get('/sitemap.xml', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const urls = [
    `${baseUrl}/`,
    ...[...db.pages.values()]
      .filter((page) => page.status === 'published')
      .map((page) => `${baseUrl}/pages/${page.slug}`),
    ...[...db.projects.values()]
      .filter((project) => project.published)
      .map((project) => `${baseUrl}/projects/${project.slug}`),
    ...[...db.posts.values()]
      .filter((post) => post.status === 'published')
      .map((post) => `${baseUrl}/blog/${post.slug}`),
  ];

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
  .map((url) => `  <url><loc>${url}</loc><lastmod>${nowIso()}</lastmod></url>`)
  .join('\n')}
</urlset>`;

  res.type('application/xml').send(xml);
});

app.get('/rss.xml', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const items = [...db.posts.values()]
    .filter((post) => post.status === 'published')
    .map(
      (post) => `
  <item>
    <title><![CDATA[${post.title}]]></title>
    <link>${baseUrl}/blog/${post.slug}</link>
    <guid>${post.id}</guid>
    <pubDate>${post.publishedAt || post.createdAt}</pubDate>
    <description><![CDATA[${post.excerpt || post.content.slice(0, 160)}]]></description>
  </item>`,
    )
    .join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
  <title>Portfolio Blog</title>
  <link>${baseUrl}</link>
  <description>Updates from the portfolio.</description>
  ${items}
</channel>
</rss>`;

  res.type('application/xml').send(rss);
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nAllow: /\n');
});

// Legacy compatibility routes
app.post('/auth/signup', handleSignup);
app.post('/auth/signin', handleLogin);

app.get('/users', (req, res) =>
  res.json({
    users: [...db.users.values()].map((user) =>
      serializeUser(user, { includePrivate: false }),
    ),
  }),
);

app.get('/users/:id', (req, res) => {
  const user = db.users.get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  return res.json({
    user: serializeUser(user, { includePrivate: false }),
  });
});

// Mount routers
app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/pages', pagesRouter);
app.use('/api/projects', projectsRouter);
app.use('/api/posts', postsRouter);
app.use('/api/contact', contactRouter);
app.use('/api/media', mediaRouter);
app.use('/api/assistant', assistantRouter);
app.use('/api/uploads', uploadsRouter);
app.use('/api/search', searchRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/admin', adminRouter);
app.use('/api/webhooks', webhooksRouter);
app.use('/api/payments', paymentsRouter);

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) {
    return next(err);
  }
  return sendError(
    res,
    500,
    'INTERNAL_SERVER_ERROR',
    'Internal server error.',
  );
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
