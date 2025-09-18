// middleware/requireAuth.js
export function requireAuth(req, res, next) {
    if (req.session?.userId) return next();
    // If it's an API request
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    // For pages
    return res.redirect('/login.html');
  }
  