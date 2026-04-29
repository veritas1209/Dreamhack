const jwt = require('jsonwebtoken');
const { flatten, nest } = require('flatnest');
const { secret } = require('../modules/env');

function readCookie(req, key) {
  const cookies = req.headers.cookie || '';
  const parts = cookies.split(';');

  for (const part of parts) {
    const [name, ...rest] = part.trim().split('=');

    if (name === key) {
      return decodeURIComponent(rest.join('='));
    }
  }

  return '';
}

function setSession(res, session) {
  res.setHeader('Set-Cookie', `session=${encodeURIComponent(session)}; HttpOnly; Path=/; SameSite=Lax`);
}

function signSession(username) {
  const sess = flatten({
    username,
  });

  return jwt.sign(sess, secret, {
    expiresIn: '1h',
  });
}

function authJwt() {
  return function jwtGuard(req, res, next) {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    const session = type === 'Bearer' && token ? token : readCookie(req, 'session');

    if (!session) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }

    try {
      const sess = jwt.verify(session, secret);
      req.user = nest(sess);
      return next();
    } catch (error) {
      return res.status(401).json({ error: 'Invalid session' });
    }
  };
}

module.exports = {
  authJwt,
  setSession,
  signSession,
};
