const express = require('express');
const { setSession, signSession } = require('../middlewares/jwt');
const { ensureAccount } = require('../modules/accounts/service');
const { createUser, findUser } = require('../modules/users/service');

const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required' });
  }

  const user = findUser(username);

  if (!user) {
    return res.status(400).json({ error: 'Unknown user' });
  }

  if (user.password !== password) {
    return res.status(400).json({ error: 'Invalid password' });
  }

  const session = signSession(username);
  setSession(res, session);

  return res.json({ session });
});

router.post('/register', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Invalid username' });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required' });
  }

  if (findUser(username)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const user = createUser(username, password);
  ensureAccount(user);

  const session = signSession(username);
  setSession(res, session);

  return res.json({ session });
});

module.exports = router;
