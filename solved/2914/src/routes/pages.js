const express = require('express');
const { authJwt, setSession, signSession } = require('../middlewares/jwt');
const { loadUser } = require('../middlewares/currentUser');
const { history, moveMoney } = require('../modules/accounts/service');
const { ensureAccount } = require('../modules/accounts/service');
const { createUser, findUser } = require('../modules/users/service');

const router = express.Router();
const jwtGuard = authJwt();

router.get('/', (req, res) => {
  return res.render('index');
});

router.get('/register', (req, res) => {
  return res.render('register');
});

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!password || typeof password !== 'string') {
    return res.status(400).send('Password is required');
  }

  const user = findUser(username);

  if (!user) {
    return res.status(400).send('Unknown user');
  }

  if (user.password !== password) {
    return res.status(400).send('Invalid password');
  }

  setSession(res, signSession(username));
  return res.redirect('/dashboard');
});

router.post('/register', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string') {
    return res.status(400).send('Invalid username');
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).send('Password is required');
  }

  if (findUser(username)) {
    return res.status(400).send('User already exists');
  }

  const user = createUser(username, password);
  ensureAccount(user);
  setSession(res, signSession(username));

  return res.redirect('/dashboard');
});

router.get('/dashboard', jwtGuard, loadUser, (req, res) => {
  return res.render('dashboard', {
    user: req.bankUser,
    account: req.bankAccount,
    transfers: history(req.bankUser),
  });
});

router.get('/transfer', jwtGuard, loadUser, (req, res) => {
  return res.render('transfer', {
    account: req.bankAccount,
  });
});

router.post('/transfer', jwtGuard, loadUser, (req, res) => {
  const { to, amount, memo } = req.body || {};

  try {
    moveMoney(req.bankUser, to, amount, memo);
    return res.redirect('/dashboard');
  } catch (error) {
    return res.status(400).send(error.message);
  }
});

module.exports = router;
