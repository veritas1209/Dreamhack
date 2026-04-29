const { findUser } = require('../modules/users/service');
const { ensureAccount } = require('../modules/accounts/service');

function loadUser(req, res, next) {
  const user = findUser(req.user && req.user.username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  req.bankUser = user;
  req.bankAccount = ensureAccount(user);
  return next();
}

module.exports = {
  loadUser,
};
