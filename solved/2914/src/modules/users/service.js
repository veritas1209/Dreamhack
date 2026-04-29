const { db } = require('../database/db');

const selectUser = db.prepare(`
  SELECT id, username, password
  FROM users
  WHERE username = ?
`);

const addUser = db.prepare(`
  INSERT INTO users (username, password)
  VALUES (?, ?)
`);

function lookupId(input) {
  const fields = ['username', 'customer', 'id'];

  if (typeof input === 'string') {
    return input;
  }

  if (input && typeof input === 'object') {
    for (const field of fields) {
      if (typeof input[field] === 'string') {
        return input[field];
      }
    }
  }

  return '';
}

function findUser(input) {
  const key = lookupId(input);

  if (!key) {
    return null;
  }

  return selectUser.get(key);
}

function createUser(name, password) {
  addUser.run(name, password);
  return findUser(name);
}

module.exports = {
  findUser,
  createUser,
};
