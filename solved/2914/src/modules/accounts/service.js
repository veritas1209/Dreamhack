const { db } = require('../database/db');

const getAccount = db.prepare(`
  SELECT id, user_id AS userId, number, balance
  FROM accounts
  WHERE user_id = ?
`);

const getAccountByNumber = db.prepare(`
  SELECT accounts.id, accounts.user_id AS userId, accounts.number, accounts.balance, users.username
  FROM accounts
  JOIN users ON users.id = accounts.user_id
  WHERE accounts.number = ?
`);

const addAccount = db.prepare(`
  INSERT INTO accounts (user_id, number, balance)
  VALUES (?, ?, ?)
`);

const addTransfer = db.prepare(`
  INSERT INTO transfers (sender_id, receiver_id, amount, memo)
  VALUES (?, ?, ?, ?)
`);

const takeMoney = db.prepare(`
  UPDATE accounts
  SET balance = balance - ?
  WHERE user_id = ?
`);

const putMoney = db.prepare(`
  UPDATE accounts
  SET balance = balance + ?
  WHERE user_id = ?
`);

const listRows = db.prepare(`
  SELECT
    transfers.id,
    transfers.amount,
    transfers.memo,
    transfers.created_at AS createdAt,
    sender.username AS sender,
    receiver.username AS receiver
  FROM transfers
  JOIN users sender ON sender.id = transfers.sender_id
  JOIN users receiver ON receiver.id = transfers.receiver_id
  WHERE transfers.sender_id = ? OR transfers.receiver_id = ?
  ORDER BY transfers.id DESC
  LIMIT 20
`);

function makeNumber(userId) {
  return `100-${String(userId).padStart(8, '0')}`;
}

function ensureAccount(user) {
  let account = getAccount.get(user.id);

  if (!account) {
    addAccount.run(user.id, makeNumber(user.id), 100000);
    account = getAccount.get(user.id);
  }

  return account;
}

function history(user) {
  return listRows.all(user.id, user.id);
}

const moveMoney = db.transaction((sender, receiverNumber, amount, memo) => {
  const value = Number(amount);

  if (!Number.isInteger(value) || value <= 0 || value > 1000000) {
    throw new Error('Invalid amount');
  }

  const from = ensureAccount(sender);
  const to = getAccountByNumber.get(receiverNumber);

  if (!to) {
    throw new Error('Receiver not found');
  }

  if (to.userId === sender.id) {
    throw new Error('is not allowed');
  }

  if (from.balance < value) {
    throw new Error('Insufficient balance');
  }

  takeMoney.run(value, sender.id);
  putMoney.run(value, to.userId);
  addTransfer.run(sender.id, to.userId, value, String(memo || '').slice(0, 80));

  return {
    from: getAccount.get(sender.id),
    to: getAccount.get(to.userId),
  };
});

module.exports = {
  ensureAccount,
  history,
  moveMoney,
};
