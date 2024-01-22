const crypto = require('crypto');

function generateSessionKey() {
  const length = 32;
  const sessionKey = crypto.randomBytes(length).toString('hex');
  return sessionKey;
}

module.exports = generateSessionKey;