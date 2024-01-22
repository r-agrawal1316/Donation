
const argon2 = require('argon2');

exports.hashPassword = async (password) => {
  try {
    const hashedPassword = await argon2.hash(password);
    return hashedPassword;
  } catch (err) {
    throw new Error('Error hashing password:', err);
  }
};