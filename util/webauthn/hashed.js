const crypto = require('crypto');

exports.toHash = (data, algo = 'SHA256') => {
  return crypto.createHash(algo).update(data).digest();
};

