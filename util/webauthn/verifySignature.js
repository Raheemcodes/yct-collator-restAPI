const crypto = require('crypto');

exports.verifySignature = (
  signature,
  signatureBase,
  publicKey,
  algo = 'sha256',
) => {
  return crypto.createVerify(algo).update(signatureBase).verify(publicKey, signature);
}