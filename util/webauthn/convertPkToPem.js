
const cbor = require('cbor')
const jwkToPem = require('jwk-to-pem')

// import { COSEKEYS, COSEKTY, COSECRV } from './convertCOSEtoPKCS';

const COSECRV = {
  // alg: -7
  1: 'p256',
  // alg: -35
  2: 'p384',
  // alg: -36
  3: 'p521',
  // alg: -8
  6: 'ed25519',
};

exports.convertPublicKeyToPEM = (publicKey) => {
  let struct;
  try {
    struct = cbor.decodeAllSync(publicKey)[0];
  } catch (err) {
    throw new Error(`Error decoding public key while converting to PEM: ${err.message}`);
  }

  const kty = struct.get(1);

  if (!kty) {
    throw new Error('Public key was missing kty');
  }

  if (kty === 2) {
    const crv = struct.get(-1);
    const x = struct.get(-2);
    const y = struct.get(-3);

    if (!crv) {
      throw new Error('Public key was missing crv (EC2)');
    }

    if (!x) {
      throw new Error('Public key was missing x (EC2)');
    }

    if (!y) {
      throw new Error('Public key was missing y (EC2)');
    }

    const ecPEM = jwkToPem({
      kty: 'EC',
      // Specify curve as "P-256" from "p256"
      crv: COSECRV[crv].replace('p', 'P-'),
      x: x.toString('base64'),
      y: y.toString('base64'),
    });

    return ecPEM;
  } else if (kty === 3) {
    const n = struct.get(-1);
    const e = struct.get(-2);

    if (!n) {
      throw new Error('Public key was missing n (RSA)');
    }

    if (!e) {
      throw new Error('Public key was missing e (RSA)');
    }

    const rsaPEM = jwkToPem({
      kty: 'RSA',
      n: n.toString('base64'),
      e: e.toString('base64'),
    });

    return rsaPEM;
  }

  throw new Error(`Could not convert public key type ${kty} to PEM`);
}
