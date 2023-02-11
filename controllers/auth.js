const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cbor = require('cbor');
const { default: base64url } = require('base64url');
const { OAuth2Client } = require('google-auth-library');

const GMAIL_CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const SIGNIN_CLIENT_ID = process.env.SIGNIN_CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN;

const client = new OAuth2Client(GMAIL_CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
client.setCredentials({ refresh_token: REFRESH_TOKEN });

const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');

const { toHash } = require('../util/webauthn/hashed');
const { convertPublicKeyToPEM } = require('./../util/webauthn/convertPkToPem');
const { verifySignature } = require('../util/webauthn/verifySignature');
const User = require('../models/User');

async function sendMail(email, subject, mail) {
  try {
    const accessToken = await client.getAccessToken();
    const transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.NODEMAIL_GMAIL,
        clientId: GMAIL_CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        refreshToken: REFRESH_TOKEN,
        accessToken,
      },
    });

    await transport.sendMail({
      from: process.env.NODEMAIL_GMAIL,
      to: email,
      subject,
      generateTextFromHTML: true,
      html: mail,
    });
  } catch (err) {
    console.log(err);
    throw err;
  }
}

exports.signup = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const email = req.body.email;
    const name = req.body.fullName;
    const password = req.body.password;

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      email: email,
      name: name,
      password: hashedPassword,
      cart: { items: [] },
    });

    await user.save();

    res.status(200).json({ message: 'Signup successful!', userId: user._id });

    await sendMail(
      email,
      'Signup Suceeded!',
      `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&display=swap" rel="stylesheet">
        <title>Document</title>
        <style>
          body {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            width: 100%;
            height: 100%;
          }
          h1 {
            font-family: 'Montserrat', sans-serif;
            font-size: 3rem;
          }
          a,
          a:visited,
          a:focus,
          a:hover,
          a:active {
            border-radius: 5px;
            background-color: #ff66cc;
            color: white !important;
            padding: 0.5rem 1rem;
            text-align: center;
            font-weight: bold;
            font-size: 1.5rem;
            font-family: 'Montserrat', sans-serif;
            text-decoration: none;
          }
        </style>
      </head>
      <body>
      <h1>You successfully signed up!</h1>
      <a href="${req.protocol}://${req.get('host')}/login">Login</a>
      </body>
      </html>
      `
    );
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.login = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const email = req.body.email;
    const password = req.body.password;
    let loadedUser;

    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error('Email not found');
      error.statusCode = 401;
      throw error;
    }

    loadedUser = user;
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error('Wrong password!');
      error.statusCode = 401;
      throw error;
    }

    const token = jwt.sign(
      {
        email: loadedUser.email,
        userId: loadedUser._id.toString(),
      },
      'somesuperraheemsecret',
      { expiresIn: '2h' }
    );

    res.status(200).json({
      email: loadedUser.email,
      name: loadedUser.name,
      id: loadedUser._id.toString(),
      token: token,
      expiresIn: 7200,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.googleAuth = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const id_token = req.body.idToken;

    const ticket = await client.verifyIdToken({
      idToken: id_token,
      audience: SIGNIN_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const password = payload.sub;
    const user = await User.findOne({ email: payload.email });

    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 12);

      const user = new User({
        email: payload.email,
        name: payload.name,
        password: hashedPassword,
        cart: { items: [] },
      });

      await user.save();
    } else {
      const isEqual = await bcrypt.compare(password, user.password);
      if (!isEqual) {
        const error = new Error('Wrong password!');
        error.statusCode = 401;
        throw error;
      }
    }

    const loadedUser = await User.findOne({ email: payload.email });

    const token = jwt.sign(
      {
        email: payload.email,
        userId: loadedUser._id,
      },
      'somesuperraheemsecret',
      { expiresIn: '2d' }
    );

    res.status(200).json({
      email: loadedUser.email,
      name: loadedUser.name,
      id: loadedUser._id.toString(),
      token: token,
      expiresIn: 7200,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.webauthnReg = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const id = req.body.userId;
    const user = await User.findById(id);

    crypto.randomBytes(32, (err, buf) => {
      if (err) {
        throw err;
      }

      const challenge = buf.toString('hex');
      user.webauthn = {
        challenge,
        resetChallengeExpiration: Date.now() + 60000,
      };
      user.save();

      const publicKeyCredentialCreationOptions = {
        // Relying Party (a.k.a. - Service):
        rp: {
          name: 'Acme',
        },

        // User:
        user: {
          id: base64url(user._id),
          name: user.email,
          displayName: user.name,
        },

        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -8,
          },
          {
            type: 'public-key',
            alg: -35,
          },
          {
            type: 'public-key',
            alg: -36,
          },
          {
            type: 'public-key',
            alg: -37,
          },
          {
            type: 'public-key',
            alg: -38,
          },
          {
            type: 'public-key',
            alg: -39,
          },
          {
            type: 'public-key',
            alg: -257,
          },
          {
            type: 'public-key',
            alg: -258,
          },
          {
            type: 'public-key',
            alg: -259,
          },
        ],

        attestation: 'direct',

        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        },

        timeout: 60000,

        challenge,
      };
      // Prints random bytes of generated data
      res.status(201).send(publicKeyCredentialCreationOptions);
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.webauthnRegVerification = async (req, res, next) => {
  try {
    const credential = req.body.credential;

    const decodedClientData = base64url.decode(
      credential.response.clientDataJSON
    );
    const clientDataJSON = JSON.parse(decodedClientData);

    const user = await User.findOne({
      'webauthn.challenge': base64url.decode(clientDataJSON.challenge),
      'webauthn.resetChallengeExpiration': { $gt: Date.now() },
    });

    if (!user) {
      const error = new Error('User not found');
      error.statusCode = 401;
      throw error;
    }

    if (
      clientDataJSON.type !== 'webauthn.create' &&
      clientDataJSON.origin !== process.env.FRONTEND_ADDRESS
    ) {
      const error = new Error('Invalid origin');
      error.statusCode = 401;
      throw error;
    }

    const attstObj = cbor.decodeFirstSync(
      base64url.toBuffer(credential.response.attestationObject)
    );

    const { authData } = attstObj;

    if (authData.byteLength < 37) {
      throw new Error(
        `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`
      );
    }

    let pointer = 53;

    const credIDLenBuf = authData.slice(pointer, (pointer += 2));
    const credIDLen = credIDLenBuf.readUInt16BE(0);
    const credentialID = base64url(
      authData.slice(pointer, (pointer += credIDLen))
    );
    const credentialPublicKey = base64url(authData.slice(pointer));

    user.webauthn.credentialID = credentialID;
    user.webauthn.credentialPublicKey = credentialPublicKey;
    user.save();

    res.status(201).send({ message: 'Biometric registration sucessful' });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.webauthnLogin = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    const email = req.body.email;

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const user = await User.findOne({ email });

    crypto.randomBytes(32, (err, buf) => {
      const challenge = buf.toString('hex');
      user.webauthn.challenge = challenge;
      user.webauthn.resetChallengeExpiration = Date.now() + 60000;
      user.save();

      const publicKeyCredentialGetOptions = {
        challenge: base64url(
          Uint8Array.from(challenge, (c) => c.charCodeAt(0))
        ),

        allowCredentials: [
          {
            id: user.webauthn.credentialID,

            type: 'public-key',
          },
        ],

        userVerification: 'preferred',

        timeout: 60000,
      };

      res.status(201).send(publicKeyCredentialGetOptions);
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.webauthnLoginVerification = async (req, res, next) => {
  try {
    const credential = req.body.credential;

    const decodedClientData = base64url.decode(
      credential.response.clientDataJSON
    );
    const clientDataJSON = JSON.parse(decodedClientData);

    const user = await User.findOne({
      'webauthn.challenge': base64url.decode(clientDataJSON.challenge),
      'webauthn.resetChallengeExpiration': { $gt: Date.now() },
    });

    if (!user) {
      const error = new Error('User not found');
      error.statusCode = 401;
      throw error;
    }

    if (
      clientDataJSON.type !== 'webauthn.create' &&
      clientDataJSON.origin !== process.env.FRONTEND_ADDRESS
    ) {
      const error = new Error('Invalid origin');
      error.statusCode = 401;
      throw error;
    }

    const authDataBuffer = base64url.toBuffer(
      credential.response.authenticatorData
    );
    const clientDataHash = toHash(
      base64url.toBuffer(credential.response.clientDataJSON)
    );

    const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);
    const publicKey = convertPublicKeyToPEM(
      base64url.toBuffer(user.webauthn.credentialPublicKey)
    );
    const signature = base64url.toBuffer(credential.response.signature);

    const sigVerified = verifySignature(signature, signatureBase, publicKey);

    if (!sigVerified) {
      const error = new Error('Invalid biometric credential');
      error.statusCode = 401;
      throw error;
    }

    const token = jwt.sign(
      {
        email: user.email,
        userId: user._id.toString(),
      },
      'somesuperraheemsecret',
      { expiresIn: '2h' }
    );

    res.status(201).send({
      email: user.email,
      name: user.name,
      id: user._id.toString(),
      token: token,
      expiresIn: 7200,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
