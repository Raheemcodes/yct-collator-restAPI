const crypto = require('crypto');
const cbor = require('cbor');
const { default: base64url } = require('base64url');
const { validationResult } = require('express-validator');

const { toHash } = require('../util/webauthn/hashed');
const { convertPublicKeyToPEM } = require('./../util/webauthn/convertPkToPem');
const { verifySignature } = require('../util/webauthn/verifySignature');
const User = require('../models/User');

exports.webauthnReg = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const id = req.body.teacherId;
    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const matricNumber = req.body.matricNumber;

    const user = await User.findById(id);

    const student = await user.findStudent(
      sessionId,
      progId,
      courseId,
      matricNumber,
    );

    if (student.isRegistered) {
      const error = new Error('You already have a biometric credential!');
      error.statusCode = 401;
      throw error;
    }

    await crypto.randomBytes(32, (err, buf) => {
      if (err) {
        throw err;
      }

      const challenge = buf.toString('hex');
      student.webauthn = {
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
          id: base64url(student._id),
          name: student.matricNumber,
          displayName: student.matricNumber,
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
    const id = req.body.teacherId;
    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const recordId = req.body.recordId;
    const attendanceId = req.body.attendanceId;
    const token = req.body.token;
    const matricNumber = req.body.matricNumber;

    const user = await User.findById(id);

    const decodedClientData = base64url.decode(
      credential.response.clientDataJSON,
    );
    const clientDataJSON = JSON.parse(decodedClientData);

    const student = await user.findStudent(
      sessionId,
      progId,
      courseId,
      matricNumber,
      clientDataJSON,
    );

    if (
      clientDataJSON.type !== 'webauthn.create' &&
      clientDataJSON.origin !== process.env.FRONTEND_ADDRESS
    ) {
      const error = new Error('Invalid origin');
      error.statusCode = 401;
      throw error;
    }

    const attstObj = cbor.decodeFirstSync(
      base64url.toBuffer(credential.response.attestationObject),
    );

    const { authData } = attstObj;

    if (authData.byteLength < 37) {
      throw new Error(
        `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
      );
    }

    let pointer = 53;

    const credIDLenBuf = authData.slice(pointer, (pointer += 2));
    const credIDLen = credIDLenBuf.readUInt16BE(0);
    const credentialID = base64url(
      authData.slice(pointer, (pointer += credIDLen)),
    );
    const credentialPublicKey = base64url(authData.slice(pointer));

    const result = await user.findAttendanceLine(
      sessionId,
      progId,
      courseId,
      recordId,
      attendanceId,
      token,
    );

    student.webauthn.credentialID = credentialID;
    student.webauthn.credentialPublicKey = credentialPublicKey;
    student.isRegistered = true;
    result.attendanceLine.isRegistered = true;
    user.save();

    res.status(201).send({ attendanceRecord: result.attendanceRecord });
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

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const id = req.body.teacherId;
    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const matricNumber = req.body.matricNumber;

    const user = await User.findById(id);

    const student = await user.findStudent(
      sessionId,
      progId,
      courseId,
      matricNumber,
    );

    if (!student.isRegistered) {
      const error = new Error("You haven't added a biometric credential");
      error.statusCode = 401;
      throw error;
    }

    await crypto.randomBytes(32, (err, buf) => {
      const challenge = buf.toString('hex');
      student.webauthn.challenge = challenge;
      student.webauthn.resetChallengeExpiration = Date.now() + 60000;
      user.save();

      const publicKeyCredentialGetOptions = {
        challenge: base64url(
          Uint8Array.from(challenge, (c) => c.charCodeAt(0)),
        ),

        allowCredentials: [
          {
            id: student.webauthn.credentialID,

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
    const id = req.body.teacherId;
    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const recordId = req.body.recordId;
    const attendanceId = req.body.attendanceId;
    const token = req.body.token;
    const status = req.body.status;
    const matricNumber = req.body.matricNumber;

    const user = await User.findById(id);

    const decodedClientData = base64url.decode(
      credential.response.clientDataJSON,
    );
    const clientDataJSON = JSON.parse(decodedClientData);

    const student = await user.findStudent(
      sessionId,
      progId,
      courseId,
      matricNumber,
      clientDataJSON,
    );

    if (
      clientDataJSON.type !== 'webauthn.create' &&
      clientDataJSON.origin !== process.env.FRONTEND_ADDRESS
    ) {
      const error = new Error('Invalid origin');
      error.statusCode = 401;
      throw error;
    }

    const authDataBuffer = base64url.toBuffer(
      credential.response.authenticatorData,
    );
    const clientDataHash = toHash(
      base64url.toBuffer(credential.response.clientDataJSON),
    );

    const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);
    const publicKey = convertPublicKeyToPEM(
      base64url.toBuffer(student.webauthn.credentialPublicKey),
    );
    const signature = base64url.toBuffer(credential.response.signature);

    const sigVerified = verifySignature(signature, signatureBase, publicKey);

    if (!sigVerified) {
      const error = new Error('Invalid biometric credential!');
      error.statusCode = 401;
      throw error;
    }

    const attendanceRecord = await user.markAttendance(
      sessionId,
      progId,
      courseId,
      recordId,
      attendanceId,
      status,
      token,
    );

    res.status(201).send({ attendanceRecord });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
