const express = require('express');
const { body } = require('express-validator');

const router = express.Router();

const User = require('../models/User');
const studentControllers = require('../controllers/student');

router.post(
  '/webauthn-reg',
  [
    body(
      ['teacherId', 'sessionId', 'progId', 'courseId', 'matricNumber'],
      'Invalid URL',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.teacherId;

        const user = await User.findById(userId);
        if (!user) throw new Error('Invalid URL');
        return true;
      }),
  ],
  studentControllers.webauthnReg,
);

router.post(
  '/webauthn-reg-verification',
  [
    body(
      [
        'teacherId',
        'sessionId',
        'progId',
        'courseId',
        'recordId',
        'attendanceId',
        'token',
      ],
      'Invalid URL',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.teacherId;

        const user = await User.findById(userId);
        if (!user) throw new Error('Invalid URL');
        return true;
      }),
  ],
  studentControllers.webauthnRegVerification,
);

router.post(
  '/webauthn-login',
  [
    body(
      ['teacherId', 'sessionId', 'progId', 'courseId', 'matricNumber'],
      'Invalid URL',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.teacherId;

        const user = await User.findById(userId);
        if (!user) throw new Error('Invalid URL');
        return true;
      }),
  ],
  studentControllers.webauthnLogin,
);

router.post(
  '/webauthn-login-verification',
  [
    body(
      [
        'teacherId',
        'sessionId',
        'progId',
        'courseId',
        'recordId',
        'attendanceId',
        'token',
      ],
      'Invalid URL',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.teacherId;

        const user = await User.findById(userId);
        if (!user) throw new Error('Invalid URL');
        return true;
      }),
    body('status')
      .trim()
      .custom((value) => {
        if (value != 'true' && value != 'false') {
          throw new Error('Invalid status');
        }

        return true;
      }),
  ],
  studentControllers.webauthnLoginVerification,
);

router.post(
  '/attendance',
  [
    body(
      ['userId', 'sessionId', 'progId', 'courseId', 'recordId'],
      'INVALID_LINK',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.userId;

        const user = await User.findById(userId);
        if (!user) throw new Error('INVALID_LINK');
        return true;
      }),
    body('coordinates').custom((value) => {
      if (
        typeof value['lat'] != 'number' ||
        typeof value['lat'] != 'number' ||
        typeof value['accuracy'] != 'number' ||
        !value['lat'] ||
        !value['lng']||
        !value['accuracy']
      ) {
        throw new Error('INVALID_COORD');
      }

      if (value['accuracy'] && value['accuracy'] > 50) {
        throw new Error(
          'INACCURATE_LOCATION',
        );
      }
      return true;
    }),
  ],
  studentControllers.postStudentAttendance,
);

module.exports = router;
