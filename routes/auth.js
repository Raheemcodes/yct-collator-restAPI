const express = require('express');

const User = require('./../models/User');

const { check, body } = require('express-validator');

const authController = require('../controllers/auth');

const router = express.Router();

router.post(
  '/signup',
  [
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email')
      .normalizeEmail()
      .custom(async (value, { req }) => {
        const userDoc = await User.findOne({ email: value });
        if (userDoc) {
          return Promise.reject('E-mail already exist!');
        }
        return userDoc;
      }),
    body('fullName', 'Enter Full Name')
      .trim()
      .isLength({ min: 5 })
      .custom((value) => {
        if (value.split(' ').length < 2) {
          throw new Error('Enter Full Name');
        }
        return true;
      }),
    body('password', 'Password not strong')
      .trim()
      .isLength({ min: 8 })
      .isAlphanumeric(),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords have to match');
      }
      return true;
    }),
  ],
  authController.signup,
);

router.post(
  '/login',
  [
    check('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Please enter a valid email'),
    body('password', 'Password has to be valid').trim().not().isEmpty(),
  ],
  authController.login,
);

router.post(
  '/webauthn-reg',
  [
    check('userId', 'Invalid user')
      .trim()
      .isLength({ min: 5 })
      .isAlphanumeric()
      .custom(async (value, { req }) => {
        const userDoc = await User.findById(value);
        if (!userDoc) {
          throw new Error('User not found');
        }
        return true;
      }),
  ],
  authController.webauthnReg,
);

router.post(
  '/webauthn-reg-verification',
  authController.webauthnRegVerification,
);

router.post(
  '/webauthn-login',
  [
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email')
      .normalizeEmail()
      .custom(async (value, { req }) => {
        const userDoc = await User.findOne({ email: value });
        if (!userDoc) {
          return Promise.reject('E-mail does not exist!');
        }
        return userDoc;
      }),
  ],
  authController.webauthnLogin,
);

router.post(
  '/webauthn-login-verification',
  [
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email')
      .normalizeEmail()
      .custom(async (value, { req }) => {
        const userDoc = await User.findOne({ email: value });
        if (!userDoc) {
          return Promise.reject('E-mail does not exist!');
        }
        return userDoc;
      }),
  ],
  authController.webauthnLoginVerification,
);

router.post(
  '/google-auth',
  [
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email')
      .normalizeEmail()
      .custom(async (value, { req }) => {
        const userDoc = await User.findOne({ email: value });
        if (!userDoc) {
          return Promise.reject('E-mail does not exist!');
        }
        return userDoc;
      }),
  ],
  authController.googleAuth,
);

module.exports = router;
