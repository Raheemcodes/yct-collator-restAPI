const express = require('express');
const attendanceController = require('../controllers/attendance');
const { body } = require('express-validator');

const isAuth = require('../middleware/is-auth');

const router = express.Router();

router.get('/sessions', isAuth, attendanceController.getSessions);

router.post(
  '/create-record',
  isAuth,
  [
    body(
      ['session', 'programme', 'course', 'firstMatric'],
      'Some fields are empty',
    )
      .trim()
      .isLength({ min: 1 }),
    body(['indexNumber', 'totalStudent'], 'Some fields are empty')
      .trim()
      .isNumeric()
      .custom((value, { req }) => {
        if (value < 1) throw new Error('minium of 1 student required');
        if (req.body.totalStudent > 500)
          throw new Error('maximum of 500 students');
        return true;
      }),
  ],
  attendanceController.createRecord,
);

router.post(
  '/modify-record',
  isAuth,
  [
    body(
      ['session', 'programme', 'course', 'firstMatric'],
      'Some fields are empty',
    )
      .trim()
      .isLength({ min: 1 }),
    body(['indexNumber', 'totalStudent'], 'Some fields are empty')
      .trim()
      .isNumeric()
      .custom((value, { req }) => {
        if (value < 1) throw new Error('minium of 1 student required');
        if (req.body.totalStudent > 500)
          throw new Error('maximum of 500 students');
        return true;
      }),
  ],
  attendanceController.modifyRecord,
);

module.exports = router;
