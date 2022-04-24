const express = require('express');
const attendanceController = require('../controllers/attendance');
const { body } = require('express-validator');

const isAuth = require('../middleware/is-auth');
const User = require('../models/User');

const router = express.Router();

router.get('/sessions', isAuth, attendanceController.getSessions);

router.post(
  '/create-attandance',
  isAuth,
  [
    body(['session', 'programme', 'course'], 'Some fields are invalid')
      .trim()
      .isLength({ min: 2 })
      .custom(async (value, { req }) => {
        const user = await User.findById(req.userId);
        const sessionTitle = req.body.session;
        const programme = req.body.programme;
        const course = req.body.course;

        const hasSession = await user.sessions.find(
          (session) => session.title == sessionTitle,
        );

        const hasProgramme = await hasSession.programmes.find(
          (prog) => prog.title == programme,
        );

        const hasCourse = hasProgramme.courses.find(
          (cour) => cour.title == course,
        );

        if (!hasCourse) throw new Error('Some fields are not in record!');

        if (hasCourse.attendanceRecords.length == 0) return true;

        const lastItem = hasCourse.attendanceRecords.length - 1;
        if (
          hasCourse.attendanceRecords[lastItem].date.includes(
            new Date().toLocaleDateString(),
          )
        ) {
          throw new Error(`One attendance per day for a course`);
        }

        return true;
      }),
    body(['hours', 'minutes'], 'Some fields are invalid').isNumeric(),
  ],
  attendanceController.createAttendance,
);

router.post(
  '/student-attendance',
  [
    body(
      ['userId', 'sessionId', 'progId', 'courseId', 'recordId'],
      'Invalid Link',
    )
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const userId = req.body.userId;

        const user = await User.findById(userId);
        if (!user) throw new Error('Invalid Link');
        return true;
      }),
  ],
  attendanceController.postStudentAttendance,
);

router.post(
  '/mark-attendance',
  isAuth,
  [
    body(['sessionId', 'progId', 'courseId', 'recordId', 'id'], 'Invalid URL')
      .trim()
      .isLength({ min: 12 })
      .custom(async (value, { req }) => {
        const user = await User.findById(req.userId);

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
  attendanceController.markAttendance,
);

router.post(
  '/create-record',
  isAuth,
  [
    body(
      ['session', 'programme', 'course', 'firstMatric'],
      'Some fields are empty',
    )
      .trim()
      .isLength({ min: 2 }),
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
