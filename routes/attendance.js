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
    body(['session', 'programme', 'course'], 'INVALID_FIELD')
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

        if (!hasCourse) throw new Error('FIELD_NOT_FOUND');

        if (hasCourse.attendanceRecords.length == 0) return true;

        const lastItem = hasCourse.attendanceRecords.length - 1;
        if (
          hasCourse.attendanceRecords[lastItem].date.includes(
            new Date().toLocaleDateString(),
          )
        ) {
          throw new Error('ATTENDANCE_LIMIT_EXCEEDED');
        }

        return true;
      }),
    body(['hours', 'minutes'], 'INVALID_FIELD').isNumeric(),
    body('coordinates').custom((value) => {
      if (
        typeof value['lat'] != 'number' ||
        typeof value['lng'] != 'number' ||
        !value['lat'] ||
        !value['lng']
      ) {
        throw new Error('INVALID_COORD');
      }

      if (value['accuracy'] && value['accuracy'] > 50) {
        throw new Error('INACCURATE_LOCATION');
      }
      return true;
    }),
  ],
  attendanceController.createAttendance,
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
  '/add-record',
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
  attendanceController.addRecord,
);

router.post(
  '/modify-programme',
  isAuth,
  [
    body(['sessionId', 'programmeId', 'newTitle'], 'EMPTY_FIELD')
      .trim()
      .isLength({ min: 1 }),
  ],
  attendanceController.modifyProgramme,
);

router.post(
  '/modify-course',
  isAuth,
  [
    body(['sessionId', 'programmeId'], 'EMPTY_FIELD')
      .trim()
      .isLength({ min: 1 })
      .custom((value, { req }) => {
        const courses = req.body.courses;
        if (courses.length <= 0) throw new Error('COURSE_NOT_EDITTED');
        return true;
      }),
  ],
  attendanceController.modifyCourse,
);

router.post(
  '/delete-programme',
  isAuth,
  [
    body(['sessionId', 'programmeId'], 'Some fields are empty')
      .trim()
      .isLength({ min: 12 }),
  ],
  attendanceController.deleteProgramme,
);

router.post(
  '/delete-course',
  isAuth,
  [
    body(['sessionId', 'programmeId'], 'EMPTY_FIELD')
      .trim()
      .isLength({ min: 1 })
      .custom((value, { req }) => {
        const courses = req.body.courses;
        if (courses.length <= 0) throw new Error('COURSE_NOT_EDITTED');
        return true;
      }),
  ],
  attendanceController.deleteCourse,
);
// router.post(
//   '/post-coordinates',
//   isAuth,
//   [
//     body(
//       ['sessionId', 'programmeId', 'courseId', 'attendanceRecordId'],
//       'INVALID_DETAILS',
//     )
//       .trim()
//       .isLength({ min: 12 })
//       .custom(async (value, { req }) => {
//         const user = await User.findById(req.userId);

//         if (!user)
//           throw new Error('USER_NOT_FOUND');
//         return true;
//       }),
//     body('coordinates').custom((value) => {
//       if (
//         typeof value['lat'] != 'number' ||
//         typeof value['lat'] != 'number' ||
//         !value['lat'] ||
//         !value['lng']
//       ) {
//         throw new Error('INVALID-COORD');
//       }

//       if (value['accuracy'] && value['accuracy'] > 100) {
//         throw new Error(
//           'INACCURATE_LOCATION',
//         );
//       }
//       return true;
//     }),
//   ],
//   attendanceController.postCoordinate,
// );

module.exports = router;
