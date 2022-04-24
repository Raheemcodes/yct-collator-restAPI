const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const cbor = require('cbor');
const { default: base64url } = require('base64url');

const User = require('../models/User');

exports.getSessions = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const user = await User.findById(req.userId);

    res.status(201).send({ sessions: user.sessions });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.postStudentAttendance = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const userId = req.body.userId;
    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const recordId = req.body.recordId;
    const token = req.body.token;

    const user = await User.findById(userId);

    const hasSession = await user.sessions.find(
      (session) => session._id == sessionId,
    );

    const hasProgramme = await hasSession.programmes.find(
      (prog) => prog._id == progId,
    );

    const hasCourse = hasProgramme.courses.find((cour) => cour._id == courseId);

    const attendanceRecord = hasCourse.attendanceRecords.find(
      (record) => record._id == recordId,
    );

    if (!attendanceRecord) {
      const error = new Error('Invalid Link');
      error.statusCode = 401;
      throw error;
    }

    if (attendanceRecord.token !== token) {
      const error = new Error('Invalid Link');
      error.statusCode = 401;
      throw error;
    }

    if (new Date(attendanceRecord.tokenResetExpiration) < new Date()) {
      const error = new Error('Link has expired');
      error.statusCode = 401;
      throw error;
    }

    res.status(201).send({ attendanceRecord });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.createAttendance = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const session = req.body.session;
    const programme = req.body.programme;
    const course = req.body.course;
    const minutes = req.body.minutes;
    const hours = req.body.hours;
    const user = await User.findById(req.userId);

    crypto.randomBytes(32, async (err, buf) => {
      const token = buf.toString('hex');
      const tokenResetExpiration =
        Date.now() + +hours * 60 * 60 * 1000 + +minutes * 60 * 1000;

      const result = await user.createAttendance(
        session,
        programme,
        course,
        token,
        tokenResetExpiration,
      );

      res.status(201).send({ res: result, sessions: user.sessions });
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.markAttendance = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const sessionId = req.body.sessionId;
    const progId = req.body.progId;
    const courseId = req.body.courseId;
    const recordId = req.body.recordId;
    const token = req.body.token;
    const status = req.body.status;
    const id = req.body.id;
    const user = await User.findById(req.userId);

    await user.markAttendance(
      sessionId,
      progId,
      courseId,
      recordId,
      id,
      status,
      token,
    );

    res.status(201).send({ sessions: user.sessions });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.createRecord = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const sessionTitle = req.body.session.toUpperCase();
    const program = req.body.programme.toUpperCase();
    const course = req.body.course.toUpperCase();
    const firstMatric = req.body.firstMatric.toUpperCase();
    const indexNumber = req.body.indexNumber;
    const totalStudent = req.body.totalStudent;
    const user = await User.findById(req.userId);

    const hasSession = (sessionTitle) => {
      return user.sessions.find((session) => session.title == sessionTitle);
    };

    if (hasSession(sessionTitle)) {
      const error = new Error('This session already exists');
      error.statusCode = 401;
      throw error;
    }

    await user.addSession(
      sessionTitle,
      program,
      course,
      firstMatric,
      indexNumber,
      totalStudent,
    );

    res.status(201).send({ sessions: user.sessions });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.modifyRecord = async (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error(errors.array()[0].msg);
      error.statusCode = 422;
      throw error;
    }

    const sessionTitle = req.body.session.toUpperCase();
    const program = req.body.programme.toUpperCase();
    const course = req.body.course.toUpperCase();
    const firstMatric = req.body.firstMatric.toUpperCase();
    const indexNumber = req.body.indexNumber;
    const totalStudent = req.body.totalStudent;
    const user = await User.findById(req.userId);

    await user.addProgramme(
      sessionTitle,
      program,
      course,
      firstMatric,
      indexNumber,
      totalStudent,
    );

    res.status(201).send({ sessions: user.sessions });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
