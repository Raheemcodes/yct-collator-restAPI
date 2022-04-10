const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const cbor = require('cbor');
const { default: base64url } = require('base64url');

const User = require('../models/user');

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

    res.status(201).send({ message: 'Session successfully created' });
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
