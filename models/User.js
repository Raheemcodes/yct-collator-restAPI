const mongoose = require('mongoose');
const { default: base64url } = require('base64url');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  webauthn: {
    challenge: String,
    resetChallengeExpiration: Date,
    credentialID: String,
    credentialPublicKey: String,
  },
  sessions: [
    {
      title: {
        type: String,
        required: true,
      },
      programmes: [
        {
          title: { type: String, required: true },
          courses: [
            {
              title: { type: String, required: true },
              students: [
                {
                  name: String,
                  matricNumber: { type: String, required: true },
                  isRegistered: { type: Boolean, required: true },
                  webauthn: {
                    challenge: String,
                    resetChallengeExpiration: Date,
                    credentialID: String,
                    credentialPublicKey: String,
                  },
                },
              ],
              attendanceRecords: [
                {
                  date: { type: String, required: true },
                  token: { type: String, required: true },
                  tokenResetExpiration: { type: Date, required: true },
                  coordinates: {
                    lat: Number,
                    lng: Number,
                    accuracy: Number,
                  },
                  attendance: [
                    {
                      name: String,
                      matricNumber: { type: String, required: true },
                      isRegistered: { type: Boolean, required: true },
                      status: { type: String, required: true },
                    },
                  ],
                },
              ],
              aggregateAttendance: [
                {
                  name: String,
                  matricNumber: { type: String, required: true },
                  timesPresent: { type: Number, required: true },
                },
              ],
            },
          ],
        },
      ],
    },
  ],
});

userSchema.methods.addSession = function (
  sessionTitle,
  program,
  course,
  firstMatric,
  indexNumber,
  totalStudent,
) {
  let students = [];
  let aggregate = [];

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const student = { matricNumber, isRegistered: false };
    students.push(student);
  }

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const student = { matricNumber, timesPresent: 0 };
    aggregate.push(student);
  }

   this.sessions.push({
    title: sessionTitle,
    programmes: [
      {
        title: program,
        courses: [
          {
            title: course,
            students,
            aggregateAttendance: aggregate,
          },
        ],
      },
    ],
  });

  this.save();
};

userSchema.methods.addProgramme = function (
  sessionTitle,
  program,
  course,
  firstMatric,
  indexNumber,
  totalStudent,
) {
  const sessionIdx = this.sessions.findIndex(
    (session) => session.title == sessionTitle,
  );

  const progIdx = this.sessions[sessionIdx].programmes.findIndex(
    (programme) => programme.title == program,
  );

  let courseIdx = -1;

  if (progIdx > -1) {
    courseIdx = this.sessions[sessionIdx].programmes[progIdx].courses.findIndex(
      ({ title }) => title == course,
    );
  }

  if (sessionIdx == -1 || courseIdx > -1) {
    const error = new Error('invalid session or course already exist!');
    error.statusCode = 401;
    throw error;
  }

  let students = [];
  let aggregate = [];

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const student = { matricNumber, isRegistered: false };
    students.push(student);
  }

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const student = { matricNumber, timesPresent: 0 };
    aggregate.push(student);
  }

  if (progIdx == -1) {
    const programmes = [
      ...this.sessions[sessionIdx].programmes,
      {
        title: program,
        courses: [
          {
            title: course,
            students: students,
            aggregateAttendance: aggregate,
          },
        ],
      },
    ];

    this.sessions[sessionIdx].programmes = programmes;
  }

  if (progIdx > -1 && courseIdx == -1) {
    const courses = [
      ...this.sessions[sessionIdx].programmes[progIdx].courses,
      {
        title: course,
        students: students,
        aggregateAttendance: aggregate,
      },
    ];

    this.sessions[sessionIdx].programmes[progIdx].courses = courses;
  }

  this.save();
};

userSchema.methods.createAttendance = function (
  session,
  programme,
  course,
  token,
  tokenResetExpiration,
  coordinates,
) {
  const foundSession = this.sessions.find((sess) => sess.title == session);

  const foundProgramme = foundSession.programmes.find(
    (prog) => prog.title == programme,
  );

  const foundCourse = foundProgramme.courses.find(
    (cour) => cour.title == course,
  );

  const attendance = [...foundCourse.students].map((student) => {
    return {
      matricNumber: student.matricNumber,
      isRegistered: student.isRegistered,
      status: 'Absent',
    };
  });

  const attendanceRecords = [
    ...foundCourse.attendanceRecords,
    {
      date: new Date().toLocaleString(),
      token,
      tokenResetExpiration,
      attendance,
      coordinates,
    },
  ];

  foundCourse.attendanceRecords = attendanceRecords;
  const last = foundCourse.attendanceRecords.length - 1;

   this.save();

  return {
    sessionId: foundSession._id,
    programmeId: foundProgramme._id,
    courseId: foundCourse._id,
    attendanceRecordId: foundCourse.attendanceRecords[last]._id,
  };
};

userSchema.methods.modifyProgramme = function (
  sessionId,
  progId,
  newTitle,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  const hasTitle = hasSession.programmes.some((prog) => prog.title == newTitle);

  if (hasTitle) {
    const error = new Error('TITLE_EXIST');
    error.statusCode = 401;
    throw error;
  }

  const programme = hasSession.programmes.find((prog) => prog._id == progId);

  if (!programme) {
    const error = new Error('PROG_NOT_FOUND');
    error.statusCode = 401;
    throw error;
  }

  programme.title = newTitle;
  this.save();
};

userSchema.methods.deleteProgramme = function (sessionId, progId) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  if (!hasSession) {
    const error = new Error('Record not found');
    error.statusCode = 401;
    throw error;
  }

  const updatedProg = hasSession.programmes.filter(
    (prog) => prog._id != progId,
  );

  hasSession.programmes = updatedProg;

  this.save();
};

userSchema.methods.modifyCourse = function (
  sessionId,
  progId,
  courseId,
  newTitle,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );
  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);
  const course = hasProgramme.courses.find((cour) => cour._id == courseId);

  if (!course) {
    const error = new Error('COURSE_NOT_FOUND');
    error.statusCode = 401;
    throw error;
  }

  const hasTitle = hasProgramme.courses.some(
    (course) => course.title == newTitle,
  );

  if (hasTitle) {
    const error = new Error('TITLE_EXIST');
    error.statusCode = 401;
    throw error;
  }

  course.title = newTitle;
};

userSchema.methods.deleteCourse = function (
  sessionId,
  progId,
  courseId,
  updatedCourses,
) {
  const hasSession = this.sessions.find((session) => session._id == sessionId);
  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);
  const course = hasProgramme.courses.find((cour) => cour._id == courseId);

  if (!course) {
    const error = new Error('COURSE_NOT_FOUND');
    error.statusCode = 401;
    throw error;
  }

  return updatedCourses.filter((course) => course._id != courseId);
};

userSchema.methods.findStudent = function (
  sessionId,
  progId,
  courseId,
  matricNumber,
  clientDataJSON,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);

  const hasCourse = hasProgramme.courses.find((cour) => cour._id == courseId);

  let student;
  if (!clientDataJSON) {
    student = hasCourse.students.find(
      (student) => student.matricNumber == matricNumber,
    );
  } else {
    student = hasCourse.students.find((student) => {
      if (
        student.webauthn.challenge ==
          base64url.decode(clientDataJSON.challenge) &&
        student.webauthn.resetChallengeExpiration > Date.now()
      ) {
        return student;
      }
    });
  }

  if (!student) {
    const error = new Error('User not found');
    error.statusCode = 401;
    throw error;
  }

  return student;
};

userSchema.methods.findAttendanceLine = function (
  sessionId,
  progId,
  courseId,
  recordId,
  id,
  token,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);

  const hasCourse = hasProgramme.courses.find((cour) => cour._id == courseId);

  const attendanceRecord = hasCourse.attendanceRecords.find(
    (record) => record._id == recordId,
  );

  if (!attendanceRecord) {
    const error = new Error('Invalid Link');
    error.statusCode = 401;
    throw error;
  }

  if (attendanceRecord.token !== token && token) {
    const error = new Error('Invalid Link');
    error.statusCode = 401;
    throw error;
  }

  if (new Date(attendanceRecord.tokenResetExpiration) < new Date() && token) {
    const error = new Error('Link has expired');
    error.statusCode = 401;
    throw error;
  }

  const attendanceLine = attendanceRecord.attendance.find(
    (student) => student._id == id,
  );

  return { attendanceLine, attendanceRecord };
};

userSchema.methods.findAttendanceRecord = function (
  sessionId,
  progId,
  courseId,
  recordId,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);

  const hasCourse = hasProgramme.courses.find((cour) => cour._id == courseId);

  const attendanceRecord = hasCourse.attendanceRecords.find(
    (record) => record._id == recordId,
  );

  return attendanceRecord;
};

userSchema.methods.markAttendance = function (
  sessionId,
  progId,
  courseId,
  recordId,
  id,
  status,
  token,
) {
  const hasSession =  this.sessions.find(
    (session) => session._id == sessionId,
  );

  const hasProgramme = hasSession.programmes.find((prog) => prog._id == progId);

  const hasCourse = hasProgramme.courses.find((cour) => cour._id == courseId);

  const attendanceRecord = hasCourse.attendanceRecords.find(
    (record) => record._id == recordId,
  );

  if (!attendanceRecord) {
    const error = new Error('Invalid Link');
    error.statusCode = 401;
    throw error;
  }

  if (attendanceRecord.token !== token && token) {
    const error = new Error('Invalid Link');
    error.statusCode = 401;
    throw error;
  }

  if (new Date(attendanceRecord.tokenResetExpiration) < new Date() && token) {
    const error = new Error('Link has expired');
    error.statusCode = 401;
    throw error;
  }

  const attendanceLine = attendanceRecord.attendance.find(
    (student) => student._id == id,
  );

  const aggregateLine = hasCourse.aggregateAttendance.find(
    (aggregate) => aggregate.matricNumber == attendanceLine.matricNumber,
  );

  if (
    (status == 'true' && attendanceLine.status == 'Absent') ||
    (status == 'false' && attendanceLine.status == 'Present')
  ) {
    if (status == 'true') {
      attendanceLine.status = 'Present';
      aggregateLine.timesPresent++;
    } else {
      attendanceLine.status = 'Absent';
      aggregateLine.timesPresent--;
    }
  }
  this.save();

  return attendanceRecord;
};

module.exports = mongoose.model('User', userSchema);
