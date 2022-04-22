const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

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
                  password: {
                    type: String,
                    required: true,
                  },
                  challenge: String,
                  resetChallengeExpiration: Date,
                  credentialID: String,
                  credentialPublicKey: String,
                },
              ],
              attendanceRecords: [
                {
                  date: { type: String, required: true },
                  token: { type: String, required: true },
                  tokenResetExpiration: { type: Date, required: true },
                  attendance: [
                    {
                      name: String,
                      matricNumber: { type: String, required: true },
                      status: { type: String, required: true },
                    },
                  ],
                },
              ],
              aggregateAttendance: [],
            },
          ],
        },
      ],
    },
  ],
});

userSchema.methods.addSession = async function (
  sessionTitle,
  program,
  course,
  firstMatric,
  indexNumber,
  totalStudent,
) {
  let students = [];

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const hashedPassword = await bcrypt.hash(matricNumber, 12);
    const student = { matricNumber, password: hashedPassword };
    students.push(student);
  }

  await this.sessions.push({
    title: sessionTitle,
    programmes: [
      {
        title: program,
        courses: [
          {
            title: course,
            students: students,
          },
        ],
      },
    ],
  });

  this.save();
};

userSchema.methods.addProgramme = async function (
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

  for (let i = 0; i < totalStudent; i++) {
    const matricNumber = firstMatric + (+indexNumber + i);
    const hashedPassword = await bcrypt.hash(matricNumber, 12);
    const student = { matricNumber, password: hashedPassword };
    students.push(student);
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
      },
    ];

    this.sessions[sessionIdx].programmes[progIdx].courses = courses;
  }

  this.save();
};

userSchema.methods.createAttendance = async function (
  session,
  programme,
  course,
  token,
  tokenResetExpiration,
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
    },
  ];

  foundCourse.attendanceRecords = attendanceRecords;
  const last = foundCourse.attendanceRecords.length - 1;

  await this.save();

  return {
    sessionId: foundSession._id,
    programmeId: foundProgramme._id,
    courseId: foundCourse._id,
    attendanceRecordId: foundCourse.attendanceRecords[last]._id,
  };
};

userSchema.methods.markAttendance = async function (
  sessionId,
  progId,
  courseId,
  recordId,
  id,
  status,
  token,
) {
  const hasSession = await this.sessions.find(
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


  status == 'true'
    ? (attendanceLine.status = 'Present')
    : (attendanceLine.status = 'Absent');

  this.save();

  return attendanceRecord;
};

module.exports = mongoose.model('User', userSchema);
