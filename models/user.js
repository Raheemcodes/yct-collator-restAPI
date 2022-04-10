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
                  date: { type: Date, required: true },
                  attendance: [
                    {
                      name: { type: String, required: true },
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
    const matricNumber = firstMatric + (indexNumber + i);
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
    const matricNumber = firstMatric + (indexNumber + i);
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

    return programmes
  }

  if (progIdx > -1 && courseIdx == -1) {
    console.log(course);
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

module.exports = mongoose.model('User', userSchema);
