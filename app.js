const express = require('express');
const { default: helmet } = require('helmet');
const mongoose = require('mongoose');

const app = express();
const authRoutes = require('./routes/auth');
const attendanceRoutes = require('./routes/attendance');
const studentRoutes = require('./routes/student');

app.use();

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.ACCESS_ORIGIN);
  res.setHeader(
    'Access-Control-Allow-Methods',
    'OPTIONS, GET, POST, PUT, PATCH, DELETE'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') res.sendStatus(204);
  else next();
});

app.use(authRoutes);
app.use(attendanceRoutes);
app.use('/student', studentRoutes);

app.use((error, req, res, next) => {
  const status = error.statusCode || 500;
  const message = error.message;
  console.log(error.message);
  res.status(status).json({ message });
});

mongoose
  .connect(
    `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.u4041.mongodb.net/${process.env.MONGO_DEFAULT_DATABASE}`
  )
  .then(() => {
    console.log('Database connected succcessfully');
    app.listen(process.env.PORT || 3000);
  })
  .catch((err) => {
    console.log(err);
  });
