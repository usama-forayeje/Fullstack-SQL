import cookieParser from 'cookie-parser';
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';

// Import all routes
import userRouter from './routes/auth.route.js';

const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

// Middleware Setup
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.BASE_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Connection',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Origin',
    ],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to the server',
  });
});

app.use('/api/v1/users', userRouter);

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
