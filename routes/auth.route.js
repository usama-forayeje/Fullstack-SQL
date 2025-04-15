import express from 'express';
import {
  adminDashboard,
  forgotPassword,
  loginUser,
  logoutUser,
  registerUser,
  resetPassword,
  userProfile,
  verifyUser,
} from '../controllers/auth.controller.js';
import { authorizeRoles, isLoggedIn } from '../middlewares/auth.middleware.js';

const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/logout', isLoggedIn, logoutUser);

userRouter.get('/verify/:token', verifyUser);
userRouter.post('/forgotPassword', forgotPassword);
userRouter.post('/resetPassword/:token', resetPassword);

userRouter.get('/userProfile', isLoggedIn, userProfile);

userRouter.get(
  '/dashboard',
  isLoggedIn,
  authorizeRoles('admin'),
  adminDashboard
);

export default userRouter;
