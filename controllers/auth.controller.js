import { PrismaClient } from '@prisma/client';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

const registerUser = async (req, res) => {
  // get data from request body
  const { email, password, name } = req.body;

  // check if any field is missing
  if (!email || !password || !name) {
    return res.status(400).json({
      success: false,
      message: 'Please provide all required fields',
    });
  }

  console.log(name, email, password);

  try {
    // check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists',
      });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create random token for email verification
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // create user in database
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        verificationToken,
      },
    });

    // setup mail transporter
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      secure: false,
      auth: {
        user: process.env.MAILTRAP_USERNAME,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    // mail options
    const mailOption = {
      from: process.env.MAILTRAP_SENDER_ADDRESS,
      to: user.email,
      subject: 'Verify Your Account',
      text: `Please verify your email by clicking on this link: ${process.env.BASE_URL}/api/v1/users/verify/${verificationToken}`,
    };

    // send email
    await transporter.sendMail(mailOption);

    // send success response
    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please verify your email.',
    });
  } catch (error) {
    console.error('Registration Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message,
    });
  }
};

const verifyUser = async (req, res) => {
  try {
    // get token from URL parameters
    const { token } = req.params;
    console.log('Received Token: ', token); // Logging token

    // validate token
    if (!token) {
      return res.status(400).json({
        message: 'Invalid Validation Token',
      });
    }

    // Find the user with the provided verification token
    const user = await prisma.user.findFirst({
      where: {
        verificationToken: token,
      },
    });

    console.log('Found User: ', user); // Logging user found from DB

    if (!user) {
      return res.status(400).json({
        message: 'User not found',
      });
    }

    // Update the user to validated and remove verification token
    const updatedUser = await prisma.user.update({
      where: {
        id: user.id, // Use 'id' instead of 'email' for better security
      },
      data: {
        isVerified: true,
        verificationToken: null, // Remove the token after successful verification
      },
    });

    console.log('Updated User: ', updatedUser); // Logging the updated user

    // send success response
    res.status(200).json({
      message: 'User verified successfully',
      success: true,
    });
  } catch (error) {
    console.error('Verification Error:', error.message); // Log the actual error message
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

const loginUser = async (req, res) => {
  try {
    // get data from request body
    const { email, password } = req.body;

    // check if any field is missing
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields',
      });
    }

    // check if user exists
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    // if user not found
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // check if password is correct
    const matchPassword = await bcrypt.compare(password, user.password); // Fixed typo here

    if (!matchPassword) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // check if user is verified
    if (!user.isVerified) {
      return res.status(400).json({
        success: false,
        message: 'User is not verified',
      });
    }

    // create JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '2d', // Token expiry time is 2 days
    });

    console.log(token);

    // set token in cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    // send success status to user
    res.status(200).json({
      message: 'User logged in successfully',
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (error) {
    console.error('Login Error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};

const logoutUser = async (req, res) => {
  try {
    // clear cookie
    res.cookie('token', null, {
      httpOnly: true,
      expires: new Date(0), // Set the cookie to expire immediately
    });

    // send success status to user
    res.status(200).json({
      message: 'User logged out successfully',
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    // check if email is provided
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email',
      });
    }

    // check if user exists
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    // if user not found
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }

    // create random token
    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log(resetToken);

    // update user with token
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpiry: new Date(Date.now() + 3600000), // 1 hour expiry (adjust as necessary)
      },
    });

    // send token to user email
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      secure: false,
      auth: {
        user: process.env.MAILTRAP_USERNAME,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    const mailOption = {
      from: process.env.MAILTRAP_SENDER_ADDRESS,
      to: user.email,
      subject: 'Password Reset Request',
      text: `Please click on the following link to reset your password: ${process.env.BASE_URL}/api/v1/users/reset/${resetToken}`, // resetToken is now used
    };

    const mail = await transporter.sendMail(mailOption);

    console.log(mail);

    // send success status to user
    res.status(200).json({
      message: 'Reset password link sent to your email',
      success: true,
    });
  } catch (error) {
    console.error('Forgot Password Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { password, token } = req.body;

    // Check if password is provided
    if (!password || password.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Please provide password',
      });
    }

    // Check if token is provided
    if (!token || token.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Please provide token',
      });
    }

    // Find user by passwordResetToken
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token, // Search for user by token
      },
    });

    // If user not found, return error
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if token has expired
    if (new Date(user.passwordResetExpiry).getTime() < new Date().getTime()) {
      return res.status(400).json({
        success: false,
        message: 'Reset token has expired',
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10); // Use bcrypt to hash the password

    // Update the user's password and clear the reset token and expiry
    await prisma.user.update({
      where: {
        id: user.id, // Identify the user by their ID
      },
      data: {
        password: hashedPassword,
        passwordResetToken: null, // Remove the reset token
        passwordResetExpiry: null, // Remove the reset token expiry
      },
    });

    // Send a success response
    res.status(200).json({
      success: true,
      message:
        'Password reset successfully. Please login with your new password.',
    });
  } catch (error) {
    // Handle any errors and send a generic error response
    console.error('Reset Password Error:', error); // Log error
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};

const userProfile = async (req, res) => {
  try {
    // get user id from token
    const userId = req.user.id;

    // get user from database
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    // if user not found
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }

    // send user data to client
    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (error) {
    console.error('User Profile Error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};

const adminDashboard = async (req, res) => {
  try {
    // Get user ID from the decoded JWT token (req.user is set by the isLoggedIn middleware)
    const userId = req.user.id;

    // Find the user in the database using the user ID
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    // If user not found, return an error
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Send success response with user data
    res.status(200).json({
      success: true,
      message: `Welcome to the Admin Dashboard, ${user.name}`,
      user: user,
    });
  } catch (error) {
    // Log error and send failure response
    res.status(500).json({
      success: false,
      message: "Something went wrong in Admin Dashboard",
      error: error.message,
    });
  }
};

export {
  loginUser,
  registerUser,
  verifyUser,
  logoutUser,
  resetPassword,
  forgotPassword,
  userProfile,
  adminDashboard,
};
