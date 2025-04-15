import jwt from 'jsonwebtoken';

export const isLoggedIn = (req, res, next) => {
  try {
    // Token read from cookie
    const token = req.cookies?.token;

    // If no token found
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'You need to log in to access this route',
      });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user data to request
    req.user = decoded;

    next(); // Proceed to next middleware
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token',
      error: error.message,
    });
  }
};

export const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    try {
      // ✅ logged in user এর role পাওয়া হবে (isLoggedIn middleware এটা আগে set করবে)
      const userRole = req.user.role;

      // ✅ যদি user এর role allowed না হয়
      if (!allowedRoles.includes(userRole)) {
        return res.status(403).json({
          success: false,
          message: `Access denied for role: ${userRole}`,
        });
      }

      // ✅ যদি role ঠিক থাকে, তাহলে পরবর্তী middleware/controller এ যাবে
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: 'Role authorization failed',
        error: error.message,
      });
    }
  };
};
