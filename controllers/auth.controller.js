const registerUser = async (req, res) => {
  // Get the user data from the request body
  const { name, email, password } = req.body;

  // check if the user already exists
};

const loginUser = async (req, res) => {};

const verifyUser = async (req, res) => {};

const logoutUser = async (req, res) => {};

const userProfile = async (req, res) => {};

const forgotPassword = async (req, res) => {};

const resetPassword = async (req, res) => {};

export {loginUser,registerUser,verifyUser,logoutUser,resetPassword,forgotPassword,userProfile}
