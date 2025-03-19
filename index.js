import cookieParser from "cookie-parser";
import express from "express";
import dotenv from "dotenv";
import cors from "cors";

// import all routes
import userRouter from "./routes/auth.route.js"; 

const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Welcome to the server"
  })
});


app.use("/api/v1/users",userRouter)
app.use(cookieParser());
app.use(cors({
  origin: "http://localhost:5173",
  Credential: true,
  method: ["GET", "POST", "PUT", "DELETE", "PATH", "OPTIONS"],
  allowedHeaders: "Connection, X-Requested-With, Content-Type, Accept, Origin,",
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
