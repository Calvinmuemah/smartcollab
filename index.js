require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const connectDB = require("./config/DB");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
// const { GoogleGenerativeAI } = require("@google/generative-ai");
const authMiddleware = require("./middlewares/AuthMiddlewares");
const AuthRoutes = require("./Routes/AuthRoutes")
const { verify } = require("crypto");


const PORT = process.env.PORT;

// Connect to DB
connectDB();

const app = express();
app.use(express.json({ limit: "5mb" }));

app.use(cors());
// app.options('*', cors());

app.use(cors({
  origin: "*",
  // methods: ['GET', 'POST',"PUT", "DELETE"],
}));



// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});



 
app.use("/api", AuthRoutes);


app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

