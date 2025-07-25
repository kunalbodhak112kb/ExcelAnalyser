const express = require("express");
const port = 5000;
const app = express();
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const XLSX = require("xlsx");

require("dotenv").config();
const upload = multer({ dest: "uploads/" });

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"))); // for static CSS/images

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "/views"));

// MongoDB Connection
async function main() {
  await mongoose.connect(process.env.CONNECTION_STRING);
}
main()
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error(err));

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ["admin", "user"] },
});
const User = mongoose.model("User", userSchema);

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  originalName: String,
  filename: String,
  data: [{}],
  uploadedAt: { type: Date, default: Date.now },
});
const History = mongoose.model("History", historySchema);

// Auth Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, "my-secret-key");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
};

// Routes
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword, role });
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).send("Registration failed.");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send("User not found");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Incorrect password");
    if (role !== user.role) return res.status(403).send("Role mismatch");

    const token = jwt.sign({ id: user._id, role: user.role }, "my-secret-key", {
      expiresIn: "1h",
    });
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 3600000,
    });
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Login failed.");
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.get("/dashboard", verifyToken, authorizeRoles("admin", "user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  res.render("dashboard", { user, role: req.user.role });
});

app.get("/upload", verifyToken, authorizeRoles("admin", "user"), (req, res) => {
  res.render("upload");
});

// 🔥 Upload Excel & Generate Charts
app.post("/chart", verifyToken, upload.single("excel"), async (req, res) => {
  try {
    const workbook = XLSX.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const jsonData = XLSX.utils.sheet_to_json(sheet);

    await History.create({
      userId: req.user.id,
      originalName: req.file.originalname,
      filename: req.file.filename,
      data: jsonData,
    });

    res.render("charts", { data: jsonData });
  } catch (err) {
    console.error("Chart generation error:", err);
    res.status(500).send("Chart generation failed.");
  }
});

app.get("/history", verifyToken, async (req, res) => {
  const uploads = await History.find({ userId: req.user.id }).sort({ uploadedAt: -1 });
  res.render("history", { uploads });
});

app.post("/view-chart", verifyToken, authorizeRoles("admin", "user"), async (req, res) => {
  const upload = await History.findById(req.body.id);
  if (!upload || upload.userId.toString() !== req.user.id) {
    return res.status(403).send("Access denied");
  }
  res.render("charts", { data: upload.data });
});

app.get("/admin", verifyToken, authorizeRoles("admin"), (req, res) => {
  res.render("admin_panel");
});
app.get("/admin/modify", verifyToken, authorizeRoles("admin"), (req, res) => {
  res.send("Modify users page coming soon!");
});
app.get("/admin/history", verifyToken, authorizeRoles("admin"), async (req, res) => {
  const uploads = await History.find().populate("userId").sort({ uploadedAt: -1 });
  res.render("admin_history", { uploads });
});

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
