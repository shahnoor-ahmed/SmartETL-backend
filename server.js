const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const csvParser = require("csv-parser");
const xlsx = require("xlsx");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || "my_secret";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/etltool";

const corsOptions = {
  origin: "http://localhost:5173",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions)); 

app.use(express.json());

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

let previewData = [];

// Multer setup for file upload
const upload = multer({ dest: "uploads/" });

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashed });
    await newUser.save();
    res.sendStatus(200);
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ email }, SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/validate", authenticate, (req, res) => {
  res.status(200).json({ valid: true });
});

app.post("/api/upload", authenticate, upload.single("file"), (req, res) => {
  const file = req.file;
  const ext = path.extname(file.originalname);

  previewData = [];

  if (ext === ".csv") {
    let full_data = []
    fs.createReadStream(file.path)
      .pipe(csvParser())
      .on("data", (row) => {
        full_data.push(row)
        if (previewData.length < 20) previewData.push(row);
      })
      .on("end", () => {
        fs.unlinkSync(file.path);
        res.json({ preview: previewData, full_data: full_data});
      });
  } else if (ext === ".xlsx") {
    const workbook = xlsx.readFile(file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const json = xlsx.utils.sheet_to_json(sheet);
    const data = json.slice(0, 20);
    fs.unlinkSync(file.path);
    res.json({ preview: data, full_data: json.slice(0, 100) });
  } else {
    fs.unlinkSync(file.path);
    res.status(400).json({ error: "Unsupported file type" });
  }
});

app.get("/api/download", authenticate, (req, res) => {
  if (!previewData.length) {
    return res.status(400).json({ error: "No data available to download" });
  }

  const headers = Object.keys(previewData[0]);
  const csvContent = [headers.join(",")]
    .concat(
      previewData.map((row) =>
        headers.map((h) => JSON.stringify(row[h] || "")).join(",")
      )
    )
    .join("\n");

  fs.writeFileSync("output.csv", csvContent);
  res.download("output.csv", "cleaned_data.csv", () => {
    fs.unlinkSync("output.csv");
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
