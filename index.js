const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const User = require("./models/UserModel");
const Message = require("./models/MessageModel");
const ws = require("ws");
const fs = require("fs");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const path = require("path");
const nodemailer = require("nodemailer");

dotenv.config();
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Successfully connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error.message);
    // Application can continue but log the error
  });

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

const app = express();
app.use(express.json());
app.use(cookieParser());

const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

app.use(cors(corsOptions));

let s3Client;
try {
  s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
  });
} catch (error) {
  console.error("Error initializing S3 client:", error.message);
  // Continue without S3 functionality
}

try {
  cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET,
  });
} catch (error) {
  console.error("Error initializing Cloudinary:", error.message);
  // Continue without Cloudinary functionality
}

let storage;
try {
  storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: "profile_images",
      allowed_formats: ["jpg", "jpeg", "png"],
    },
  });
} catch (error) {
  console.error("Error creating CloudinaryStorage:", error.message);
  // Fallback to local storage
  const uploadsDir = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
  storage = multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
    }
  });
}

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

const bucketName = process.env.AWS_S3_BUCKET_NAME;

async function uploadToS3(fileName, filePath) {
  if (!s3Client || !bucketName) {
    console.warn("S3 client or bucket name not configured, skipping S3 upload");
    return null;
  }

  try {
    const fileContent = fs.readFileSync(filePath);
    const command = new PutObjectCommand({
      Bucket: bucketName,
      Key: fileName,
      Body: fileContent,
    });

    await s3Client.send(command);

    const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
    // Clean up local file
    fs.unlink(filePath, (err) => {
      if (err) console.error("Error removing temporary file:", err.message);
    });
    return url.split("?")[0];
  } catch (err) {
    console.error("S3 upload error:", err.message);
    return null;
  }
}

async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token || 
                 (req.headers.authorization && req.headers.authorization.split(' ')[1]);
                 
    if (!token) {
      return reject(new Error("Authentication token not found"));
    }
    
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) {
        return reject(new Error("Invalid or expired token"));
      }
      resolve(userData);
    });
  });
}

app.get("/", (req, res) => {
  res.status(200).json({ status: "ok", message: "Server is running" });
});

app.get("/messages/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = await getUserDataFromRequest(req);
    const ourUserId = userData.userId;
    
    const messages = await Message.find({
      sender: { $in: [userId, ourUserId] },
      recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 });
    
    res.status(200).json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error.message);
    res.status(error.message.includes("token") ? 401 : 500)
       .json({ error: error.message || "Error fetching messages" });
  }
});

app.get("/people", async (req, res) => {
  try {
    const users = await User.find({}, { _id: 1, username: 1, profileImage: 1 });
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error.message);
    res.status(500).json({ error: "Error fetching users" });
  }
});

let transporter;
try {
  transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
} catch (error) {
  console.error("Error initializing email transporter:", error.message);
}

app.post("/register", upload.single("profileImage"), async (req, res) => {
  console.log("🟢 Incoming registration request");

  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  
  console.log("📝 Data received:", username, password, email);

  try {
    console.log("🔍 Checking if username exists...");
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      const field = existingUser.username === username ? "username" : "email";
      console.log(`❌ ${field} already exists`);
      return res.status(400).json({ error: `${field} already exists` });
    }

    console.log("🔐 Hashing password...");
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);

    const profileImageUrl = req.file ? req.file.path : "";
    console.log("📸 Profile image path:", profileImageUrl);

    console.log("🛠️ Creating user...");
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
      email: email,
      profileImage: profileImageUrl,
      isVerified: false,
    });
    
    console.log("🔑 Generating verification token...");
    jwt.sign(
      { userId: createdUser._id, username, email },
      jwtSecret,
      { expiresIn: '1d' },
      async (err, token) => {
        if (err) {
          console.log("❌ Error generating token:", err.message);
          return res.status(500).json({ error: "Error generating verification token" });
        }

        const verificationLink = `${process.env.FRONTEND_URL || "http://localhost:5173"}/verify-email?token=${token}`;
        console.log("📧 Sending verification email to:", email);
        
        // Skip email sending if transporter not configured
        if (!transporter) {
          console.warn("Email transporter not configured, skipping verification email");
          return res.status(201).json({ 
            message: "Registration successful. Email verification skipped (email service not configured).",
            userId: createdUser._id 
          });
        }

        try {
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your email address",
            html: `<p>Hi ${username},</p>
                   <p>Please click on the link below to verify your email address:</p>
                   <a href="${verificationLink}">Verify Email</a>`,
          });
          
          console.log("✅ Registration successful. Verification email sent.");
          res.status(201).json({ 
            message: "Registration successful. Please verify your email.",
            userId: createdUser._id 
          });
        } catch (emailErr) {
          console.error("Error sending verification email:", emailErr.message);
          // Mark user as verified if email sending fails
          createdUser.isVerified = true;
          await createdUser.save();
          res.status(201).json({ 
            message: "Registration successful, but verification email could not be sent. You can log in.",
            userId: createdUser._id 
          });
        }
      }
    );
  } catch (err) {
    console.error("Registration error:", err.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ error: "Missing token" });
  }

  try {
    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded);
      });
    });

    const { userId } = decoded;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: "Email successfully verified. You can now log in." });
  } catch (error) {
    console.error("Email verification error:", error.message);
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  
  console.log("Login request received for user:", username);

  try {
    const foundUser = await User.findOne({ username });

    if (!foundUser) {
      return res.status(404).json({ error: "User not registered" });
    }

    if (!foundUser.isVerified) {
      return res.status(401).json({ error: "Please verify your email before logging in" });
    }

    const passOk = bcrypt.compareSync(password, foundUser.password);

    if (!passOk) {
      return res.status(401).json({ error: "Invalid password" });
    }

    jwt.sign(
      { userId: foundUser._id, username },
      jwtSecret,
      { expiresIn: '30d' },
      (err, token) => {
        if (err) {
          console.error("Error generating JWT:", err.message);
          return res.status(500).json({ error: "Server error" });
        }

        res.cookie("token", token, { 
          sameSite: "none", 
          secure: true,
          httpOnly: false,
          maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
        }).status(200).json({
          id: foundUser._id,
          username: foundUser.username,
          token,
          userProfile: foundUser.profileImage,
        });
      }
    );
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "", { 
    sameSite: "none", 
    secure: true, 
    httpOnly: true,
    expires: new Date(0) 
  }).status(200).json({ message: "Logged out successfully" });
});

app.get("/profile", async (req, res) => {
  const authHeader = req.headers.authorization;

  // Log incoming request
  console.log("📩 Received request to /profile endpoint");

  // Check if Authorization header is present
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("⚠️ Unauthorized: No token provided");
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    console.log("🔑 Verifying token...");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("✅ Token verified successfully");

    console.log("🔍 Fetching user data...");
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      console.log("❌ User not found");
      return res.status(404).json({ error: "User not found" });
    }

    console.log("📤 Sending user data:", {
      userId: user._id,
      username: user.username,
      profileImage: user.profileImage,
    });
    res.status(200).json({
      userId: user._id,
      username: user.username,
      profileImage: user.profileImage,
    });
  } catch (error) {
    console.error("🚨 Error verifying token or fetching user data:", error);
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

const port = process.env.PORT || 8000;
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('Server error:', error.message);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use`);
    process.exit(1);
  }
});

// Handle process termination
process.on('SIGTERM', shutDown);
process.on('SIGINT', shutDown);

function shutDown() {
  console.log('Received kill signal, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
  
  // Force close if graceful shutdown fails
  setTimeout(() => {
    console.error('Forcing shutdown after timeout');
    process.exit(1);
  }, 10000);
}

const wss = new ws.WebSocketServer({ server });

wss.on("connection", (connection, req) => {
  function notifyAboutOnlinePeople() {
    try {
      const onlineClients = [...wss.clients].filter((client) => client.userId);
      [...wss.clients].forEach((client) => {
        if (client.readyState === ws.OPEN) {
          client.send(
            JSON.stringify({
              online: onlineClients.map((c) => ({
                userId: c.userId,
                username: c.username,
              })),
            })
          );
        }
      });
    } catch (error) {
      console.error("Error in notifyAboutOnlinePeople:", error.message);
    }
  }

  connection.isAlive = true;

  // Set up ping/pong mechanism
  connection.timer = setInterval(() => {
    if (connection.readyState !== ws.OPEN) {
      clearInterval(connection.timer);
      return;
    }
    
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
      console.log("Connection terminated due to inactivity");
    }, 1000);
  }, 5000);

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer);
  });

  // Authenticate WebSocket connection
  try {
    const cookies = req.headers.cookie;
    if (cookies) {
      const tokenCookieString = cookies
        .split(";")
        .find((str) => str.trim().startsWith("token="));
      if (tokenCookieString) {
        const token = tokenCookieString.split("=")[1];
        if (token) {
          jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) {
              console.error("WebSocket auth error:", err.message);
              return connection.close();
            }
            const { userId, username } = userData;
            connection.userId = userId;
            connection.username = username;
            notifyAboutOnlinePeople();
          });
        }
      }
    }
  } catch (error) {
    console.error("Error authenticating WebSocket connection:", error.message);
    connection.close();
  }

  // Handle WebSocket messages
  connection.on("message", async (message) => {
    try {
      const messageData = JSON.parse(message.toString());
      const { recipient, text, file } = messageData;
      
      if (!recipient) {
        console.warn("Message without recipient:", messageData);
        return;
      }
      
      let fileUrl = null;
      
      if (file) {
        try {
          const parts = file.name.split(".");
          const ext = parts[parts.length - 1];
          const fileName = `${Date.now()}.${ext}`;
          const filePath = path.join(__dirname, 'uploads', fileName);
          
          // Ensure uploads directory exists
          if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
            fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
          }
          
          const bufferData = Buffer.from(file.data.split(",")[1], "base64");
          fs.writeFileSync(filePath, bufferData);

          // Upload to AWS S3
          fileUrl = await uploadToS3(fileName, filePath);
          
          // Clean up local file if S3 upload was successful
          if (fileUrl && fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        } catch (fileError) {
          console.error("File processing error:", fileError.message);
        }
      }
      
      if (recipient && (text || fileUrl)) {
        const messageDoc = await Message.create({
          sender: connection.userId,
          recipient,
          text,
          file: fileUrl || null,
        });
        
        // Send message to recipient if online
        [...wss.clients]
          .filter((c) => c.userId === recipient && c.readyState === ws.OPEN)
          .forEach((c) =>
            c.send(
              JSON.stringify({
                text,
                sender: connection.userId,
                recipient,
                file: fileUrl || null,
                _id: messageDoc._id,
              })
            )
          );
      }
    } catch (error) {
      console.error("Error processing WebSocket message:", error.message);
    }
  });

  // Handle WebSocket close
  connection.on("close", () => {
    clearInterval(connection.timer);
    notifyAboutOnlinePeople();
  });

  // Handle WebSocket errors
  connection.on("error", (error) => {
    console.error("WebSocket connection error:", error.message);
    clearInterval(connection.timer);
    connection.terminate();
  });

  // Initial notification
  notifyAboutOnlinePeople();
});

// Handle WebSocket server errors
wss.on("error", (error) => {
  console.error("WebSocket server error:", error.message);
});