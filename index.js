const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require("nodemailer");
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const cors = require('cors');
const port = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_user}:${process.env.DB_pass}@cluster0.ihuxcck.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
    socketTimeoutMS: 60000,
    connectTimeoutMS: 30000,
});

const dbConnect = async () => {
    try {
        await client.connect();
        console.log("Database Connected Successfully ✅");
    } catch (error) {
        console.error("Database connection error:", error);
    }
};

dbConnect();

const usersCollection = client.db('storage').collection('user');
const otpCollection = client.db("storage").collection("otp");

const notesCollection = client.db('storage').collection('notes');
const imagesCollection = client.db('storage').collection('images');
const pdfsCollection = client.db('storage').collection('pdfs');
const foldersCollection = client.db('storage').collection('folders');

const cleanupExpiredOtps = async () => {
  try {
      const now = new Date();
      const result = await otpCollection.deleteMany({ expiry: { $lt: now } });
      if (result.deletedCount > 0) {
          console.log(`🗑️ Deleted ${result.deletedCount} expired OTP(s)`);
      }
  } catch (error) {
      console.error("❌ Error deleting expired OTPs:", error);
  }
};

setInterval(cleanupExpiredOtps, 60 * 60 * 1000);


// Email Transporter
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// Root Route
app.get('/', (req, res) => {
    res.send('Server is running');
});

// Authentication Middleware
const authMiddleware = (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Authentication token is missing' });

        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        console.error("Auth Middleware Error:", error);
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// User Registration
app.post('/control/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required' });

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { username, email, password: hashedPassword, role: "user", created_at: new Date() };
        await usersCollection.insertOne(newUser);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: 'Registration failed', error: error.message });
    }
});

// User Login
app.post('/control/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const user = await usersCollection.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const passwordMatch = user.password.startsWith('$2b$') ? await bcrypt.compare(password, user.password) : user.password === password;
        if (!passwordMatch) return res.status(401).json({ message: 'Invalid credentials' });

        if (!user.password.startsWith('$2b$')) {
            user.password = await bcrypt.hash(password, 10);
            await usersCollection.updateOne({ _id: user._id }, { $set: { password: user.password } });
        }

        const token = jwt.sign({ sub: user._id, email: user.email, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('accessToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 604800000 });
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Login failed', error: error.message });
    }
});

// Logout
app.post('/control/logout', (req, res) => {
    try {
        res.clearCookie('accessToken', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ message: 'Logout failed', error: error.message });
    }
});

// Forgot Password - Send OTP
app.post("/control/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "❌ User not found" });

        const otp = Math.random().toString().slice(2, 8);
        await otpCollection.insertOne({ email, otp, expiry: new Date(Date.now() + 300000) });

        await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: "Password Reset OTP", text: `Your OTP is ${otp}` });
        res.json({ message: "✅ OTP sent" });
    } catch (error) {
        console.error("Forgot Password Error:", error);
        res.status(500).json({ message: "❌ Email sending failed" });
    }
});

// Verify OTP
app.post("/control/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        const otpData = await otpCollection.findOne({ email });

        if (!otpData) return res.status(400).json({ message: "❌ No OTP found" });
        if (new Date() > otpData.expiry) return res.status(400).json({ message: "❌ Expired OTP" });

        if (otpData.otp !== otp.toString()) return res.status(400).json({ message: "❌ Invalid OTP" });

        await otpCollection.deleteOne({ email });
        res.json({ message: "✅ OTP verified" });
    } catch (error) {
        console.error("OTP Verification Error:", error);
        res.status(500).json({ message: "❌ OTP verification failed" });
    }
});

// Reset Password
app.post("/reset-password", async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const otpData = await otpCollection.findOne({ email, otp });
        if (!otpData || new Date() > otpData.expiry) return res.status(400).json({ message: "❌ Invalid or expired OTP" });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await usersCollection.updateOne({ email }, { $set: { password: hashedPassword } });
        await otpCollection.deleteOne({ email, otp });

        res.json({ message: "✅ Password reset successfully" });
    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ message: "❌ Password reset failed" });
    }
});

// Add Note
app.post('/control/add-note', authMiddleware, async (req, res) => {
  try {
      const { name, content } = req.body;
      if (!title || !content) return res.status(400).json({ message: 'Title and content are required' });

      const existingNote = await notesCollection.findOne({ userId: req.user.sub, title });
      if (existingNote) return res.status(400).json({ message: 'A note with this title already exists' });

      await notesCollection.insertOne({
          userId: req.user.sub,
          title,
          content,
          type: "note",
          createdAt: new Date()
      });
      res.status(201).json({ message: 'Note added successfully' });
  } catch (error) {
      console.error("Add Note Error:", error);
      res.status(500).json({ message: 'Failed to add note', error: error.message });
  }
});

// Import Image
app.post('/control/import-image', authMiddleware, async (req, res) => {
  try {
      const { imageUrl, description } = req.body;
      if (!imageUrl) return res.status(400).json({ message: 'Image URL is required' });

      const existingImage = await imagesCollection.findOne({ userId: req.user.sub, imageUrl });
      if (existingImage) return res.status(400).json({ message: 'This image is already imported' });

      await imagesCollection.insertOne({
          userId: req.user.sub,
          imageUrl,
          description,
          type: "image",
          uploadedAt: new Date()
      });
      res.status(201).json({ message: 'Image imported successfully' });
  } catch (error) {
      console.error("Import Image Error:", error);
      res.status(500).json({ message: 'Failed to import image', error: error.message });
  }
});

// Import PDF
app.post('/control/import-pdf', authMiddleware, async (req, res) => {
  try {
      const { pdfUrl, title } = req.body;
      if (!pdfUrl || !title) return res.status(400).json({ message: 'PDF URL and title are required' });

      const existingPDF = await pdfsCollection.findOne({ userId: req.user.sub, pdfUrl });
      if (existingPDF) return res.status(400).json({ message: 'This PDF is already imported' });

      await pdfsCollection.insertOne({
          userId: req.user.sub,
          pdfUrl,
          title,
          type: "pdf",
          uploadedAt: new Date()
      });
      res.status(201).json({ message: 'PDF imported successfully' });
  } catch (error) {
      console.error("Import PDF Error:", error);
      res.status(500).json({ message: 'Failed to import PDF', error: error.message });
  }
});

// Create Folder
app.post('/control/create-folder', authMiddleware, async (req, res) => {
  try {
      const { folderName } = req.body;
      if (!folderName) return res.status(400).json({ message: 'Folder name is required' });

      const existingFolder = await foldersCollection.findOne({ userId: req.user.sub, folderName });
      if (existingFolder) return res.status(400).json({ message: 'A folder with this name already exists' });

      await foldersCollection.insertOne({
          userId: req.user.sub,
          folderName,
          type: "folder",
          createdAt: new Date()
      });
      res.status(201).json({ message: 'Folder created successfully' });
  } catch (error) {
      console.error("Create Folder Error:", error);
      res.status(500).json({ message: 'Failed to create folder', error: error.message });
  }
});

function getCollectionByType(type) {
  switch (type) {
      case 'image': return imagesCollection;
      case 'folder': return foldersCollection;
      case 'note': return notesCollection;
      case 'pdf': return pdfsCollection;
      default: throw new Error('Invalid type');
  }
}

//Favorite item
app.post('/control/favorite', authMiddleware, async (req, res) => {
  try {
      const { itemId, type } = req.body;
      if (!itemId || !type) return res.status(400).json({ message: 'Item ID and type are required' });

      const collection = getCollectionByType(type);
      const item = await collection.findOne({ _id: new ObjectId(itemId) });

      if (!item) return res.status(404).json({ message: 'Item not found' });

      await collection.updateOne({ _id: new ObjectId(itemId) }, { $set: { isFavorite: true } });
      res.json({ message: `${type} marked as favorite` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to mark favorite', error: error.message });
  }
});

//Unfavorite item
app.post('/control/unfavorite', authMiddleware, async (req, res) => {
    try {
        const { itemId, type } = req.body;
        if (!itemId || !type) return res.status(400).json({ message: 'Item ID and type are required' });
  
        const collection = getCollectionByType(type);
        const item = await collection.findOne({ _id: new ObjectId(itemId) });
  
        if (!item) return res.status(404).json({ message: 'Item not found' });
  
        await collection.updateOne({ _id: new ObjectId(itemId) }, { $set: { isFavorite: false } });
        res.json({ message: `${type} marked as favorite` });
  
    } catch (error) {
        res.status(500).json({ message: 'Failed to mark favorite', error: error.message });
    }
  });

//Copy item
 app.post('/control/copy', authMiddleware, async (req, res) => {
  try {
      const { itemId, type } = req.body;
      if (!itemId || !type) return res.status(400).json({ message: 'Item ID and type are required' });

      const collection = getCollectionByType(type);
      const item = await collection.findOne({ _id: new ObjectId(itemId) });

      if (!item) return res.status(404).json({ message: 'Item not found' });

      const newItem = { ...item, _id: new ObjectId(), copiedAt: new Date() };
      delete newItem._id;

      await collection.insertOne(newItem);
      res.json({ message: `${type} copied successfully` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to copy item', error: error.message });
  }
});

//Rename item
app.post('/control/rename', authMiddleware, async (req, res) => {
  try {
      const { itemId, type, newName } = req.body;
      if (!itemId || !type || !newName) return res.status(400).json({ message: 'Item ID, type, and new name are required' });

      const collection = getCollectionByType(type);

      let updateField;
      switch (type) {
          case 'note': updateField = 'title'; break;
          case 'image': updateField = 'description'; break;
          case 'pdf': updateField = 'title'; break;
          case 'folder': updateField = 'folderName'; break;
          default: return res.status(400).json({ message: 'Invalid type' });
      }

      await collection.updateOne({ _id: new ObjectId(itemId) }, { $set: { [updateField]: newName } });

      res.json({ message: `${type} renamed successfully` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to rename item', error: error.message });
  }
});

//Duplicate item
app.post('/control/duplicate', authMiddleware, async (req, res) => {
  try {
      const { itemId, type } = req.body;
      if (!itemId || !type) return res.status(400).json({ message: 'Item ID and type are required' });

      const collection = getCollectionByType(type);
      const item = await collection.findOne({ _id: new ObjectId(itemId) });

      if (!item) return res.status(404).json({ message: 'Item not found' });

      const newItem = { ...item, _id: new ObjectId(), name: item.name + ' - Copy', duplicatedAt: new Date() };
      delete newItem._id;

      await collection.insertOne(newItem);
      res.json({ message: `${type} duplicated successfully` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to duplicate item', error: error.message });
  }
});

//Delete item
app.delete('/control/delete', authMiddleware, async (req, res) => {
  try {
      const { itemId, type } = req.body;
      if (!itemId || !type) return res.status(400).json({ message: 'Item ID and type are required' });

      const collection = getCollectionByType(type);
      await collection.deleteOne({ _id: new ObjectId(itemId) });

      res.json({ message: `${type} deleted successfully` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to delete item', error: error.message });
  }
});

//Share item
app.post('/control/share', authMiddleware, async (req, res) => {
  try {
      const { itemId, type, sharedWithUserId } = req.body;
      if (!itemId || !type || !sharedWithUserId) return res.status(400).json({ message: 'Item ID, type, and shared user ID are required' });

      const collection = getCollectionByType(type);
      await collection.updateOne({ _id: new ObjectId(itemId) }, { $addToSet: { sharedWith: sharedWithUserId } });

      res.json({ message: `${type} shared successfully` });

  } catch (error) {
      res.status(500).json({ message: 'Failed to share item', error: error.message });
  }
});

//Get Data by Type
app.get('/control/typedata', authMiddleware, async (req, res) => {
    try {
        const { type } = req.query;
        if (!type) return res.status(400).json({ message: 'Type is required' });
  
        // Function to get the correct collection
        const collection = getCollectionByType(type);
        if (!collection) return res.status(400).json({ message: 'Invalid type' });
  
        // Retrieve data of the specified type
        const data = await collection.find().toArray();
  
        res.json({ message: `${type} data retrieved successfully`, data });
  
    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve data', error: error.message });
    }
});

//Single Data
app.get('/control/data', authMiddleware, async (req, res) => {
    try {
        const { type, id } = req.query;
        if (!type) return res.status(400).json({ message: 'Type is required' });
        
        const collection = getCollectionByType(type);

        if (id) {
            const item = await collection.findOne({ _id: new ObjectId(id) });
            if (!item) return res.status(404).json({ message: 'Item not found' });

            return res.json({ message: 'Item retrieved successfully', data: item });
        }

        const items = await collection.find().toArray();
        res.json({ message: `${type} data retrieved successfully`, data: items });

    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve data', error: error.message });
    }
});

//All Favorite
app.get('/control/favorites', authMiddleware, async (req, res) => {
    try {
        const types = ['image', 'folder', 'note', 'pdf']; 
        const results = {};

        for (const type of types) {
            const collection = getCollectionByType(type);
            const data = await collection.find({ isFavorite: true }).toArray();
            results[type] = data;
        }

        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch favorite data', error: error.message });
    }
});

//By Data
app.get('/control/data/by-date', authMiddleware, async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) return res.status(400).json({ message: 'Date is required' });

        const targetDate = new Date(date);
        if (isNaN(targetDate.getTime())) return res.status(400).json({ message: 'Invalid date format' });

        const types = ['image', 'folder', 'note', 'pdf'];
        const results = {};

        for (const type of types) {
            const collection = getCollectionByType(type);
            const data = await collection.find({
                createdAt: {
                    $gte: new Date(targetDate.setHours(0, 0, 0, 0)),
                    $lt: new Date(targetDate.setHours(23, 59, 59, 999))
                }
            }).toArray();
            results[type] = data;
        }

        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch data', error: error.message });
    }
});


// Start Server
app.listen(port, () => console.log(`Server running on port ${port}`));
