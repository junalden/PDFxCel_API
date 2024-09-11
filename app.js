const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");
const XLSX = require("xlsx");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// Use CORS middleware
app.use(cors()); // This will allow all origins by default

// Middleware to parse JSON
app.use(express.json());

// Create a MySQL connection pool
const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Function to generate JWT tokens
const generateToken = (user) => {
  return jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
};

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401); // If no token is found

  try {
    const user = await jwt.verify(token, process.env.JWT_SECRET);
    req.user = user; // Attach user object to request
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    res.sendStatus(403); // If token is invalid
  }
};

// Function to extract text from a PDF
async function extractTextFromPdf(pdfPath) {
  const data = fs.readFileSync(pdfPath);
  const pdfData = await pdfParse(data);
  return pdfData.text;
}

// Function to send text to Gemini AI API
async function processTextWithGemini(prompt) {
  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=${process.env.API_KEY}`,
      {
        contents: [
          {
            role: "user",
            parts: [{ text: prompt }],
          },
        ],
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    return response.data;
  } catch (error) {
    return { error: error.message };
  }
}

// Function to parse Markdown table and save to Excel
function saveMarkdownToExcel(markdownText, filePath) {
  const lines = markdownText.trim().split("\n");
  const workbook = XLSX.utils.book_new();
  const worksheet = [];

  if (!lines.length || lines.length < 3) {
    worksheet.push([
      "Error",
      "Markdown text is not in expected format or is empty.",
    ]);
    XLSX.utils.book_append_sheet(
      workbook,
      XLSX.utils.aoa_to_sheet(worksheet),
      "Gemini API Results"
    );
    XLSX.writeFile(workbook, filePath);
    return;
  }

  const headers = lines[0]
    .trim()
    .split("|")
    .map((header) => header.trim())
    .filter((header) => header);
  worksheet.push(headers);

  for (const line of lines.slice(2)) {
    const row = line
      .trim()
      .split("|")
      .map((cell) => cell.trim())
      .filter((cell) => cell);
    worksheet.push(row);
  }

  XLSX.utils.book_append_sheet(
    workbook,
    XLSX.utils.aoa_to_sheet(worksheet),
    "Gemini API Results"
  );
  XLSX.writeFile(workbook, filePath);
}

// Middleware to handle file uploads
const upload = multer({ dest: "tmp/" });

// API route to create a new user
app.post("/api/create-account", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const connection = await pool.getConnection();
    const query = "INSERT INTO users (email, password) VALUES (?, ?)";
    await connection.query(query, [email, hashedPassword]);
    connection.release(); // Release connection back to the pool

    res.status(201).json({ message: "Account created successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error creating account", details: error.message });
  }
});

// API route to authenticate a user
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const connection = await pool.getConnection();
    const query = "SELECT * FROM users WHERE email = ?";
    const [results] = await connection.query(query, [email]);
    connection.release(); // Release connection back to the pool

    if (results.length > 0) {
      const user = results[0];

      // Compare the provided password with the hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        // Generate a JWT token and send it to the client
        const token = generateToken(user);
        res.status(200).json({ message: "Login successful", token });
      } else {
        res.status(401).json({ error: "Invalid credentials" });
      }
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).json({ error: "Error logging in", details: error.message });
  }
});

// API route to save matrix data
app.post("/api/save-matrix", authenticateToken, async (req, res) => {
  const { matrixId, matrixData } = req.body;
  const userId = req.user.userId; // Extract userId from the token

  if (!userId || !Array.isArray(matrixData) || matrixData.length === 0) {
    return res.status(400).json({ error: "Invalid input data" });
  }

  try {
    const connection = await pool.getConnection();

    // Generate new matrixId if not provided
    const [matrixIdResults] = await connection.query(
      "SELECT MAX(matrix_id) AS maxMatrixId FROM matrix_data WHERE user_id = ?",
      [userId]
    );
    const lastMatrixId = matrixIdResults[0].maxMatrixId || 0; // If null, start with 0
    const newMatrixId = matrixId || lastMatrixId + 1;

    const values = matrixData.map((row) => [
      userId,
      newMatrixId,
      row.columnName,
      row.transformation,
    ]);

    const query = `
      INSERT INTO matrix_data (user_id, matrix_id, column_name, transformation)
      VALUES ?
    `;
    await connection.query(query, [values]);
    connection.release(); // Release connection back to the pool

    res.status(201).json({
      message: "Matrix data saved successfully",
      matrixId: newMatrixId,
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error saving matrix data", details: error.message });
  }
});

// Endpoint to load available matrices
app.get("/api/get-matrix-list", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const connection = await pool.getConnection();
    const query =
      "SELECT DISTINCT matrix_id FROM matrix_data WHERE user_id = ?";
    const [results] = await connection.query(query, [userId]);
    connection.release(); // Release connection back to the pool

    res.status(200).json(results);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error fetching matrix list", details: error.message });
  }
});

app.get("/api/get-matrix/:matrixId", authenticateToken, async (req, res) => {
  const { matrixId } = req.params;
  const userId = req.user.userId;

  try {
    const connection = await pool.getConnection();
    const query =
      "SELECT column_name, transformation FROM matrix_data WHERE matrix_id = ? AND user_id = ?";
    const [results] = await connection.query(query, [matrixId, userId]);
    connection.release(); // Release connection back to the pool

    res.json(results);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error fetching matrix data", details: error.message });
  }
});

// PDF processing route
app.post(
  "/api/process-pdf",
  // authenticateToken,
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file part" });
    }

    if (path.extname(req.file.originalname) !== ".pdf") {
      return res
        .status(400)
        .json({ error: "Invalid file type. Only PDF files are allowed." });
    }

    try {
      const pdfText = await extractTextFromPdf(req.file.path);
      const prompts = req.body.prompts ? JSON.parse(req.body.prompts) : [];

      let customText = "Make me a summary in table format:\n";
      for (const row of prompts) {
        const columnName = row.columnName || "";
        const transformation = row.transformation || "";
        customText += `Column Name: ${columnName}, then format ${columnName} to ${transformation}.\n`;
      }

      const combinedText = customText + "\n\n" + pdfText;
      const geminiResponse = await processTextWithGemini(combinedText);

      if (geminiResponse.error) {
        return res.status(400).json(geminiResponse);
      }

      const candidates = geminiResponse.candidates || [{}];
      const parts = candidates[0].content?.parts || [{}];
      const markdownText = parts[0]?.text || "";

      if (!markdownText) {
        return res
          .status(400)
          .json({ error: "No content found in API response." });
      }

      const excelFilePath = path.join("tmp", "PDFxCel_result.xlsx");
      saveMarkdownToExcel(markdownText, excelFilePath);

      res.download(excelFilePath, "PDFxCel_Result.xlsx", (err) => {
        if (err) {
          console.error(err);
        }
        fs.unlinkSync(req.file.path); // Clean up the uploaded file
        fs.unlinkSync(excelFilePath); // Clean up the generated Excel file
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

const https = require("https"); // Add this line at the beginning if not already imported

// Fetch templates
app.get("/api/templates", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const connection = await pool.getConnection();
    const query =
      "SELECT DISTINCT matrix_id FROM matrix_data WHERE user_id = ?";
    const [results] = await connection.query(query, [userId]);
    connection.release(); // Release connection back to the pool

    res.status(200).json(results);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error fetching templates", details: error.message });
  }
});

app.delete("/api/templates/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;

  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query(
      "DELETE FROM matrix_data WHERE matrix_id = ? AND user_id = ?",
      [id, userId]
    );
    connection.release(); // Release connection back to the pool

    if (result.affectedRows > 0) {
      res.status(200).json({ message: "Template deleted successfully" });
    } else {
      res
        .status(404)
        .json({ error: "Template not found or not owned by user" });
    }
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error deleting template", details: error.message });
  }
});

// Change Email
app.put("/api/change-email", authenticateToken, async (req, res) => {
  const { newEmail } = req.body;
  const { userId } = req.user;

  if (!newEmail) {
    return res.status(400).json({ error: "New email is required" });
  }

  try {
    const connection = await pool.getConnection();
    await connection.query("UPDATE users SET email = ? WHERE id = ?", [
      newEmail,
      userId,
    ]);
    connection.release();
    res.status(200).json({ message: "Email updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update email" });
  }
});

// Change Password
app.put("/api/change-password", authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const { userId } = req.user;

  if (!oldPassword || !newPassword) {
    return res
      .status(400)
      .json({ error: "Both old and new passwords are required" });
  }

  try {
    const connection = await pool.getConnection();
    // Fetch current password hash from database
    const [rows] = await connection.query(
      "SELECT password FROM users WHERE id = ?",
      [userId]
    );
    connection.release();

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const currentPasswordHash = rows[0].password;

    // Check if the old password is correct
    const match = await bcrypt.compare(oldPassword, currentPasswordHash);

    if (!match) {
      return res.status(401).json({ error: "Incorrect old password" });
    }

    // Hash new password and update it in the database
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    const connection2 = await pool.getConnection();
    await connection2.query("UPDATE users SET password = ? WHERE id = ?", [
      newPasswordHash,
      userId,
    ]);
    connection2.release();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ error: "Failed to update password" });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
