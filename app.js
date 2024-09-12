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
      "PDFxCel Results"
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
    "PDFxCel Results"
  );
  XLSX.writeFile(workbook, filePath);
}

// Middleware to handle file uploads
const upload = multer({ dest: "tmp/" });

// New API route for file upload and processing
app.post("/api/upload-file", upload.array("files"), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "No files uploaded" });
  }

  try {
    // Process each file
    for (const file of req.files) {
      if (path.extname(file.originalname) !== ".pdf") {
        return res.status(400).json({ error: "Only PDF files are allowed" });
      }

      const pdfText = await extractTextFromPdf(file.path);
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

      const excelFilePath = path.join(
        "tmp",
        `PDFxCel_result_${path.basename(
          file.originalname,
          path.extname(file.originalname)
        )}.xlsx`
      );
      saveMarkdownToExcel(markdownText, excelFilePath);

      res.download(excelFilePath, (err) => {
        if (err) {
          console.error(err);
        }
        fs.unlinkSync(file.path); // Clean up the uploaded file
        fs.unlinkSync(excelFilePath); // Clean up the generated Excel file
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Other existing routes ...

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
