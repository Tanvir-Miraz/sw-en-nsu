const express = require("express");
const cors = require("cors");
const path = require("path");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
const PORT = 5000;

// -----------------------------
// Middleware
// -----------------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend folder
const frontendPath = path.join(__dirname, "frontend");
app.use(express.static(frontendPath));

// -----------------------------
// MySQL Connection
// -----------------------------
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "medicore_db",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
    return;
  }

  console.log("✅ Connected to MySQL database.");
  createPasswordResetTable();
});

// -----------------------------
// Helper: Create password reset table
// -----------------------------
function createPasswordResetTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      email VARCHAR(255) NOT NULL,
      reset_token VARCHAR(255) NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      is_used TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    )
  `;

  db.query(query, (err) => {
    if (err) {
      console.error("❌ Could not create password_reset_tokens table:", err.message);
    } else {
      console.log("✅ password_reset_tokens table is ready.");
    }
  });
}

// -----------------------------
// Helper Functions
// -----------------------------
function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message,
  });
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    req.ip ||
    null
  );
}

function formatDiseases(diseases) {
  if (!diseases) return JSON.stringify([]);
  if (Array.isArray(diseases)) return JSON.stringify(diseases);
  return JSON.stringify([String(diseases)]);
}

// -----------------------------
// Basic Routes
// -----------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is running fine",
    app: "MediCore",
    timestamp: new Date().toISOString(),
  });
});

// -----------------------------
// Register Route
// -----------------------------
app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      age,
      height,
      heightUnit,
      weight,
      bloodGroup,
      gender,
      phone,
      email,
      address,
      password,
      chronicDiseases,
    } = req.body;

    if (
      !name ||
      !age ||
      !height ||
      !weight ||
      !bloodGroup ||
      !gender ||
      !phone ||
      !email ||
      !address ||
      !password
    ) {
      return sendError(res, 400, "Please fill all required fields.");
    }

    const cleanEmail = String(email).trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return sendError(res, 400, "Please enter a valid email address.");
    }

    if (String(password).length < 6) {
      return sendError(res, 400, "Password must be at least 6 characters long.");
    }

    const checkUserQuery = "SELECT user_id FROM users WHERE email = ?";

    db.query(checkUserQuery, [cleanEmail], async (checkErr, results) => {
      if (checkErr) {
        console.error("Register check error:", checkErr.message);
        return sendError(res, 500, "Database error while checking email.");
      }

      if (results.length > 0) {
        return sendError(res, 400, "This email is already registered.");
      }

      try {
        const hashedPassword = await bcrypt.hash(String(password), 10);

        const insertQuery = `
          INSERT INTO users
          (
            full_name,
            age,
            height,
            height_unit,
            weight,
            blood_group,
            gender,
            phone,
            email,
            address,
            password_hash,
            chronic_diseases
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
          String(name).trim(),
          Number(age),
          Number(height),
          heightUnit || "cm",
          Number(weight),
          bloodGroup,
          gender,
          String(phone).trim(),
          cleanEmail,
          String(address).trim(),
          hashedPassword,
          formatDiseases(chronicDiseases),
        ];

        db.query(insertQuery, values, (insertErr, result) => {
          if (insertErr) {
            console.error("Register insert error:", insertErr.message);
            return sendError(res, 500, "Could not create account.");
          }

          return res.status(201).json({
            success: true,
            message: "Registration successful.",
            user_id: result.insertId,
          });
        });
      } catch (hashErr) {
        console.error("Password hash error:", hashErr.message);
        return sendError(res, 500, "Could not secure password.");
      }
    });
  } catch (error) {
    console.error("Register route error:", error.message);
    return sendError(res, 500, "Something went wrong during registration.");
  }
});

// -----------------------------
// Login Route
// -----------------------------
app.post("/api/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return sendError(res, 400, "Please enter email and password.");
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const query = "SELECT * FROM users WHERE email = ? LIMIT 1";

    db.query(query, [cleanEmail], async (err, results) => {
      if (err) {
        console.error("Login query error:", err.message);
        return sendError(res, 500, "Database error during login.");
      }

      if (results.length === 0) {
        return sendError(res, 401, "Invalid email or password.");
      }

      const user = results[0];

      try {
        const isMatch = await bcrypt.compare(String(password), user.password_hash);

        if (!isMatch) {
          return sendError(res, 401, "Invalid email or password.");
        }

        const sessionInsertQuery = `
          INSERT INTO user_sessions
          (
            user_id,
            email,
            login_time,
            session_status,
            ip_address,
            user_agent
          )
          VALUES (?, ?, NOW(), 'active', ?, ?)
        `;

        const ipAddress = getClientIp(req);
        const userAgent = req.headers["user-agent"] || null;

        db.query(
          sessionInsertQuery,
          [user.user_id, user.email, ipAddress, userAgent],
          (sessionErr, sessionResult) => {
            if (sessionErr) {
              console.error("Session insert error:", sessionErr.message);
              return sendError(res, 500, "Login succeeded, but session could not be recorded.");
            }

            return res.json({
              success: true,
              message: "Login successful.",
              user: {
                user_id: user.user_id,
                full_name: user.full_name,
                email: user.email,
              },
              session_id: sessionResult.insertId,
            });
          }
        );
      } catch (compareErr) {
        console.error("Password compare error:", compareErr.message);
        return sendError(res, 500, "Could not verify password.");
      }
    });
  } catch (error) {
    console.error("Login route error:", error.message);
    return sendError(res, 500, "Something went wrong during login.");
  }
});

// -----------------------------
// Logout Route
// -----------------------------
app.post("/api/logout", (req, res) => {
  try {
    const { session_id } = req.body;

    if (!session_id) {
      return sendError(res, 400, "Session ID is required for logout.");
    }

    const updateQuery = `
      UPDATE user_sessions
      SET logout_time = NOW(),
          session_status = 'logged_out'
      WHERE session_id = ? AND session_status = 'active'
    `;

    db.query(updateQuery, [session_id], (err, result) => {
      if (err) {
        console.error("Logout query error:", err.message);
        return sendError(res, 500, "Could not log out properly.");
      }

      return res.json({
        success: true,
        message: "Logout successful.",
        affectedRows: result.affectedRows,
      });
    });
  } catch (error) {
    console.error("Logout route error:", error.message);
    return sendError(res, 500, "Something went wrong during logout.");
  }
});

// -----------------------------
// Forgot Password Route
// -----------------------------
app.post("/api/forgot-password", (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendError(res, 400, "Email is required.");
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const findUserQuery = "SELECT user_id, email, full_name FROM users WHERE email = ? LIMIT 1";

    db.query(findUserQuery, [cleanEmail], (findErr, results) => {
      if (findErr) {
        console.error("Forgot password find user error:", findErr.message);
        return sendError(res, 500, "Database error while finding user.");
      }

      if (results.length === 0) {
        return sendError(res, 404, "No account found with this email.");
      }

      const user = results[0];
      const resetToken = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 1000 * 60 * 30); // 30 minutes

      const insertTokenQuery = `
        INSERT INTO password_reset_tokens
        (user_id, email, reset_token, expires_at, is_used)
        VALUES (?, ?, ?, ?, 0)
      `;

      db.query(
        insertTokenQuery,
        [user.user_id, user.email, resetToken, expiresAt],
        (tokenErr) => {
          if (tokenErr) {
            console.error("Reset token insert error:", tokenErr.message);
            return sendError(res, 500, "Could not create reset link.");
          }

          const resetLink = `http://localhost:${PORT}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(
            user.email
          )}`;

          console.log("🔐 Password reset link:", resetLink);

          return res.json({
            success: true,
            message: "Password reset link generated successfully.",
            resetLink,
          });
        }
      );
    });
  } catch (error) {
    console.error("Forgot password route error:", error.message);
    return sendError(res, 500, "Something went wrong.");
  }
});

// -----------------------------
// Verify Reset Token Route
// -----------------------------
app.post("/api/verify-reset-token", (req, res) => {
  try {
    const { token, email } = req.body;

    if (!token || !email) {
      return sendError(res, 400, "Token and email are required.");
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const query = `
      SELECT *
      FROM password_reset_tokens
      WHERE reset_token = ?
        AND email = ?
        AND is_used = 0
        AND expires_at > NOW()
      LIMIT 1
    `;

    db.query(query, [token, cleanEmail], (err, results) => {
      if (err) {
        console.error("Verify token error:", err.message);
        return sendError(res, 500, "Could not verify reset token.");
      }

      if (results.length === 0) {
        return sendError(res, 400, "This reset link is invalid or expired.");
      }

      return res.json({
        success: true,
        message: "Reset token is valid.",
      });
    });
  } catch (error) {
    console.error("Verify reset token route error:", error.message);
    return sendError(res, 500, "Something went wrong.");
  }
});

// -----------------------------
// Reset Password Route
// -----------------------------
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;

    if (!token || !email || !newPassword) {
      return sendError(res, 400, "Token, email, and new password are required.");
    }

    if (String(newPassword).length < 6) {
      return sendError(res, 400, "New password must be at least 6 characters long.");
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const findTokenQuery = `
      SELECT *
      FROM password_reset_tokens
      WHERE reset_token = ?
        AND email = ?
        AND is_used = 0
        AND expires_at > NOW()
      LIMIT 1
    `;

    db.query(findTokenQuery, [token, cleanEmail], async (findErr, results) => {
      if (findErr) {
        console.error("Reset password token lookup error:", findErr.message);
        return sendError(res, 500, "Database error.");
      }

      if (results.length === 0) {
        return sendError(res, 400, "Reset link is invalid or expired.");
      }

      const tokenRow = results[0];

      try {
        const hashedPassword = await bcrypt.hash(String(newPassword), 10);

        const updateUserQuery = `
          UPDATE users
          SET password_hash = ?
          WHERE user_id = ? AND email = ?
        `;

        db.query(
          updateUserQuery,
          [hashedPassword, tokenRow.user_id, cleanEmail],
          (updateErr) => {
            if (updateErr) {
              console.error("Reset password update user error:", updateErr.message);
              return sendError(res, 500, "Could not update password.");
            }

            const markUsedQuery = `
              UPDATE password_reset_tokens
              SET is_used = 1
              WHERE token_id = ?
            `;

            db.query(markUsedQuery, [tokenRow.token_id], (markErr) => {
              if (markErr) {
                console.error("Reset password mark token used error:", markErr.message);
                return sendError(res, 500, "Password updated, but token cleanup failed.");
              }

              return res.json({
                success: true,
                message: "Password has been reset successfully.",
              });
            });
          }
        );
      } catch (hashErr) {
        console.error("Reset password hash error:", hashErr.message);
        return sendError(res, 500, "Could not secure new password.");
      }
    });
  } catch (error) {
    console.error("Reset password route error:", error.message);
    return sendError(res, 500, "Something went wrong.");
  }
});

// -----------------------------
// User Profile Route
// -----------------------------
app.get("/api/user-profile", (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();

    if (!email) {
      return sendError(res, 400, "Email is required.");
    }

    const query = `
      SELECT
        user_id,
        full_name,
        age,
        height,
        height_unit,
        weight,
        blood_group,
        gender,
        phone,
        email,
        address,
        chronic_diseases,
        created_at,
        updated_at
      FROM users
      WHERE email = ?
      LIMIT 1
    `;

    db.query(query, [email], (err, results) => {
      if (err) {
        console.error("User profile query error:", err.message);
        return sendError(res, 500, "Could not fetch user profile.");
      }

      if (results.length === 0) {
        return sendError(res, 404, "User not found.");
      }

      const user = results[0];

      let parsedDiseases = [];
      try {
        parsedDiseases = user.chronic_diseases ? JSON.parse(user.chronic_diseases) : [];
      } catch {
        parsedDiseases = [];
      }

      return res.json({
        success: true,
        user: {
          ...user,
          chronic_diseases: parsedDiseases,
        },
      });
    });
  } catch (error) {
    console.error("User profile route error:", error.message);
    return sendError(res, 500, "Something went wrong.");
  }
});

// -----------------------------
// Start Server
// -----------------------------
app.listen(PORT, () => {
  console.log(`🚀 MediCore server running at http://localhost:${PORT}`);
});