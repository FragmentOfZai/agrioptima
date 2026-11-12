require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------
// Koneksi database PostgreSQL.
// - Neon / layanan cloud: isi DATABASE_URL (SSL otomatis aktif).
// - Lokal: isi DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
//   (isi DB_SSL=true bila server mewajibkan SSL).
// ---------------------------------------------------------------
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : undefined,
      }
);

pool.connect(function (err, client, release) {
  if (err) {
    console.error("Gagal menyambung ke PostgreSQL:", err.message);
  } else {
    console.log("Berhasil tersambung ke database");
    release();
    // Akun lama yang tertahan verifikasi OTP otomatis diaktifkan.
    pool
      .query("UPDATE users SET is_verified = true WHERE is_verified = false")
      .catch(function (e) {
        console.error("Gagal mengaktifkan akun lama:", e.message);
      });
  }
});

// 1. Registrasi (akun langsung aktif, tanpa verifikasi OTP)
app.post("/api/auth/register", async function (req, res) {
  try {
    var nama = (req.body.nama || "").trim();
    var instansi = (req.body.instansi || "").trim();
    var email = (req.body.email || "").trim();
    var password = req.body.password || "";

    if (!nama || !email || !password) {
      return res.status(400).json({ message: "Nama, email, dan password wajib diisi." });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password harus terdiri dari minimal 6 karakter." });
    }

    var userExist = await pool.query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [email]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ message: "Email sudah terdaftar di sistem!" });
    }

    var salt = await bcrypt.genSalt(10);
    var passwordHash = await bcrypt.hash(password, salt);

    var newUser = await pool.query(
      "INSERT INTO users (nama, instansi, email, password_hash, is_verified) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, nama",
      [nama, instansi, email, passwordHash, true]
    );

    res.status(201).json({
      message: "Registrasi berhasil! Akun Anda sudah aktif, silakan masuk.",
      email: newUser.rows[0].email,
    });
  } catch (error) {
    console.error("Error registrasi:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// 2. Login
app.post("/api/auth/login", async function (req, res) {
  try {
    var email = (req.body.email || "").trim();
    var password = req.body.password || "";

    var userResult = await pool.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: "Email atau password salah!" });
    }
    var user = userResult.rows[0];

    var validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: "Email atau password salah!" });
    }

    var token = jwt.sign(
      { id: user.id, email: user.email, nama: user.nama, instansi: user.instansi },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(200).json({
      message: "Login berhasil!",
      token: token,
      user: { id: user.id, nama: user.nama, email: user.email, instansi: user.instansi },
    });
  } catch (error) {
    console.error("Error login:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// JWT Middleware
function authenticateToken(req, res, next) {
  var authHeader = req.headers["authorization"];
  var token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Akses ditolak. Token tidak ditemukan." });
  jwt.verify(token, process.env.JWT_SECRET, function (err, user) {
    if (err) return res.status(403).json({ message: "Sesi telah berakhir. Silakan login kembali." });
    req.user = user;
    next();
  });
}

// 3. Profile
app.get("/api/auth/profile", authenticateToken, async function (req, res) {
  try {
    var userResult = await pool.query(
      "SELECT id, nama, instansi, email, created_at FROM users WHERE id = $1",
      [req.user.id]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan" });
    }
    res.status(200).json(userResult.rows[0]);
  } catch (error) {
    console.error("Error get profile:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// 4. Ubah Password
app.post("/api/auth/change-password", authenticateToken, async function (req, res) {
  try {
    var currentPassword = req.body.currentPassword || "";
    var newPassword = req.body.newPassword || "";

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password baru harus terdiri dari minimal 6 karakter." });
    }

    var userResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan" });
    }
    var user = userResult.rows[0];

    var validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ message: "Password saat ini yang Anda masukkan salah!" });
    }

    var salt = await bcrypt.genSalt(10);
    var passwordHash = await bcrypt.hash(newPassword, salt);

    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, user.id]);
    res.status(200).json({ message: "Password berhasil diperbarui!" });
  } catch (error) {
    console.error("Error change password:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// 5. Simpan Riwayat
app.post("/api/history", authenticateToken, async function (req, res) {
  try {
    var luas_lahan = req.body.luas_lahan;
    var total_tanaman_aktif = req.body.total_tanaman_aktif;
    var rekomendasi_pola = req.body.rekomendasi_pola;
    var estimasi_pendapatan = req.body.estimasi_pendapatan;
    var userId = req.user.id;

    var newHistory = await pool.query(
      "INSERT INTO riwayat_simulasi (user_id, luas_lahan, total_tanaman_aktif, rekomendasi_pola, estimasi_pendapatan) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [userId, luas_lahan, total_tanaman_aktif, rekomendasi_pola, estimasi_pendapatan]
    );

    res.status(201).json({ message: "Riwayat berhasil disimpan!", data: newHistory.rows[0] });
  } catch (error) {
    console.error("Error save history:", error);
    res.status(500).json({ message: "Terjadi kesalahan saat menyimpan riwayat." });
  }
});

// 6. Ambil Riwayat
app.get("/api/history", authenticateToken, async function (req, res) {
  try {
    var userId = req.user.id;
    var historyResult = await pool.query(
      "SELECT * FROM riwayat_simulasi WHERE user_id = $1 ORDER BY tanggal_simulasi DESC",
      [userId]
    );
    res.status(200).json(historyResult.rows);
  } catch (error) {
    console.error("Error fetch history:", error);
    res.status(500).json({ message: "Terjadi kesalahan saat mengambil riwayat." });
  }
});

// Health Check
app.get("/", function (req, res) {
  res.json({ status: "ok", message: "Server AgriOptima Backend Berjalan Lancar!", version: "4.0" });
});

var PORT = process.env.PORT || 5000;
app.listen(PORT, function () {
  console.log("Server berjalan di http://localhost:" + PORT);
});
