// ============================================================
// API AgriOptima (Vercel Serverless Function) + database Neon (PostgreSQL)
// Satu fungsi menangani semua rute /api/* (lihat vercel.json).
// Variabel lingkungan yang dibutuhkan di Vercel:
//   DATABASE_URL : connection string Neon (gunakan yang "pooled")
//   JWT_SECRET   : kalimat acak panjang untuk menandatangani token
// Tabel dibuat otomatis saat permintaan pertama (CREATE TABLE IF NOT EXISTS).
// ============================================================
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;

let pool = null;
function getPool() {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new Error('KONFIG_DB');
  if (!pool) {
    pool = new Pool({ connectionString: url, ssl: { rejectUnauthorized: false }, max: 3 });
  }
  return pool;
}

const SKEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  nama VARCHAR(100) NOT NULL,
  instansi VARCHAR(100) NOT NULL DEFAULT '',
  email VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_verified BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));
CREATE TABLE IF NOT EXISTS riwayat_simulasi (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  tanggal_simulasi TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  luas_lahan NUMERIC NOT NULL,
  total_tanaman_aktif INTEGER NOT NULL,
  rekomendasi_pola VARCHAR(255) NOT NULL,
  estimasi_pendapatan NUMERIC NOT NULL
);
`;

let skemaSiap = null;
function pastikanSkema() {
  if (!skemaSiap) {
    skemaSiap = getPool()
      .query(SKEMA)
      .catch((e) => {
        skemaSiap = null;
        throw e;
      });
  }
  return skemaSiap;
}

function kirim(res, status, data) {
  res.status(status).setHeader('Cache-Control', 'no-store').json(data);
}

function bacaBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  return {};
}

function ambilPengguna(req) {
  const header = req.headers['authorization'] || '';
  const token = header.split(' ')[1];
  if (!token) return { error: [401, 'Akses ditolak. Token tidak ditemukan.'] };
  if (!process.env.JWT_SECRET) throw new Error('KONFIG_JWT');
  try {
    return { user: jwt.verify(token, process.env.JWT_SECRET) };
  } catch {
    return { error: [403, 'Sesi telah berakhir. Silakan login kembali.'] };
  }
}

export default async function handler(req, res) {
  try {
    const u = new URL(req.url, 'http://localhost');
    // vercel.json meneruskan /api/* ke fungsi ini dengan parameter ?route=...
    const rute = u.searchParams.get('route');
    const path = (rute !== null ? '/api/' + rute : u.pathname).replace(/\/+$/, '');
    const metode = req.method;

    if (path === '/api/health') return kirim(res, 200, { status: 'ok' });

    await pastikanSkema();
    const db = getPool();
    const body = bacaBody(req);

    // ---- Registrasi (akun langsung aktif)
    if (path === '/api/auth/register' && metode === 'POST') {
      const nama = String(body.nama || '').trim();
      const instansi = String(body.instansi || '').trim();
      const email = String(body.email || '').trim();
      const password = String(body.password || '');
      if (!nama || !email || !password) {
        return kirim(res, 400, { message: 'Nama, email, dan password wajib diisi.' });
      }
      if (password.length < 6) {
        return kirim(res, 400, { message: 'Password harus terdiri dari minimal 6 karakter.' });
      }
      const ada = await db.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
      if (ada.rows.length > 0) {
        return kirim(res, 400, { message: 'Email sudah terdaftar di sistem!' });
      }
      const hash = await bcrypt.hash(password, 10);
      const baru = await db.query(
        'INSERT INTO users (nama, instansi, email, password_hash, is_verified) VALUES ($1, $2, $3, $4, TRUE) RETURNING email',
        [nama, instansi, email, hash],
      );
      return kirim(res, 201, {
        message: 'Registrasi berhasil! Akun Anda sudah aktif, silakan masuk.',
        email: baru.rows[0].email,
      });
    }

    // ---- Login
    if (path === '/api/auth/login' && metode === 'POST') {
      const email = String(body.email || '').trim();
      const password = String(body.password || '');
      if (!process.env.JWT_SECRET) throw new Error('KONFIG_JWT');
      const hasil = await db.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
      const user = hasil.rows[0];
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return kirim(res, 401, { message: 'Email atau password salah!' });
      }
      const token = jwt.sign(
        { id: user.id, email: user.email, nama: user.nama, instansi: user.instansi },
        process.env.JWT_SECRET,
        { expiresIn: '24h' },
      );
      return kirim(res, 200, {
        message: 'Login berhasil!',
        token,
        user: { id: user.id, nama: user.nama, email: user.email, instansi: user.instansi },
      });
    }

    // ---- Rute yang butuh login
    if (path === '/api/auth/profile' || path === '/api/auth/change-password' || path === '/api/history') {
      const { user, error } = ambilPengguna(req);
      if (error) return kirim(res, error[0], { message: error[1] });

      if (path === '/api/auth/profile' && metode === 'GET') {
        const r = await db.query('SELECT id, nama, instansi, email, created_at FROM users WHERE id = $1', [user.id]);
        if (r.rows.length === 0) return kirim(res, 404, { message: 'Pengguna tidak ditemukan' });
        return kirim(res, 200, r.rows[0]);
      }

      if (path === '/api/auth/change-password' && metode === 'POST') {
        const passwordLama = String(body.currentPassword || '');
        const passwordBaru = String(body.newPassword || '');
        if (passwordBaru.length < 6) {
          return kirim(res, 400, { message: 'Password baru harus terdiri dari minimal 6 karakter.' });
        }
        const r = await db.query('SELECT * FROM users WHERE id = $1', [user.id]);
        if (r.rows.length === 0) return kirim(res, 404, { message: 'Pengguna tidak ditemukan' });
        if (!(await bcrypt.compare(passwordLama, r.rows[0].password_hash))) {
          return kirim(res, 400, { message: 'Password saat ini yang Anda masukkan salah!' });
        }
        const hash = await bcrypt.hash(passwordBaru, 10);
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, user.id]);
        return kirim(res, 200, { message: 'Password berhasil diperbarui!' });
      }

      if (path === '/api/history' && metode === 'POST') {
        const r = await db.query(
          'INSERT INTO riwayat_simulasi (user_id, luas_lahan, total_tanaman_aktif, rekomendasi_pola, estimasi_pendapatan) VALUES ($1, $2, $3, $4, $5) RETURNING *',
          [user.id, body.luas_lahan, body.total_tanaman_aktif, body.rekomendasi_pola, body.estimasi_pendapatan],
        );
        return kirim(res, 201, { message: 'Riwayat berhasil disimpan!', data: r.rows[0] });
      }

      if (path === '/api/history' && metode === 'GET') {
        const r = await db.query('SELECT * FROM riwayat_simulasi WHERE user_id = $1 ORDER BY tanggal_simulasi DESC', [user.id]);
        return kirim(res, 200, r.rows);
      }
    }

    return kirim(res, 404, { message: 'Rute tidak ditemukan.' });
  } catch (err) {
    console.error('Error API:', err);
    if (err && err.message === 'KONFIG_DB') {
      return kirim(res, 500, { message: 'Database belum dikonfigurasi (DATABASE_URL belum diatur).' });
    }
    if (err && err.message === 'KONFIG_JWT') {
      return kirim(res, 500, { message: 'JWT_SECRET belum diatur di server.' });
    }
    return kirim(res, 500, { message: 'Terjadi kesalahan pada server.' });
  }
}

