import React from 'react';
import { Link } from 'react-router-dom';

const NOMOR_WA = '6285830847093'; // 0858-3084-7093
const NOMOR_TAMPIL = '0858-3084-7093';
const PESAN = 'Halo Admin AgriOptima, saya lupa password akun saya. Mohon bantuannya untuk reset password. Email terdaftar: ';

const ForgotPassword: React.FC = () => {
  const tautanWa = `https://wa.me/${NOMOR_WA}?text=${encodeURIComponent(PESAN)}`;

  return (
    <div className="min-h-screen bg-agri-light flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full bg-white p-8 rounded-xl shadow-lg border border-gray-100">
        <div className="text-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Lupa Password?</h2>
          <p className="mt-2 text-sm text-gray-600">
            Reset password dilakukan oleh admin. Silakan hubungi kami melalui WhatsApp dan sebutkan
            email yang Anda daftarkan.
          </p>
        </div>

        <a
          href={tautanWa}
          target="_blank"
          rel="noopener noreferrer"
          className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-white font-bold bg-green-600 hover:bg-green-700 transition"
        >
          Hubungi Admin via WhatsApp
        </a>
        <p className="mt-3 text-center text-sm text-gray-500">Nomor admin: <span className="font-semibold text-gray-700">{NOMOR_TAMPIL}</span></p>

        <div className="mt-6 text-center">
          <Link to="/login" className="text-sm font-bold text-gray-500 hover:text-agri-green transition">
            &larr; Kembali ke Login
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
