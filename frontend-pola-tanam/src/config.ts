// Alamat dasar API. Kosong = alamat yang sama dengan situs (fungsi /api di Vercel).
// Untuk menguji ke server lain saat pengembangan, isi VITE_API_URL di berkas .env.
export const API_BASE: string = (import.meta.env.VITE_API_URL as string | undefined) ?? '';

