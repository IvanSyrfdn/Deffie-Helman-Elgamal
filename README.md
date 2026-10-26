# Pengiriman Nilai dan KRS Terenkripsi (Diffie-Hellman + ElGamal)

Aplikasi web untuk tugas matakuliah Kriptografi. BAAK mengirim data nilai atau KRS ke dosen wali secara terenkripsi. Diffie-Hellman menyepakati kunci sesi, ElGamal mengenkripsi isi data, dan setiap langkah perhitungan ditampilkan di halaman.

Seluruh algoritma ditulis dari nol. Tidak ada library atau framework pihak ketiga, hanya modul bawaan Python.

## Fitur

- Pertukaran kunci Diffie-Hellman dan enkripsi ElGamal buatan sendiri (perpangkatan modular, invers modular dengan Euclid, uji prima Miller-Rabin, pembuatan safe prime).
- Tampilan step by step untuk pembuatan kunci, enkripsi, dan dekripsi.
- Pilihan ukuran bilangan prima: 16-bit (mudah dicek dengan kalkulator), 64-bit, dan 256-bit.
- Login dengan dua role: BAAK (pengirim) dan dosen wali (penerima).
- Kotak masuk untuk penerima yang berisi ciphertext.
- SHA-256 buatan sendiri untuk hash password bersalt, sesi cookie, dan pembatasan percobaan login.

## Struktur folder

```
kripto-nilai/
├── app.py            server web (http.server) dan pemeriksaan hak akses
├── auth.py           SHA-256, hash password, login, sesi
├── crypto_utils.py   Diffie-Hellman, ElGamal, dan matematika pendukung
├── index.html        antarmuka web
└── README.md
```

## Kebutuhan

- Python 3.8 atau lebih baru (diuji di Python 3.12)
- Tidak perlu `pip install` apa pun

## Cara menjalankan (WSL Ubuntu)

```bash
cd kripto-nilai
python3 app.py
```

Buka `http://127.0.0.1:5000` di browser. Hentikan server dengan Ctrl+C.

## Akun demo

| Username | Password | Role |
|---|---|---|
| `baak` | `baak123` | Pengirim |
| `dosen` | `dosen123` | Penerima |

## Cara memakai

1. Login sebagai `baak`.
2. **Langkah 1:** pilih ukuran bilangan prima (mulai dari 16-bit) lalu klik **Buat kunci**. Halaman menampilkan p, g, kunci DH kedua pihak, shared secret K, dan kunci ElGamal.
3. **Langkah 2:** isi data nilai atau KRS lalu klik **Enkripsi dan kirim**. Halaman menampilkan perhitungan tiap blok. Ciphertext masuk ke kotak masuk penerima.
4. Keluar, lalu login sebagai `dosen`.
5. Di kotak masuk, pilih pesan lalu klik **Dekripsi** untuk melihat langkah dekripsi dan plaintext.
6. Untuk percobaan, ubah satu angka pada ciphertext sebelum dekripsi dan lihat hasilnya.

Membuat kunci baru menghapus pesan lama di kotak masuk, karena pesan lama tidak bisa didekripsi dengan kunci baru.

## Cara kerja singkat

1. Server membuat bilangan prima aman `p = 2q + 1` dan memakai `g = 4`.
2. Diffie-Hellman: `A = g^a mod p`, `B = g^b mod p`, lalu kedua pihak menghitung `K = g^(ab) mod p`.
3. ElGamal: kunci publik penerima `y = g^x mod p`. Tiap blok `m` dienkripsi menjadi `c1 = g^k mod p` dan `c2 = m * y^k mod p`.
4. Lapisan DH: `c2' = c2 * K^(n+i) mod p`, dengan `n` nonce acak per pesan dan `i` nomor blok.
5. Dekripsi membuka lapisan DH, lalu `m = c2 * (c1^x)^(-1) mod p`.

Teks dipecah per blok dan ditambah byte penanda `0x01` di depan agar nol di awal blok tidak hilang. Format ciphertext:

```
n|c1,c2';c1,c2';...
```

## Endpoint API

| Endpoint | Metode | Akses |
|---|---|---|
| `/api/login` | POST | Publik |
| `/api/logout` | POST | Semua yang login |
| `/api/me` | GET | Semua yang login |
| `/api/setup` | POST | BAAK |
| `/api/encrypt` | POST | BAAK |
| `/api/inbox` | GET | Penerima |
| `/api/decrypt` | POST | Penerima |

Server mengembalikan 401 jika belum login dan 403 jika role tidak sesuai.

## Keterbatasan

Program ini untuk pembelajaran, bukan untuk data sungguhan.

- Prima 16 dan 64 bit sangat lemah. Penggunaan nyata memerlukan minimal 2048 bit.
- Lapisan DH (`mask`) adalah konstruksi buatan sendiri dan bukan skema standar.
- Pertukaran DH tidak diautentikasi, jadi rentan terhadap man-in-the-middle.
- ElGamal tidak menjamin integritas. Ciphertext yang diubah biasanya gagal didekripsi, tetapi itu bukan jaminan.
- Antarmuka BAAK menampilkan kunci privat penerima karena tugas meminta semua langkah ditampilkan.
- Pengirim dan penerima disimulasikan dalam satu proses, dan data hanya disimpan di memori.
- Server hanya cocok dijalankan lokal. Tanpa HTTPS dan cookie `Secure`, jangan dipublikasikan.
- Akun demo ditulis di `auth.py` dan belum ada fitur registrasi.


## Pembuat
| Nama                        | NRP        |
| --------------------------- | ---------- |
| Hansen Chang                | 5027241028 |
| Ivan Syarifuddin            | 5027241045 |
| Hafiz Ramadhan              | 5027241096 |