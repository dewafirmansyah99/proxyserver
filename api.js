// File: server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const fs_promises = require('fs').promises;
const path = require('path');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { MongoClient } = require("mongodb");
const { GoogleAuth } = require('google-auth-library');
const { Storage } = require('@google-cloud/storage');
require('dotenv').config();
// const upload = multer({ dest: 'uploads/' });
// const fetch = require('node-fetch')
// import { GoogleGenerativeAI } from "@google/generative-ai";
// import fetch from 'node-fetch';

const app = express();
const port = process.env.PORT;

// ====================================================================================
console.log('--- STARTING APP ---');

// Log untuk memeriksa variabel lingkungan GOOGLE_APPLICATION_CREDENTIALS_JSON
console.log('Checking GOOGLE_APPLICATION_CREDENTIALS_JSON...');
const credentialsJson = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON;

if (credentialsJson) {
    console.log('GOOGLE_APPLICATION_CREDENTIALS_JSON DITEMUKAN!');
    try {
        const parsed = JSON.parse(credentialsJson);
        console.log('JSON Berhasil di-parse. Project ID:', parsed.project_id);
        // Jangan log 'private_key' atau data sensitif lainnya secara penuh!
        console.log('Client Email:', parsed.client_email);
    } catch (e) {
        console.error('ERROR: Gagal mem-parse GOOGLE_APPLICATION_CREDENTIALS_JSON:', e.message);
        console.error('Mungkin format JSON salah di Railway. Coba pastikan tidak ada kutipan tambahan di awal/akhir.');
    }
} else {
    console.warn('PERINGATAN: GOOGLE_APPLICATION_CREDENTIALS_JSON TIDAK DITEMUKAN!');
    console.warn('Pastikan variabel lingkungan ini diatur dengan benar di Railway.');
}

// ... kemudian inisialisasi GoogleAuth dan Storage client Anda
const auths = new GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/cloud-platform'], // Sesuaikan dengan kebutuhan izin Anda
});
const storages = new Storage(); // Ini akan mencoba memuat kredensial default
// ====================================================================================

const projectId = process.env.NODE_PROJECT_ID;
async function authenticateImplicitWithAdc() {
    // This snippet demonstrates how to list buckets.
    // NOTE: Replace the client created below with the client required for your application.
    // Note that the credentials are not specified when constructing the client.
    // The client library finds your credentials using ADC.
    const storage = new Storage({
        projectId,
    });
    const [buckets] = await storage.getBuckets();
    console.log('Buckets:');

    for (const bucket of buckets) {
        console.log(`- ${bucket.name}`);
    }

    console.log('Listed all storage buckets.NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN');
}

authenticateImplicitWithAdc();

// const apikey = process.env.NODE_API_KEY;
// async function authenticateWithAPIKey(apiKey) {
//     const auth = new GoogleAuth({ apiKey });
//     const language = new LanguageServiceClient({ auth });

//     const text = 'Hello, world!';

//     const [response] = await language.analyzeSentiment({
//         document: {
//             content: text,
//             type: 'PLAIN_TEXT',
//         },
//     });

//     console.log(`Text: ${text}`);
//     console.log(
//         `Sentiment: ${response.documentSentiment.score}, ${response.documentSentiment.magnitude}`,
//     );
//     console.log('Successfully authenticated using the API key');
// }

// authenticateWithAPIKey(apikey);

// Middleware
app.use(cors()); // Mengaktifkan CORS untuk semua permintaan
app.use(bodyParser.json()); // Parsing body dalam format JSON
app.use(express.json({ limit: '200mb', extended: true }));
app.use(express.urlencoded({ limit: '200mb', extended: true, parameterLimit: 50000 }));

// Konfigurasi Mailtrap
const MAILTRAP_API_URL = process.env.NODE_MAILTRAP_API_URL;
const MAILTRAP_API_TOKEN = process.env.NODE_MAILTRAP_API_TOKEN;
// const MAILTRAP_API_URL = 'https://send.api.mailtrap.io/api/send';
// const MAILTRAP_API_TOKEN = 'fdcac0793747c5bd073a8d56667aa09b';

const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform', // Sesuaikan scope yang dibutuhkan
    // scopes: 'https://www.googleapis.com/auth/devstorage.read_only'
});

let cachedAccessToken = null;
let accessTokenExpiry = null;
const storage = new Storage();
const bucketName = 'shiradoc_file_demo'

// Endpoint untuk mengirim OTP via Mailtrap
app.post('/api/send-otp', async (req, res) => {
    try {
        // Mendapatkan data email dan token dari request
        const { emailUser, token } = req.body;

        if (!emailUser || !token) {
            return res.status(400).json({
                error: 'Email dan token OTP harus disediakan'
            });
        }

        // Membuat data email sesuai format yang dibutuhkan
        const emailData = {
            from: { email: "hello@demomailtrap.co", name: "Shiradoc" },
            to: [{ email: emailUser }],
            subject: "Kode OTP dari shiradoc",
            text: `Hai, ini adalah kode otp kamu: ${token}`,
            category: "Integration Test"
        };

        // Log request (opsional, untuk debugging)
        console.log('Mengirim OTP ke:', emailUser);

        // Kirim permintaan ke Mailtrap API
        const response = await axios.post(MAILTRAP_API_URL, emailData, {
            headers: {
                'Authorization': `Bearer ${MAILTRAP_API_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });

        // Log respons (opsional, untuk debugging)
        console.log('OTP berhasil dikirim ke:', emailUser);

        // Kirim respons Mailtrap ke klien
        res.status(200).json({
            success: true,
            message: 'OTP berhasil dikirim',
            data: response.data
        });
    } catch (error) {
        // Tangani error
        console.error('Error saat mengirim OTP:',
            error.response?.data || error.message);

        // Kirim error ke klien
        res.status(error.response?.status || 500).json({
            success: false,
            error: error.response?.data || error.message
        });
    }
});

// Endpoint sederhana untuk testing
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server proxy Shiradoc OTP berjalan' });
});

// Konfigurasi multer untuk upload file
// const upload = multer({
//     storage: multer.memoryStorage(), // Simpan file di memori
//     limits: { fileSize: 10 * 1024 * 1024 } // Batasi ukuran file 10MB
// });
const upload = multer();

// Konfigurasi Gemini API
const GEMINI_API_KEY = process.env.NODE_GEMINI_API_KEY; // Ganti dengan API Key Anda
const BASE_URL = process.env.NODE_BASE_URL;
// const GEMINI_API_KEY = 'AIzaSyCtbAxw1yIfyMndAX9RI7G1qyI5SsQd_vU'; // Ganti dengan API Key Anda
// const BASE_URL = 'https://generativelanguage.googleapis.com';
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: 'models/gemini-1.5-flash' });

// Fungsi untuk mendownload file dari URL
async function downloadFileFromUrl(url) {
    try {
        const response = await axios.get(url, {
            responseType: 'arraybuffer'
        });

        // Ekstrak nama file dari URL
        const urlParts = new URL(url);
        const fileName = path.basename(urlParts.pathname) || 'downloaded-file.pdf';

        return {
            buffer: Buffer.from(response.data),
            fileName: fileName,
            contentType: response.headers['content-type'] || 'application/pdf'
        };
    } catch (error) {
        console.error('Kesalahan mengunduh file dari URL:', error);
        throw new Error(`Gagal mengunduh file: ${error.message}`);
    }
}

async function uploadFileToGemini(fileBuffer, fileName, contentType = 'application/pdf') {
    try {
        // Dapatkan ukuran file
        const numBytes = fileBuffer.length;

        // Tahap 1: Inisiasi unggahan resumable
        const initiateUploadResponse = await axios.post(
            `${BASE_URL}/upload/v1beta/files?key=${GEMINI_API_KEY}`,
            { file: { display_name: fileName } },
            {
                headers: {
                    'X-Goog-Upload-Protocol': 'resumable',
                    'X-Goog-Upload-Command': 'start',
                    'X-Goog-Upload-Header-Content-Length': numBytes.toString(),
                    'X-Goog-Upload-Header-Content-Type': contentType,
                    'Content-Type': 'application/json'
                }
            }
        );

        const uploadUrl = initiateUploadResponse.headers['x-goog-upload-url'];

        if (!uploadUrl) {
            throw new Error('Gagal mendapatkan URL unggahan');
        }

        // Tahap 2: Unggah file
        const uploadFileResponse = await axios.post(uploadUrl, fileBuffer, {
            headers: {
                'Content-Length': numBytes.toString(),
                'X-Goog-Upload-Offset': '0',
                'X-Goog-Upload-Command': 'upload, finalize'
            }
        });

        const fileInfo = uploadFileResponse.data;
        const fileUri = fileInfo.file.uri;

        return fileUri;
    } catch (error) {
        console.error('Kesalahan mengunggah file:', error);
        throw error;
    }
}

async function generateContentWithFile(fileUri, prompt, mimeType = 'application/pdf') {
    try {
        const response = await axios.post(
            `${BASE_URL}/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
            {
                contents: [{
                    parts: [
                        { text: prompt },
                        { file_data: { mime_type: mimeType, file_uri: fileUri } }
                    ]
                }]
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );

        return response.data.candidates[0]?.content?.parts[0]?.text || 'Tidak ada konten yang dihasilkan';
    } catch (error) {
        console.error('Kesalahan menghasilkan konten:', error);
        throw error;
    }
}

// Endpoint untuk file yang diupload
app.post('/api/generate-content', upload.single('file'), async (req, res) => {
    try {
        const { prompt = "Jelaskan isi dokumen ini secara ringkas" } = req.body;
        const { fileUrl } = req.body;

        let fileBuffer, fileName, contentType;

        // Cek apakah menggunakan file yang diupload atau URL
        if (fileUrl) {
            // Jika menggunakan URL
            const downloadedFile = await downloadFileFromUrl(fileUrl);
            fileBuffer = downloadedFile.buffer;
            fileName = downloadedFile.fileName;
            contentType = downloadedFile.contentType;
        } else if (req.file) {
            // Jika menggunakan file yang diupload
            fileBuffer = req.file.buffer;
            fileName = req.file.originalname;
            contentType = req.file.mimetype || 'application/pdf';
        } else {
            return res.status(400).json({ error: 'Tidak ada file yang diunggah atau URL yang valid' });
        }

        // Unggah file ke Gemini
        const fileUri = await uploadFileToGemini(fileBuffer, fileName, contentType);

        // Hasilkan konten
        const generatedContent = await generateContentWithFile(fileUri, prompt, contentType);

        // Kirim respons
        res.json({
            fileUri,
            generatedContent
        });
    } catch (error) {
        console.error('Kesalahan dalam proses:', error);
        res.status(500).json({
            error: 'Gagal memproses permintaan',
            details: error.message
        });
    }
});

// Endpoint alternatif untuk URL saja
app.post('/api/generate-content-from-url', async (req, res) => {
    try {
        const { fileUrl, prompt = "Jelaskan isi dokumen ini secara ringkas" } = req.body;

        if (!fileUrl) {
            return res.status(400).json({ error: 'URL file harus disediakan' });
        }

        // Download file dari URL
        const downloadedFile = await downloadFileFromUrl(fileUrl);

        // Unggah file ke Gemini
        const fileUri = await uploadFileToGemini(
            downloadedFile.buffer,
            downloadedFile.fileName,
            downloadedFile.contentType
        );

        // Hasilkan konten
        const generatedContent = await generateContentWithFile(
            fileUri,
            prompt,
            downloadedFile.contentType
        );

        // Kirim respons
        res.json({
            fileUri,
            generatedContent
        });
    } catch (error) {
        console.error('Kesalahan dalam proses:', error);
        res.status(500).json({
            error: 'Gagal memproses permintaan',
            details: error.message
        });
    }
});

// Function to convert ArrayBuffer to Base64 manually
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

// Helper function to download file as buffer
async function downloadFileAsBuffer(url) {
    try {
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
        }

        return await response.arrayBuffer();
    } catch (error) {
        console.error("Error downloading file:", error);
        throw error;
    }
}

function convertToBase64(dataBuffer) {
    // Convert to Base64
    let base64Data;
    try {
        // Use Node.js Buffer for conversion (more efficient)
        base64Data = Buffer.from(dataBuffer).toString('base64');
    } catch (error) {
        // Fallback to manual conversion if Buffer fails
        base64Data = arrayBufferToBase64(dataBuffer);
    }
    return base64Data
}

// API endpoint to summarize PDF from URL
app.post('/api/summarize-pdf/url', async (req, res) => {
    try {
        const { url, prompt = 'Summarize this document' } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'PDF URL is required' });
        }

        // Download the PDF as buffer
        const fileBuffer = await downloadFileAsBuffer(url);

        const base64Data = convertToBase64(fileBuffer)

        // Generate content using Gemini model
        const result = await model.generateContent([
            {
                inlineData: {
                    data: base64Data,
                    mimeType: "application/pdf",
                },
            },
            prompt,
        ]);

        const summary = result.response.text();

        // Return the summary
        res.json({
            success: true,
            summary,
            metadata: {
                url,
                prompt,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error("Error processing PDF:", error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

async function originaFileAsBuffer(file) {
    try {
        console.log(file, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        const filePath = file.path;
        const fileBuffer = fs.readFileSync(filePath);
        const base64Data = fileBuffer.toString('base64');
        return base64Data
    } catch (error) {
        console.error("Error create buffer from file:", error);
        throw error;
    }
}

app.post('/api/summarize-pdf/file', upload.single('file'), async (req, res) => {
    try {
        // Ambil file dari req.file (bukan req.body.file)
        const uploadedFile = req.file;
        const { prompt = 'Summarize this document' } = req.body;

        if (!uploadedFile) {
            return res.status(400).json({ error: 'PDF File is required' });
        }

        // Proses file yang diupload
        const base64Data = await originaFileAsBuffer(uploadedFile);
        console.log(base64Data.substring(0, 100), "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"); // Hanya menampilkan awal base64 untuk debug

        // Tidak perlu konversi lagi karena originaFileAsBuffer sudah mengembalikan base64
        // const base64Data = convertToBase64(fileBuffer) <- hapus baris ini

        // Generate content using Gemini model
        const result = await model.generateContent([
            {
                inlineData: {
                    data: base64Data,
                    mimeType: uploadedFile.mimetype || "application/pdf",
                },
            },
            prompt,
        ]);

        const summary = result.response.text();

        // Return the summary
        res.json({
            success: true,
            summary,
            metadata: {
                filename: uploadedFile.originalname,
                prompt,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error("Error processing PDF:", error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// MongoDB Connection URI
// const uri = process.env.NODE_MONGO_URI;
const uri = `mongodb+srv://firmansyahdewa702:slayer702@cluster0.na6bp.mongodb.net/`;
const client = new MongoClient(uri);
let db;

// Koneksi ke MongoDB sekali saja
async function connectToMongo() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        db = client.db('shiradoc');
        return true;
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
        return false;
    }
}

app.post('/api/mongo/create/account', async (req, res) => {
    try {
        const { email, username, password } = req.body;

        if (!email || !username || !password) {
            return res.status(400).json({
                error: 'semua data harus di isi'
            });
        }

        const user = db.collection('user');

        const data = {
            email: email,
            username: username,
            password: password,
        }

        const result = await user.insertOne(data)

        console.log(`A document was inserted with the _id: ${result.insertedId}`);
        return res.status(200).json({
            success: true,
            message: 'Berhasil menambahkan user',
            result: result.insertedId
        });
    } catch (error) {
        console.error('Error in create account:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.get('/api/mongo/read/account', async (req, res) => {
    try {
        const items = db.collection('user');
        const { username } = req.query;

        if (!username) {
            return res.status(400).json({
                error: 'username harus ada'
            });
        }

        const query = { username: username };
        const res_user = await items.findOne(query);

        // Pastikan hanya mengirim respons sekali
        return res.json(res_user);
    } catch (error) {
        console.error('Error in read account:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.post('/api/mongo/create/chat', async (req, res) => {
    try {
        const { chat } = req.body;

        if (!chat) {
            return res.status(400).json({
                error: 'chat harus ada'
            });
        }

        const user = db.collection('chat');

        const data = {
            chat: chat,
        }

        const result = await user.insertOne(data)

        console.log(`A document was inserted with the _id: ${result.insertedId}`);
        return res.status(200).json({
            success: true,
            message: 'Berhasil menambahkan chat',
            result: result.insertedId
        });
    } catch (error) {
        console.error('Error in create chat:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.get('/api/mongo/read/chat', async (req, res) => {
    try {
        const items = db.collection('chat');
        const { username, title, chat_id } = req.query;
        let query = {}

        if (!username) {
            return res.status(400).json({
                error: 'username harus ada'
            });
        }

        // Set query dasar dengan username
        query = { "chat.username": username };

        // Tambahkan kondisi tambahan berdasarkan parameter yang diberikan
        if (title && title !== '') {
            console.log('Query dengan username dan title');
            query = {
                $and: [
                    { "chat.username": username },
                    { "chat.user": 1 }  // Apakah ini benar-benar filter berdasarkan title?
                ]
            };
        } else if (chat_id && chat_id !== '') {
            console.log('Query dengan username dan chat_id');
            query = {
                $and: [
                    { "chat.username": username },
                    { "chat.chat_id": chat_id }
                ]
            };
        } else {
            console.log('Query hanya dengan username');
        }

        // Limit to 1 result and sort by earliest time
        const res_user = await items.find(query).sort({ "chat.timestamp": 1 });

        // const res_user = await items.find(query);
        const array_data = await res_user.toArray();

        // Pastikan hanya mengirim respons sekali
        return res.json(array_data)
    } catch (error) {
        console.error('Error in read chat:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.get('/api/mongo/read/chat/id', async (req, res) => {
    try {
        const items = db.collection('chat');
        const { chat_id } = req.query;
        let query = {}

        if (!chat_id) {
            return res.status(400).json({
                error: 'chat_id harus ada'
            });
        }

        // Set query dasar dengan username
        query = { "chat.chat_id": chat_id };

        // Tambahkan kondisi tambahan berdasarkan parameter yang diberikan
        // if (title && title !== '') {
        //     console.log('Query dengan username dan title');
        //     query = {
        //         $and: [
        //             { "chat.username": username },
        //             { "chat.user": 1 }  // Apakah ini benar-benar filter berdasarkan title?
        //         ]
        //     };
        // } else if (chat_id && chat_id !== '') {
        //     console.log('Query dengan username dan chat_id');
        //     query = {
        //         $and: [
        //             { "chat.username": username },
        //             { "chat.chat_id": chat_id }
        //         ]
        //     };
        // } else {
        //     console.log('Query hanya dengan username');
        // }

        // Limit to 1 result and sort by earliest time
        const res_user = await items.find(query).sort({ "chat.timestamp": 1 });

        // const res_user = await items.find(query);
        const array_data = await res_user.toArray();

        // Pastikan hanya mengirim respons sekali
        return res.json(array_data)
    } catch (error) {
        console.error('Error in read chat:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.post('/api/mongo/create/buffer', async (req, res) => {
    try {
        const { buffer } = req.body;

        if (!buffer) {
            return res.status(400).json({
                error: 'buffer harus ada'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Berhasil membuat buffer',
            result: Buffer.from(buffer, 'base64')
        });
    } catch (error) {
        console.error('Error in create chat:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.get('/api/content/download', async (req, res) => {
    const link = req.query.url;

    try {
        // Pastikan URL disediakan
        if (!link) {
            return res.status(400).json({
                success: false,
                message: 'URL is required'
            });
        }

        // // Validasi URL (pastikan fungsi ini sudah didefinisikan)
        // if (!isValidUrl(link)) {
        //     return res.status(400).json({
        //         success: false,
        //         message: 'Invalid URL format'
        //     });
        // }

        // Buat request ke ulvis.net
        const response = await fetch(`https://ulvis.net/API/write/get?url=${encodeURIComponent(link)}`);

        // Periksa apakah response OK
        if (!response.ok) {
            return res.status(response.status).json({
                success: false,
                message: `Ulvis API returned status ${response.status}`
            });
        }

        const json = await response.json();
        console.log(json, "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT");

        // Validasi bahwa response memiliki format yang diharapkan
        if (!json.success || !json.data || !json.data.id) {
            return res.status(422).json({
                success: false,
                message: 'Invalid response from URL shortener service'
            });
        }

        // Kembalikan hasil
        return res.status(200).json({
            success: json.success,
            data: {
                id: json.data.id,
                url: json.data.url,
                full: json.data.full
            }
        });
    } catch (error) {
        console.error('URL shortening error:', error);
        return res.status(500).json({
            success: false,
            message: 'Error shortening download URL',
            error: error.message
        });
    }
});

// async function getAccessToken() {
//     if (cachedAccessToken && accessTokenExpiry > Date.now()) {
//         return cachedAccessToken;
//     }

//     try {
//         const client = await auth.getClient();
//         const tokenResponse = await client.getAccessToken();
//         cachedAccessToken = tokenResponse.token;
//         accessTokenExpiry = Date.now() + (tokenResponse.expires_in * 1000) - 60000;
//         console.log(cachedAccessToken, "=====================================================")
//         return cachedAccessToken;
//     } catch (error) {
//         console.error('Failed to get new access token:', error);
//         cachedAccessToken = null;
//         accessTokenExpiry = null;
//         throw error;
//     }
// }

async function getAccessToken() {
    if (cachedAccessToken && accessTokenExpiry > Date.now()) {
        console.log("Using cached access token.");
        return cachedAccessToken;
    }

    try {
        console.log("Attempting to get new access token...");
        const client = await auth.getClient(); // Ini harus berhasil sekarang
        const tokenResponse = await client.getAccessToken();

        if (!tokenResponse || !tokenResponse.token || !tokenResponse.expires_in) {
            throw new Error('Invalid token response from Google Auth client.');
        }

        cachedAccessToken = tokenResponse.token;
        // Kurangi beberapa detik/menit dari expiry untuk keamanan (misalnya, 5 menit = 300000 ms)
        accessTokenExpiry = Date.now() + (tokenResponse.expires_in * 1000) - 300000;

        console.log("Successfully obtained new access token. Expires in:", (tokenResponse.expires_in / 60).toFixed(2), "minutes.");
        // console.log(cachedAccessToken, "====================================================="); // Hindari log token ke console di produksi
        return cachedAccessToken;
    } catch (error) {
        console.error('Failed to get new access token:', error.message); // Log error message saja
        cachedAccessToken = null;
        accessTokenExpiry = null;
        throw error;
    }
}

app.get('/api/get-access-token-cache', async (req, res) => {
    if (cachedAccessToken) {
        res.json({ token: cachedAccessToken });
    }
    if (!cachedAccessToken) {
        try {
            const accessToken = await getAccessToken();
            return res.json({ token: accessToken });
        } catch (error) {
            return res.status(500).json({ error: 'Failed to retrieve access token' });
        }
    }
});

app.get('/api/get-access-token', async (req, res) => {
    try {
        const accessToken = await getAccessToken();
        return res.json({ token: accessToken });
    } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve access token' });
    }
});

app.get('/api/list-buckets', async (req, res) => {
    try {
        const accessToken = await getAccessToken();
        const response = await axios.get('https://storage.googleapis.com/storage/v1/b?project=gen-lang-client-0500049568', {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        res.json({ buckets: response.data.items ? response.data.items.map(item => item.name) : [] });
    } catch (error) {
        console.error('Error listing buckets:', error);
        if (error.response && error.response.status === 401) {
            // Jika token tidak valid, coba dapatkan token baru dan coba lagi (sederhana)
            try {
                cachedAccessToken = null;
                accessTokenExpiry = null;
                const newAccessToken = await getAccessToken();
                const retryResponse = await axios.get('https://storage.googleapis.com/storage/v1/b?project=gen-lang-client-0500049568', {
                    headers: {
                        Authorization: `Bearer ${newAccessToken}`,
                    },
                });
                return res.json({ buckets: retryResponse.data.items ? retryResponse.data.items.map(item => item.name) : [] });
            } catch (retryError) {
                console.error('Failed to refresh and list buckets:', retryError);
                return res.status(401).json({ error: 'Authentication failed after refresh' });
            }
        }
        res.status(500).json({ error: 'Failed to list buckets' });
    }
});

// Contoh sederhana endpoint untuk "refresh" token (sebenarnya hanya meminta token baru)
app.get('/api/refresh-access-token', async (req, res) => {
    cachedAccessToken = null;
    accessTokenExpiry = null;
    try {
        const newAccessToken = await getAccessToken();
        res.json({ accessToken: newAccessToken });
    } catch (error) {
        res.status(500).json({ error: 'Failed to refresh access token' });
    }
});

async function fetchMetadataWithRetry(bucketName, fileName, folderName, maxRetries = 10, delay = 1000) {
    let attempt = 0;
    while (attempt < maxRetries) {
        attempt++;
        const accessToken = cachedAccessToken;
        const url = `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${encodeURIComponent(folderName)}%2F${encodeURIComponent(fileName)}`;
        console.error(`Attempt ${attempt}: Fetching metadata for ${bucketName}/${folderName}/${fileName}`);
        try {
            const response = await axios.get(url, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });
            console.log(`Metadata fetched successfully on attempt ${attempt}`);
            return response.data;
        } catch (error) {
            console.error(`Attempt ${attempt} failed:`, error.message);
            if (error.response && error.response.status === 401) {
                console.log("Authentication error, trying to refresh token...");
                cachedAccessToken = null;
                const newAccessToken = await getAccessToken();
                console.log("New token obtained.");
                // Retry dengan token baru pada iterasi berikutnya
            } else if (attempt < maxRetries) {
                console.log(`Retrying in ${delay / 1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                console.error('Max retries reached, fetching metadata failed.');
                throw error; // Re-throw error setelah semua percobaan gagal
            }
        }
    }
    // Ini seharusnya tidak tercapai jika loop berhasil
    throw new Error('Failed to fetch metadata after multiple retries.');
}

app.get('/api/bucket/metadata', async (req, res) => {
    const bucketNames = req.query.bucketname;
    const fileName = req.query.filename;
    const folderName = req.query.foldername;
    console.error(`bucketNames = ${bucketNames}, fileName = ${fileName}, folderName = ${folderName}`)
    try {
        const metadata = await fetchMetadataWithRetry(bucketNames, fileName, folderName);
        return res.status(200).json({
            success: 'sukses mendapatkan data',
            data: metadata
        });
    } catch (error) {
        console.error('Gagal mendapatkan metadata setelah mencoba beberapa kali:', error);
        if (error.response && error.response.status === 401) {
            return res.status(401).json({ error: 'Authentication failed after multiple retries' });
        }
        return res.status(error.response ? error.response.status : 500).json({
            error: 'Gagal mendapatkan metadata',
            details: error.message
        });
    }
    // try {
    //     const accessToken = cachedAccessToken;
    //     const response = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketNames}/o/${folderName}%2F${fileName}`, {
    //         headers: {
    //             Authorization: `Bearer ${accessToken}`,
    //         },
    //     });
    //     console.log("TOKEN LAMA", accessToken)
    //     return res.status(200).json({
    //         success: 'sukses mendapatkan data',
    //         data: response.data
    //     });
    // } catch (error) {
    //     console.error('Gagal mendownload file:', error);
    //     if (error.response && error.response.status === 401) {
    //         try {
    //             cachedAccessToken = null;
    //             const newAccessToken = await getAccessToken();
    //             const retryResponse = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketNames}/o/${folderName}%2F${fileName}`, {
    //                 headers: {
    //                     Authorization: `Bearer ${newAccessToken}`,
    //                 },
    //             });
    //             console.log("TOKEN BARU", newAccessToken)
    //             return res.status(200).json({
    //                 success: 'sukses mendapatkan data',
    //                 data: retryResponse.data
    //             });
    //         } catch (retryError) {
    //             console.error('Failed get metadata:', retryError);
    //             return res.status(401).json({ error: 'Authentication failed after refresh' });
    //         }
    //     }
    // }
});

app.get('/api/bucket/folders/read', async (req, res) => {
    var listFolders = []
    const bucketName = req.query.bucketName;
    try {
        const accessToken = cachedAccessToken;
        const response = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketName}/folders`, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        console.log("TOKEN LAMA", accessToken)
        if (response.data && response.data.items) {
            { response.data.items.map((items, index) => listFolders.push(items.name)) }
        }
        return res.status(200).json({
            success: 'sukses mendapatkan data',
            listData: listFolders,
            data: response.data
        });
    } catch (error) {
        console.error('Gagal mendapatkan folder:', error);
        if (error.response && error.response.status === 401) {
            try {
                cachedAccessToken = null;
                const newAccessToken = await getAccessToken();
                const retryResponse = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketName}/folders`, {
                    headers: {
                        Authorization: `Bearer ${newAccessToken}`,
                    },
                });
                console.log("TOKEN BARU", newAccessToken)
                if (retryResponse.data && retryResponse.data.items) {
                    { retryResponse.data.items.map((items, index) => listFolders.push(items.name)) }
                }
                return res.status(200).json({
                    success: 'sukses mendapatkan data',
                    listData: listFolders,
                    data: retryResponse.data
                });
            } catch (retryError) {
                console.error('Failed get folders:', retryError);
                return res.status(401).json({ error: 'Authentication failed after refresh' });
            }
        }
    }
});

app.post('/api/bucket/folders/create', async (req, res) => {
    try {
        const { name } = req.body;
        const bucketName = req.query.bucketName;
        const data = {
            name: name
        }

        if (!name) {
            return res.status(400).json({
                error: 'nama folder harus ada'
            });
        }
        const accessToken = cachedAccessToken;
        const response = await axios.post(`https://storage.googleapis.com/storage/v1/b/${bucketName}/folders?recursive=true`, data, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
        });
        console.log(response, "RRRRRRRRRRRRRRRRRRRRRR")

        return res.status(200).json({
            success: true,
            message: 'Berhasil membuat folder baru',
            // response: response
        });
    } catch (error) {
        if (error.response && error.response.status === 401) {
            try {
                const { name } = req.body;
                const bucketName = req.query.bucketName;
                const data = {
                    name: name
                }

                if (!name) {
                    return res.status(400).json({
                        error: 'nama folder harus ada'
                    });
                }
                cachedAccessToken = null;
                const newAccessToken = await getAccessToken();
                const retryResponse = await axios.post(`https://storage.googleapis.com/storage/v1/b/${bucketName}/folders?recursive=true`, data, {
                    headers: {
                        'Authorization': `Bearer ${newAccessToken}`,
                        'Content-Type': 'application/json'
                    },
                });
                console.log(retryResponse, "RRRRRRRRRRRRRRRRRRRRRR")
                return res.status(200).json({
                    success: true,
                    message: 'Berhasil membuat folder baru',
                    // response: retryResponse
                });
            } catch (retryError) {
                console.error('Failed create folders:', retryError);
                return res.status(401).json({ error: 'Authentication failed after refresh' });
            }
        }
    }
});

app.post('/api/bucket/upload', upload.single('file'), async (req, res) => {
    try {
        console.log(req, "===================================================")
        console.log(req.body.file.buffer, "===================================================")
        const { bucketName, folderName, fileName } = req.query;
        const accessToken = cachedAccessToken;
        if (!bucketName || !fileName) {
            return res.status(400).json({ error: 'Parameter bucketName dan fileName harus disertakan dalam query.' });
        }
        const gcsFileName = `${folderName}/${fileName}`;
        const response = await axios.post(`https://storage.googleapis.com/upload/storage/v1/b/${bucketName}o?uploadType=media&name=${encodeURIComponent(gcsFileName)}`, req.body.file.buffer, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': req.file.mimetype
            },
        });
        console.log(response, "RRRRRRRRRRRRRRRRRRRRRR")

        return res.status(200).json({
            success: true,
            message: `Berhasil upload file ${fileName} ke folder ${folderName}`,
            data: response.data
        });
    } catch (error) {
        if (error.response && error.response.status === 401) {
            try {
                // if (!req.file) {
                //     return res.status(400).json({ error: 'Tidak ada file yang diunggah.' });
                // }
                const { bucketName, folderName, fileName } = req.query;
                cachedAccessToken = null;
                const newAccessToken = await getAccessToken();
                if (!bucketName || !fileName) {
                    return res.status(400).json({ error: 'Parameter bucketName dan fileName harus disertakan dalam query.' });
                }
                const gcsFileName = `${folderName}/${fileName}`
                const retryResponse = await axios.post(`https://storage.googleapis.com/upload/storage/v1/b/${bucketName}o?uploadType=media&name=${encodeURIComponent(gcsFileName)}`, req.file, {
                    headers: {
                        'Authorization': `Bearer ${newAccessToken}`,
                        'Content-Type': req.file.mimetype
                    },
                });
                console.log(retryResponse, "RRRRRRRRRRRRRRRRRRRRRR")
                return res.status(200).json({
                    success: true,
                    message: `Berhasil upload file ${fileName} ke folder ${folderName}`,
                    data: retryResponse.data
                });
            } catch (retryError) {
                console.error('Failed create folders:', retryError);
                return res.status(401).json({ error: 'Authentication failed after refresh' });
            }
        }
    }
});

app.get('/api/bucket/objects/read', async (req, res) => {
    var listObjects = []
    const bucketName = req.query.bucketName;
    const folderName = req.query.folderName;
    try {
        const accessToken = cachedAccessToken;
        const response = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketName}/o?prefix=${folderName}/`, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        console.log("TOKEN LAMA", accessToken)
        if (response.data && response.data.items) {
            { response.data.items.map((items, index) => listObjects.push(items.name.replace(`${folderName}/`, ''))) }
        }
        return res.status(200).json({
            success: 'sukses mendapatkan data',
            listData: listObjects,
            data: response.data
        });
    } catch (error) {
        if (error.response && error.response.status === 401) {
            try {
                cachedAccessToken = null;
                const newAccessToken = await getAccessToken();
                const retryResponse = await axios.get(`https://storage.googleapis.com/storage/v1/b/${bucketName}/o?prefix=${folderName}/`, {
                    headers: {
                        Authorization: `Bearer ${newAccessToken}`,
                    },
                });
                console.log("TOKEN BARU", newAccessToken)
                if (retryResponse.data && retryResponse.data.items) {
                    { retryResponse.data.items.map((items, index) => listObjects.push(items.name.replace(`${folderName}/`, ''))) }
                }
                return res.status(200).json({
                    success: 'sukses mendapatkan data',
                    listData: listObjects,
                    data: retryResponse.data
                });
            } catch (retryError) {
                console.error('Failed get folders:', retryError);
                return res.status(401).json({ error: 'Authentication failed after refresh' });
            }
        }
    }
});

app.post('/api/mongo/create/history', async (req, res) => {
    try {
        const { username, url, filename, size, upload_date, download_date } = req.body;

        if (!username || !url || !filename || !size || !upload_date || !download_date) {
            return res.status(400).json({
                error: 'semua data harus di isi'
            });
        }

        const con = db.collection('convert');

        const data = {
            username: username,
            url: url,
            filename: filename,
            size: size,
            upload_date: upload_date,
            download_date: download_date
        }

        const result = await con.insertOne(data)

        console.log(` 666666666666666666666666666666666666666666666666666666666666666666666666666666A document was inserted with the _id: ${result.insertedId}`);
        return res.status(200).json({
            success: true,
            message: 'Berhasil menambahkan history',
            result: result.insertedId
        });
    } catch (error) {
        console.error('Error in create history:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.get('/api/mongo/read/history', async (req, res) => {
    try {
        const items = db.collection('convert');
        const { username } = req.query;

        if (!username) {
            return res.status(400).json({
                error: 'semua data harus di isi'
            });
        }

        const query = { username: username };
        const res_user = await items.find(query);
        const result = await res_user.toArray()
        // Pastikan hanya mengirim respons sekali
        return res.json(result);
    } catch (error) {
        console.error('Error in read history:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.delete('/api/mongo/cleanup', async (req, res) => {
    try {
        const items = db.collection('convert');
        const { filename, username } = req.query;

        if (!filename) {
            return res.status(400).json({
                error: 'Parameter filename harus diisi'
            });
        }

        // Membuat query dasar
        const baseQuery = { filename: filename };
        if (username) {
            baseQuery.username = username;
        }

        // 1. Menghapus data dengan URL kosong (array kosong atau tidak ada)
        const emptyUrlQuery = {
            ...baseQuery,
            $or: [
                { url: { $size: 0 } },
                { url: { $exists: false } }
            ]
        };

        const emptyUrlResult = await items.deleteMany(emptyUrlQuery);

        // 2. Menangani duplikat - mencari dokumen dengan filename dan username yang sama
        const duplicateQuery = {
            ...baseQuery,
            url: { $exists: true, $ne: [] } // URL ada dan bukan array kosong
        };

        const duplicates = await items.find(duplicateQuery).toArray();

        // Jika tidak ada duplikat, selesai
        if (duplicates.length <= 1) {
            return res.json({
                message: `Pembersihan data selesai untuk ${filename}${username ? ` - ${username}` : ''}`,
                emptyUrlDeleted: emptyUrlResult.deletedCount,
                duplicatesDeleted: 0,
                totalDeleted: emptyUrlResult.deletedCount
            });
        }

        // 3. Mengurutkan duplikat berdasarkan upload_date terbaru
        // Jika ada format tanggal yang sama, kita perlu mengonversinya ke format yang bisa dibandingkan
        duplicates.sort((a, b) => {
            // Mengonversi string tanggal ke objek Date
            // Format: "17/05/2025 09:48" -> "2025-05-17T09:48:00"
            try {
                const dateA = a.upload_date ?
                    new Date(a.upload_date.replace(/(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2})/, "$3-$2-$1T$4:$5:00")) :
                    new Date(0);

                const dateB = b.upload_date ?
                    new Date(b.upload_date.replace(/(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2})/, "$3-$2-$1T$4:$5:00")) :
                    new Date(0);

                return dateB - dateA; // Urutkan terbaru ke terlama
            } catch (e) {
                console.error("Error parsing date:", e);
                return 0;
            }
        });

        // 4. Simpan dokumen terbaru, hapus sisanya
        const latestDoc = duplicates[0];
        const docsToDelete = duplicates.slice(1);
        const idsToDelete = docsToDelete.map(doc => doc._id);

        let duplicateDeletedCount = 0;
        if (idsToDelete.length > 0) {
            const deleteResult = await items.deleteMany({
                _id: { $in: idsToDelete }
            });
            duplicateDeletedCount = deleteResult.deletedCount;
        }

        return res.json({
            message: `Pembersihan data berhasil untuk ${filename}${username ? ` - ${username}` : ''}`,
            emptyUrlDeleted: emptyUrlResult.deletedCount,
            duplicatesDeleted: duplicateDeletedCount,
            totalDeleted: emptyUrlResult.deletedCount + duplicateDeletedCount,
            latestDocument: latestDoc._id
        });
    } catch (error) {
        console.error('Error saat membersihkan data:', error);
        return res.status(500).json({
            error: 'Server Error',
            message: error.message
        });
    }
});

app.listen(port, async () => {
    // console.log(`Server proxy Shiradoc berjalan di http://localhost:${port}`);
    console.log(process.env, "********************************")
    console.log(`Server is running on port ${process.env.PORT}`);
    const connected = await connectToMongo();
    if (!connected) {
        console.error('Failed to connect to MongoDB. Server might not work properly.');
    }
    if (cachedAccessToken) {
        console.info('berhasil mendapatkan access token')
    }
});

// Handle graceful shutdown
process.on('SIGINT', async () => {
    await client.close();
    console.log('MongoDB connection closed');
    process.exit(0);
});

// _id: {
//     // username + user_id
//     firman90398393jldjkldjkld: {
//         // uuid
//         uuid: {
//             // file
//             file_object: fileObject,
//                 file_url: 'file_url',
//                     chat: {
//                 [uuidv4()]: { sender: "user0", message: "Halo!" },
//                 [uuidv4()]: { sender: "user1", message: "Hai, ada yang bisa saya bantu?" }
//             }
//         },
//         uuid: {
//             // file
//             file_object: fileObject,
//                 file_url: 'file_url',
//                     chat: {
//                 [uuidv4()]: { sender: "user0", message: "Halo!" },
//                 [uuidv4()]: { sender: "user1", message: "Hai, ada yang bisa saya bantu?" }
//             }
//         },
//     }
// }