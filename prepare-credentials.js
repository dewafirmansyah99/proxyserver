const fs = require('fs');
const path = require('path');

// Ganti dengan path ke file JSON service account Anda
const serviceAccountPath = path.resolve('../gen-lang-client-0500049568-4c98da195a69.json');

try {
    const credentials = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
    // Stringify dengan indentasi 0 untuk menghapus semua spasi dan baris baru kecuali di private_key
    const jsonStringForEnv = JSON.stringify(credentials);
    console.log('Salin teks di bawah ini (TERMASUK KURUNG KURAWAL) dan tempel ke nilai variabel GOOGLE_APPLICATION_CREDENTIALS_JSON di Railway:\n');
    console.log(jsonStringForEnv);
    console.log('\nPastikan TIDAK ADA SPASI atau KARAKTER BARIS BARU di awal/akhir saat menempel.');
} catch (error) {
    console.error('Terjadi kesalahan saat memproses file JSON:', error);
}
