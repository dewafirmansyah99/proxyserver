// File: sendEmail.js
// import nodemailer from 'nodemailer';
// const nodemailer = require('nodemailer');
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

export async function sendEmail({ to, subject, text, html }) {
    try {
        // 1. Buat transporter menggunakan akun SMTP (Gmail sebagai contoh)
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.NODE_USERNAME_EMAIL, // ganti dengan email kamu
                pass: process.env.NODE_PASSWORD_EMAIL // ganti dengan App Password Gmail, bukan password biasa
            }
        });

        // 2. Konfigurasi email
        const mailOptions = {
            from: process.env.NODE_USERNAME_EMAIL, // email pengirim
            to, // email tujuan
            subject, // subjek
            text, // isi dalam bentuk teks biasa
            html // isi dalam bentuk HTML (optional)
        };

        // 3. Kirim email
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
        return info;
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

// module.exports = sendEmail;

/*
Cara menggunakan:
const sendEmail = require('./sendEmail');

sendEmail({
  to: 'recipient@example.com',
  subject: 'Test Email',
  text: 'Halo, ini adalah email dari Node.js!',
  html: '<b>Halo, ini adalah email dari Node.js!</b>'
});
*/
