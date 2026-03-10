const axios = require('axios');
require('dotenv').config();

const WEB_API_URL = process.env.WEB_API_URL || 'http://localhost:3000/api/bot';
const BOT_API_SECRET = process.env.BOT_API_SECRET || '';

console.log(`[IdentityCheck] Terhubung ke Web API: ${WEB_API_URL}`);

const apiClient = axios.create({
    baseURL: WEB_API_URL,
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
        'x-bot-secret': BOT_API_SECRET
    }
});

function logApiError(label, e) {
    if (e.code === 'ECONNREFUSED') {
        console.error(`[${label}] ❌ Web app tidak aktif di ${WEB_API_URL}. Jalankan: cd C:\\laragon\\www\\wa-shield-web && npm run dev`);
    } else if (e.response) {
        console.error(`[${label}] API Error ${e.response.status}:`, JSON.stringify(e.response.data));
    } else {
        console.error(`[${label}] Network Error:`, e.message || e.code || 'Unknown');
    }
}

async function cekIdentitas(inputNomor) {
    try {
        const res = await apiClient.post('/check-number', { nomor: inputNomor });
        return res.data;
    } catch (e) {
        logApiError('cekIdentitas', e);
        return { status: 'UNKNOWN', number: inputNomor };
    }
}

async function laporNomor(inputNomor, alasan) {
    try {
        const res = await apiClient.post('/reports', { nomor: inputNomor, alasan });
        return res.data;
    } catch (e) {
        logApiError('laporNomor', e);
        throw new Error('Gagal menyimpan laporan ke server.');
    }
}

async function tambahWhitelist(inputNomor, namaInstansi) {
    try {
        const res = await apiClient.post('/whitelist', { nomor: inputNomor, nama: namaInstansi });
        return res.data;
    } catch (e) {
        logApiError('tambahWhitelist', e);
        throw new Error('Gagal menyimpan ke server.');
    }
}

// cekUserBaru: Tetap lokal, karena ini hanya user tracking per sesi bot
const fs = require('fs');
const path = require('path');
const usersFile = path.resolve(__dirname, '../known_users.json');

function loadKnownUsers() {
    try {
        if (fs.existsSync(usersFile)) {
            return JSON.parse(fs.readFileSync(usersFile, 'utf-8'));
        }
    } catch (e) { /* ignore */ }
    return [];
}

function saveKnownUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users), 'utf-8');
}

function cekUserBaru(jid) {
    const users = loadKnownUsers();
    if (users.includes(jid)) {
        return Promise.resolve(false);
    }
    users.push(jid);
    saveKnownUsers(users);
    return Promise.resolve(true);
}

module.exports = {
    cekIdentitas,
    laporNomor,
    tambahWhitelist,
    cekUserBaru
};