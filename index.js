const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    downloadMediaMessage,
    fetchLatestBaileysVersion
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const qrcode = require('qrcode-terminal');
const fs = require('fs');
const fsPromises = fs.promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// ==================== STRUCTURED LOGGING ====================
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

const logger = pino({
    level: 'info',
    timestamp: pino.stdTimeFunctions.isoTime,
}, pino.destination(path.join(logDir, 'bot.log')));

// ==================== GLOBAL ERROR HANDLER ====================
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught Exception:', err);
    logger.fatal({ err, type: 'uncaughtException' }, 'Bot crash — uncaught exception');
    // Beri waktu untuk flush log, lalu restart
    setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[FATAL] Unhandled Rejection:', reason);
    logger.error({ reason: String(reason), type: 'unhandledRejection' }, 'Unhandled promise rejection');
});

// ==================== STATISTICS TRACKER ====================
const statsFile = path.join(__dirname, 'data', 'stats.json');
let stats = { totalScans: 0, totalLinks: 0, totalNumbers: 0, totalQR: 0, threatsDetected: 0, startedAt: new Date().toISOString() };

function loadStats() {
    try {
        if (fs.existsSync(statsFile)) {
            stats = { ...stats, ...JSON.parse(fs.readFileSync(statsFile, 'utf-8')) };
        }
    } catch (e) { /* ignore */ }
}

function saveStats() {
    try {
        const dir = path.dirname(statsFile);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(statsFile, JSON.stringify(stats, null, 2));
    } catch (e) { /* ignore */ }
}

function trackStat(type, isThreat = false) {
    if (type === 'scan') stats.totalScans++;
    else if (type === 'link') stats.totalLinks++;
    else if (type === 'number') stats.totalNumbers++;
    else if (type === 'qr') stats.totalQR++;
    if (isThreat) stats.threatsDetected++;
    saveStats();
}

loadStats();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "dummy");

const systemInstruction = `Kamu adalah Asisten Cybersecurity WA-SHIELD buatan Adam.
Tugas utama kamu adalah membantu pengguna awam memeriksa keamanan digital mereka. 
Gunakan gaya bahasa yang profesional, ramah, ringkas, mudah dipahami orang awam, dan hindari istilah teknis yang rumit.

Kemampuan yang kamu miliki dan bisa kamu tawarkan:
1. Cek Nomor Telepon (Spam/Penipuan)
2. Cek Link / URL Berbahaya (Phishing/Scam/Punycode)
3. Cek File / Dokumen / APK (Virus/Malware)
4. Cek QR Code (Anti-Quishing / Ekstrak link tersembunyi)

Aturan Penting:
- Jika pengguna mengirim teks nomor atau link, langsung panggil fungsi (tools) yang tersedia tanpa menyuruh pengguna mengetik command manual.
- Jika pengguna ingin mengecek file atau QR code, minta mereka untuk langsung mengirimkan gambar/filenya ke chat ini. Sistem kami akan memprosesnya secara otomatis.`;

const tools = [
    {
        functionDeclarations: [
            {
                name: "cekNomor",
                description: "Mengecek apakah suatu nomor telepon terkait penipuan atau aman berdasarkan database komunitas dan Truecaller.",
                parameters: {
                    type: "OBJECT",
                    properties: {
                        nomor: {
                            type: "STRING",
                            description: "Nomor telepon yang ingin dicek, misalnya +6281234567890"
                        }
                    },
                    required: ["nomor"]
                }
            },
            {
                name: "cekLink",
                description: "Mengecek apakah suatu link/URL aman dari pishing atau virus. Panggil ini jika chat murni bertumpu pada analisis URL.",
                parameters: {
                    type: "OBJECT",
                    properties: {
                        url: {
                            type: "STRING",
                            description: "URL atau link yang ingin dicek, misalnya https://example.com"
                        }
                    },
                    required: ["url"]
                }
            },
            {
                name: "laporNomor",
                description: "Melaporkan suatu nomor telepon penipu ke database komunitas.",
                parameters: {
                    type: "OBJECT",
                    properties: {
                        nomor: {
                            type: "STRING",
                            description: "Nomor telepon penipu, misalnya +6281234567890"
                        },
                        alasan: {
                            type: "STRING",
                            description: "Alasan pelaporan atau kasus penipuannya, misalnya 'Penipuan online shop'"
                        }
                    },
                    required: ["nomor", "alasan"]
                }
            }
        ]
    }
];

const aiModel = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
    systemInstruction: systemInstruction,
    tools: tools
});

// Model terpisah untuk QR Vision (tanpa system instruction/tools)
const visionModel = genAI.getGenerativeModel({
    model: "gemini-2.5-flash"
});

// Model terpisah untuk menjelaskan hasil scan (TANPA tools agar tidak trigger function calling)
const explainModel = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
    systemInstruction: `Kamu adalah Asisten Cybersecurity WA-SHIELD. Tugas kamu HANYA menjelaskan hasil scan yang sudah dilakukan oleh sistem. Gunakan bahasa yang profesional, ramah, sangat RINGKAS, PADAT, dan mudah dipahami orang awam. Jawablah langsung ke intinya tanpa bertele-tele (maksimum 2 paragraf). JANGAN menyuruh pengguna melakukan apapun.`
});

const userChats = {};
const userChatTimeouts = {};

function getChat(sender) {
    if (!userChats[sender]) {
        userChats[sender] = aiModel.startChat({ history: [] });
    }

    if (userChatTimeouts[sender]) {
        clearTimeout(userChatTimeouts[sender]);
    }

    userChatTimeouts[sender] = setTimeout(() => {
        delete userChats[sender];
        delete userChatTimeouts[sender];
    }, 30 * 60 * 1000);

    return userChats[sender];
}

const { cekLink, cekFile } = require('./lib/virustotal');
const { deepScan, addMalwareHash, computeSHA256 } = require('./lib/scan');
const { cariNomor } = require('./lib/truecaller');
const { analyzeLink } = require('./lib/link');
const { cekIdentitas, laporNomor, cekUserBaru } = require('./lib/identitycheck');
const { checkOsintProfile } = require('./lib/osint');
const { scanQRCode } = require('./lib/qrscanner');

const OWNER_NUMBER = '6285211322123@s.whatsapp.net';

const userCooldown = {};
const COOLDOWN_TIME = 3000;

// Global socket reference agar bisa dicleanup
let activeSock = null;
let reconnectAttempts = 0;
let reconnectTimer = null;
const MAX_RECONNECT_ATTEMPTS = 10;

async function connectToWhatsApp() {
    // Cegah multiple reconnect timer
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    const { state, saveCreds } = await useMultiFileAuthState('auth_info_baileys');

    // Fetch versi WA Web terbaru agar tidak kena 405
    let version;
    try {
        const { version: latestVersion } = await fetchLatestBaileysVersion();
        version = latestVersion;
        console.log('Menggunakan WA Web versi:', version.join('.'));
    } catch (e) {
        console.log('Gagal fetch versi terbaru, pakai default');
    }

    // Cleanup socket lama sebelum buat baru
    if (activeSock) {
        try {
            activeSock.ev.removeAllListeners();
            activeSock.end(undefined);
        } catch (e) { /* ignore cleanup errors */ }
        activeSock = null;
    }

    const sock = makeWASocket({
        auth: state,
        logger: pino({ level: 'silent' }),
        version: version,
        browser: ["WA-SHIELD", "Chrome", "22.0"],
        connectTimeoutMs: 60000,
        syncFullHistory: false,
        markOnlineOnConnect: true,
        generateHighQualityLinkPreview: false
    });

    activeSock = sock;

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;
        if (qr) {
            console.log('QR Code muncul, silakan scan:');
            qrcode.generate(qr, { small: true });
        }

        if (connection === 'close') {
            const statusCode = lastDisconnect?.error?.output?.statusCode;
            const reason = lastDisconnect?.error?.message || 'Unknown';
            console.log(`[${new Date().toLocaleTimeString()}] Koneksi terputus. Code: ${statusCode} | Alasan: ${reason}`);

            // 401 = logged out, 440 = conflict (sesi lain aktif / multiple instance)
            const isLoggedOut = statusCode === DisconnectReason.loggedOut;
            const isConflict = statusCode === 440;

            if (isLoggedOut) {
                console.log("Logged out. Hapus folder auth_info_baileys dan jalankan ulang untuk scan QR baru.");
                process.exit(0);
            } else if (isConflict) {
                console.log("⚠️  KONFLIK: Ada sesi WhatsApp Web lain yang aktif.");
                console.log("   Pastikan tidak ada instance bot lain yang berjalan.");
                console.log("   Cek juga WhatsApp Web di browser - logout dari sana jika ada.");
                console.log("   Bot akan mencoba reconnect dalam 10 detik...");
                reconnectTimer = setTimeout(() => connectToWhatsApp(), 10000);
            } else if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                reconnectAttempts++;
                // Exponential backoff: 3s, 6s, 12s, 24s, max 30s
                const delay = Math.min(3000 * Math.pow(2, reconnectAttempts - 1), 30000);
                console.log(`Reconnect attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} dalam ${delay / 1000}s...`);
                reconnectTimer = setTimeout(() => connectToWhatsApp(), delay);
            } else {
                console.log("Max reconnect attempts reached. Silakan restart bot secara manual.");
                process.exit(1);
            }
        } else if (connection === 'open') {
            reconnectAttempts = 0; // Reset counter saat berhasil konek
            console.log(`[${new Date().toLocaleTimeString()}] ✅ Bot Online dan Terhubung!`);
        }
    });

    sock.ev.on('messages.upsert', async ({ messages }) => {
        try {
            const m = messages[0];
            if (!m.message || m.key.fromMe) return;
            console.log("Raw Message:", JSON.stringify(m.message, null, 2));

            const sender = m.key.remoteJid;
            const isGroup = sender.endsWith('@g.us');
            let textBody = '';
            let docMessage = null;

            if (m.message.documentWithCaptionMessage) {
                docMessage = m.message.documentWithCaptionMessage.message?.documentMessage;
                textBody = docMessage?.caption || m.message.documentWithCaptionMessage.message?.caption;
            } else if (m.message.documentMessage) {
                docMessage = m.message.documentMessage;
                textBody = docMessage?.caption;
            } else if (m.message.conversation) {
                textBody = m.message.conversation;
            } else if (m.message.extendedTextMessage) {
                textBody = m.message.extendedTextMessage?.text;
            } else if (m.message.imageMessage) {
                textBody = m.message.imageMessage?.caption;
            }
            textBody = (textBody || '').trim();

            // Skip welcome message dan fitur personal untuk grup
            let sentWelcome = false;
            if (!isGroup) {
                try {
                    const isNewUser = await cekUserBaru(sender);
                    if (isNewUser) {
                        sentWelcome = true;
                        console.log(`User Baru Terdeteksi: ${sender}`);
                        const welcomeMsg =
                            `Halo! Selamat datang di *WA-SHIELD* 🛡️

Saya adalah asisten keamanan digital yang siap melindungi Anda dari ancaman siber.

🔍 *Yang bisa saya lakukan:*
• Scan file mencurigakan (APK, PDF, Dokumen Office, ZIP, dll)
• Cek link/URL apakah aman atau phishing
• Deteksi QR Code berbahaya (Anti-Quishing)
• Cek & laporkan nomor penipu

💬 *Cara menggunakannya sangat mudah:*
Cukup kirim file, link, gambar QR, atau langsung chat saja seperti biasa. Saya akan otomatis memproses semuanya untuk Anda.

Saya aktif 24 jam. Silakan mulai! 😊`;

                        await sock.sendMessage(sender, {
                            text: welcomeMsg,
                            contextInfo: {
                                externalAdReply: {
                                    title: "WA-SHIELD",
                                    body: "",
                                    mediaType: 1,
                                    renderLargerThumbnail: true,
                                    thumbnailUrl: "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
                                    sourceUrl: "https://wa.me/" + OWNER_NUMBER.split('@')[0]
                                }
                            }
                        }, { quoted: m });
                    }
                } catch (e) {
                    console.error("Error Welcome:", e);
                    logger.error({ err: e.message, sender }, 'Welcome message error');
                }
            } // end if (!isGroup)

            if (sender !== OWNER_NUMBER && userCooldown[sender]) {
                const sisaWaktu = Date.now() - userCooldown[sender];
                if (sisaWaktu < COOLDOWN_TIME) return;
            }
            userCooldown[sender] = Date.now();

            if (docMessage) {
                const doc = docMessage;
                const fileName = doc.fileName || "unknown";
                const targetExt = ['.apk', '.exe', '.bat', '.sh', '.jar', '.zip', '.rar', '.pdf', '.doc', '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.scr', '.vbs', '.cmd', '.msi', '.lnk', '.hta', '.pif'];
                const isTarget = targetExt.some(ext => fileName.toLowerCase().endsWith(ext));

                if (isTarget) {
                    // React call removed

                    let isDangerous = false;
                    let tempFilePath = null;
                    try {
                        // Download file while showing typing indicator
                        await sock.sendPresenceUpdate('composing', sender);
                        const buffer = await downloadMediaMessage(m, 'buffer', {}, { logger: pino({ level: 'silent' }), reuploadRequest: sock.updateMediaMessage });

                        const tempDir = path.join(__dirname, 'temp_scan');
                        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

                        const safeName = `${uuidv4()}${path.extname(fileName)}`;
                        tempFilePath = path.join(tempDir, safeName);
                        await fsPromises.writeFile(tempFilePath, buffer);

                        // DeepScan is PRIMARY (fast, local). VT is BONUS with 4s deadline.
                        const vtWithDeadline = Promise.race([
                            cekFile(buffer).catch(() => ({ found: false })),
                            new Promise(resolve => setTimeout(() => resolve({ found: false, timeout: true }), 4000))
                        ]);

                        const [vtResult, deepResult] = await Promise.all([
                            vtWithDeadline,
                            deepScan(tempFilePath, fileName).catch(() => null)
                        ]);

                        if (vtResult && vtResult.found) {
                            const vtStats = vtResult.data.last_analysis_stats;
                            const totalBahaya = vtStats.malicious + vtStats.suspicious;
                            if (totalBahaya > 0) isDangerous = true;
                        }
                        if (vtResult && vtResult.timeout) console.log('[VT] Timeout — menggunakan hasil local scan saja.');

                        if (deepResult && (deepResult.riskLevel === 'BAHAYA' || deepResult.riskLevel === 'WARNING')) {
                            isDangerous = true;
                        }

                        trackStat('scan', isDangerous);
                        logger.info({ fileName, riskLevel: deepResult ? deepResult.riskLevel : 'UNKNOWN', isDangerous, sender }, 'File scanned');

                        let riskPercentStr = "";
                        if (deepResult && typeof deepResult.riskPercentage === 'number') {
                            riskPercentStr = ` (Probabilitas Bahaya: ${deepResult.riskPercentage}%)`;
                        }

                        // Build detection details string for AI context
                        let detectionDetails = '';
                        if (deepResult && deepResult.detections && deepResult.detections.length > 0) {
                            const uniqueDetections = [...new Set(deepResult.detections)];
                            detectionDetails = `\n\n🔬 *Temuan Forensik Detail:*\n` + uniqueDetections.map((d) => `- ${d}`).join('\n');
                        }

                        // Include app info for APK files
                        let appInfoStr = '';
                        if (deepResult && deepResult.appName && deepResult.appName !== '-' && deepResult.appName !== 'Unknown') {
                            appInfoStr = `\n📱 *Info Aplikasi:* Nama="${deepResult.appName}", Package="${deepResult.packageName}", Versi="${deepResult.version}"`;
                        }

                        // Include SHA-256 hash
                        let hashStr = '';
                        if (deepResult && deepResult.sha256) {
                            hashStr = `\n🛡️ *SHA-256:* ${deepResult.sha256}`;
                        }

                        try {
                            const statusStr = isDangerous ? `🚨 *BAHAYA - Virus/Malware terdeteksi*${riskPercentStr}` : `✅ *AMAN DARI VIRUS*${riskPercentStr}`;
                            let finalMsg = `${statusStr}\n\n*File:* ${fileName}${appInfoStr}${hashStr}${detectionDetails}`;
                            await sock.sendMessage(sender, { text: finalMsg }, { quoted: m });
                        } catch (err) {
                            console.error("Gemini File Output Error:", err.message);
                            await sock.sendMessage(sender, { text: isDangerous ? "🚨 [FILE BAHAYA]" : "✅ [FILE AMAN]" }, { quoted: m });
                        }
                    } catch (e) {
                        console.error("Scan Error:", e);
                        await sock.sendMessage(sender, { text: "Gagal scan file." }, { quoted: m }).catch(() => { });
                    } finally {
                        if (tempFilePath && fs.existsSync(tempFilePath)) {
                            try { await fsPromises.unlink(tempFilePath); } catch (err) { }
                        }
                    }
                    if (!textBody) return;
                }
            }

            // --- Cek apakah pesan berisi Image (Kemungkinan QR Code) ---
            if (m.message.imageMessage || (docMessage && docMessage.mimetype && docMessage.mimetype.startsWith('image/'))) {
                try {
                    const textBodyLower = (textBody || "").toLowerCase();

                    const buffer = await downloadMediaMessage(
                        m, 'buffer', {},
                        { logger: pino({ level: 'silent' }), reuploadRequest: sock.updateMediaMessage }
                    );

                    let mimeType = 'image/jpeg';
                    if (m.message.imageMessage) mimeType = m.message.imageMessage.mimetype || 'image/jpeg';
                    else if (docMessage) mimeType = docMessage.mimetype || 'image/jpeg';

                    // Lanjut ke QR Code Scanner (Anti-Quishing) - Advanced Multi-Strategy + AI Fallback
                    console.log('[Anti-Quishing] Memproses gambar untuk deteksi QR...');
                    await sock.sendPresenceUpdate('composing', sender);

                    const qrResult = await scanQRCode(buffer, visionModel);

                    if (qrResult && qrResult.startsWith('http')) {
                        console.log(`[Anti-Quishing] QR Code URL Terdeteksi: ${qrResult}`);
                        await sock.sendPresenceUpdate('composing', sender);

                        const [localResult, vtResult] = await Promise.all([
                            analyzeLink(qrResult, textBody).catch(() => null),
                            cekLink(qrResult).catch(() => ({ found: false }))
                        ]);

                        let isDangerous = false;
                        let finalScore = localResult ? localResult.score : 0;

                        if (vtResult && vtResult.found) {
                            const stats = vtResult.data;
                            const bahaya = (stats.malicious || 0) + (stats.suspicious || 0);
                            finalScore += (bahaya * 60);
                        }

                        if (finalScore >= 50) {
                            isDangerous = true;
                        }

                        if (isDangerous) {
                            const finalRiskPercentage = Math.min(Math.round((finalScore / 100) * 100), 100);
                            // Tambahkan catatan forensik SSL/DNS jika ada
                            let forensicStr = '';
                            if (localResult && localResult.forensicNotes && localResult.forensicNotes.length > 0) {
                                forensicStr = '\n\n🔬 *Analisis Forensik SSL/DNS:*\n' + localResult.forensicNotes.map(n => `- ${n}`).join('\n');
                            }
                            const balasanAsisten = `🔳 *QR Code ini menyembunyikan link:* \n${qrResult}\n\n🚨 *JANGAN DI-SCAN!* Ini adalah link Phishing/Berbahaya yang dapat mencuri data Anda! \n(Probabilitas Bahaya: ${finalRiskPercentage}%)${forensicStr}`;
                            trackStat('qr', true);
                            await sock.sendMessage(sender, { text: balasanAsisten }, { quoted: m });
                            return;
                        } else {
                            let forensicStr = '';
                            if (localResult && localResult.forensicNotes && localResult.forensicNotes.length > 0) {
                                forensicStr = '\n\n🔬 *Analisis Forensik SSL/DNS:*\n' + localResult.forensicNotes.map(n => `- ${n}`).join('\n');
                            }
                            const balasanAsisten = `🔳 *QR Code berisi link:* \n${qrResult}\n\n✅ Hasil scan otomatis menunjukkan link tersebut relatif aman.${forensicStr}`;
                            trackStat('qr', false);
                            await sock.sendMessage(sender, { text: balasanAsisten }, { quoted: m });
                            return;
                        }
                    } else if (qrResult) {
                        await sock.sendMessage(sender, { text: `🔳 *Isi QR Code:* \n${qrResult}` }, { quoted: m });
                        return;
                    }
                } catch (e) {
                    console.error("[Anti-Quishing] Gagal memproses gambar/QR:", e.message);
                }

                // If it's just an image without a QR, but the user sent text alongside it, skip to the Gemini logic at the end by relying on textBody.
                if (!textBody) return;
            }

            const urlsFound = extractUrlsFromMessage(m.message);
            if (urlsFound.length > 0) {
                const targetUrl = urlsFound[0];

                console.log(`Cek Link: ${targetUrl}`);
                await sock.sendPresenceUpdate('composing', sender);

                const [localResult, vtResult] = await Promise.all([
                    analyzeLink(targetUrl, textBody).catch(() => null),
                    cekLink(targetUrl).catch(() => ({ found: false }))
                ]);

                let isDangerous = false;
                let finalScore = localResult ? localResult.score : 0;

                if (vtResult && vtResult.found) {
                    const vtLinkStats = vtResult.data;
                    const bahaya = (vtLinkStats.malicious || 0) + (vtLinkStats.suspicious || 0);
                    // Add 60 points for every malicious/suspicious flag from VT
                    finalScore += (bahaya * 60);
                }

                if (finalScore >= 50) {
                    isDangerous = true;
                }

                trackStat('link', isDangerous);
                logger.info({ url: targetUrl, isDangerous, finalScore, sender }, 'Link scanned');

                let finalRiskPercentage = Math.min(Math.round((finalScore / 100) * 100), 100);

                try {
                    let responseText = isDangerous
                        ? `🚨 *PERINGATAN BAHAYA (Probabilitas: ${finalRiskPercentage}%)*\n\nSistem mendeteksi bahwa tautan ini kemungkinan besar mengandung Phishing, Malware, Scam, atau Credential Harvesting.`
                        : `✅ *AMAN DARI ANCAMAN (Probabilitas Risiko: ${finalRiskPercentage}%)*\n\nHasil pemindaian otomatis tidak menemukan indikasi berbahaya pada tautan ini.`;

                    if (localResult && localResult.finalUrl && localResult.finalUrl !== targetUrl) {
                        responseText += `\n\n⚠️ *Link Asli Tersembunyi:*\nTautan pendek di atas aslinya mengarah ke: \n${localResult.finalUrl}`;
                    }

                    if (localResult && localResult.forensicNotes && localResult.forensicNotes.length > 0) {
                        responseText += `\n\n*Catatan Forensik Scanner:*\n` + localResult.forensicNotes.map(note => `- ${note}`).join('\n');
                    }

                    await sock.sendMessage(sender, { text: responseText.trim() }, { quoted: m });
                } catch (err) {
                    console.error("Link Output Error:", err.message);
                    await sock.sendMessage(sender, { text: isDangerous ? "🚨 [LINK BAHAYA]" : "✅ [LINK AMAN]" }, { quoted: m });
                }

                return;
            }



            if (textBody && !docMessage) {
                try {
                    await sock.sendPresenceUpdate('composing', sender);
                    const chat = getChat(sender);
                    const result = await chat.sendMessage(textBody);
                    let responseText = result.response.text();

                    const call = result.response.functionCalls();
                    if (call && call.length > 0) {
                        const functionCall = call[0];
                        let functionResult = {};

                        if (functionCall.name === 'cekNomor') {
                            const target = functionCall.args.nomor;
                            try {
                                const [lokalResult, tcResult] = await Promise.allSettled([
                                    cekIdentitas(target),
                                    cariNomor(target)
                                ]);

                                const dataLokal = lokalResult.status === 'fulfilled' ? lokalResult.value : { status: 'UNKNOWN' };
                                const dataTC = tcResult.status === 'fulfilled' ? tcResult.value : { found: false };

                                functionResult = { identitasLokal: dataLokal, dataTruecaller: dataTC };
                            } catch (e) {
                                functionResult = { error: "Proses investigasi nomor gagal." };
                            }
                        } else if (functionCall.name === 'cekLink') {
                            const url = functionCall.args.url;
                            const localResult = await analyzeLink(url, textBody);

                            // Gunakan URL asli jika link di-unshorten
                            const urlForVT = localResult.finalUrl || url;

                            let vtResult = { found: false };
                            try { vtResult = await cekLink(urlForVT); } catch (e) { }
                            functionResult = { localResult, vtResult };
                        } else if (functionCall.name === 'laporNomor') {
                            const target = functionCall.args.nomor;
                            const alasan = functionCall.args.alasan;
                            try {
                                const hasilLapor = await laporNomor(target, alasan);
                                functionResult = { status: "Sukses dilaporkan", detail: hasilLapor };
                            } catch (e) {
                                functionResult = { error: "Gagal menyimpan laporan." };
                            }
                        }

                        const step2Result = await chat.sendMessage([{
                            functionResponse: {
                                name: functionCall.name,
                                response: functionResult
                            }
                        }]);
                        responseText = step2Result.response.text();
                    }

                    if (responseText) {
                        await sock.sendMessage(sender, { text: responseText }, { quoted: m });
                    }
                } catch (e) {
                    console.error("Gemini Error:", e);
                }
            }

        } catch (e) { console.error('Error:', e); }
    });
}

function extractUrlsFromMessage(message) {
    const urls = [];
    const urlRegex = /(https?:\/\/[^\s]+)/g;

    // Gabungkan semua sumber teks (termasuk caption dokumen)
    const textSources = [
        message.conversation,
        message.extendedTextMessage?.text,
        message.imageMessage?.caption,
        message.documentMessage?.caption,
        message.documentWithCaptionMessage?.message?.documentMessage?.caption,
        message.documentWithCaptionMessage?.message?.caption,
    ].filter(Boolean);

    for (const text of textSources) {
        const matches = text.match(urlRegex);
        if (matches) urls.push(...matches);
    }

    const interactive = message.interactiveMessage;
    if (interactive && interactive.nativeFlowMessage?.buttons) {
        interactive.nativeFlowMessage.buttons.forEach(btn => {
            try {
                const params = JSON.parse(btn.buttonParamsJson);
                if (params.url) urls.push(params.url);
            } catch (e) { }
        });
    }
    return urls;
}


if (!fs.existsSync('temp_scan')) fs.mkdirSync('temp_scan');
connectToWhatsApp();
