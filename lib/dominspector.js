/**
 * DOM Inspector — Inspeksi HTML untuk Deteksi Credential Harvesting
 * 
 * Mengunduh dan membedah struktur HTML dari URL target untuk mendeteksi
 * formulir yang meminta data sensitif (NIK, PIN, OTP, rekening, dll).
 * 
 * Dirancang untuk mendeteksi penipuan yang menumpang di platform legal
 * seperti Google Forms, Typeform, JotForm, dll.
 */

const axios = require('axios');
const cheerio = require('cheerio');

// ==================== REGEX POLA DATA SENSITIF ====================

// Kategori 1: Data Identitas (wajar diminta di formulir resmi)
const IDENTITY_PATTERNS = [
    /\b(nik)\b/i,
    /\b(no\.?\s*ktp|nomor\s*ktp|kartu\s*tanda\s*penduduk)\b/i,
    /\b(ktp)\b/i,
    /\b(no\.?\s*identitas|nomor\s*identitas)\b/i,
];

// Kategori 2: Data Finansial / Rahasia (TIDAK WAJAR di formulir pelaporan)
const FINANCIAL_PATTERNS = [
    /\b(rekening|no\.?\s*rekening|nomor\s*rekening|bank\s*account)\b/i,
    /\b(pin|kode\s*pin|pin\s*atm)\b/i,
    /\b(cvv|cvc|kode\s*keamanan\s*kartu)\b/i,
    /\b(saldo)\b/i,
    /\b(ibu\s*kandung|nama\s*gadis\s*ibu|maiden\s*name)\b/i,
    /\b(otp|kode\s*otp|kode\s*verifikasi)\b/i,
    /\b(password|kata\s*sandi|sandi)\b/i,
    /\b(m-?banking|mobile\s*banking|internet\s*banking)\b/i,
    /\b(kartu\s*kredit|credit\s*card)\b/i,
    /\b(token\s*bank|kode\s*token)\b/i,
];

// Kategori 3: Kata-kata Intimidasi / Paksaan (konteks penipu yang mendesak)
const INTIMIDATION_PATTERNS = [
    /\b(pasal\s*\d+|undang.?undang|uu\s*ite|uu\s*no)/i,
    /\b(pidana|hukuman|denda|penjara)\b/i,
    /\b(segera|wajib|harus|darurat|mendesak)\b/i,
    /\b(blokir|diblokir|pemblokiran|memblokir)\b/i,
    /\b(cybercrime|cyber\s*crime|kejahatan\s*siber)\b/i,
    /\b(bareskrim|polda|polres|polsek|kepolisian)\b/i,
];

// Domain formulir legal yang SERING disalahgunakan penipu
const FORM_HOSTING_DOMAINS = [
    'docs.google.com',
    'forms.gle',
    'typeform.com',
    'jotform.com',
    'surveyheart.com',
    'surveymonkey.com',
    'formstack.com',
    'airtable.com',
    'tally.so',
    'notion.site',
];

// ==================== FUNGSI UTAMA ====================

/**
 * Inspeksi DOM dari URL target untuk mendeteksi credential harvesting
 * @param {string} url - URL target
 * @returns {Promise<object>} Hasil inspeksi
 */
async function inspectDOM(url) {
    const result = {
        isCredentialHarvesting: false,
        isIntimidation: false,
        identityFieldsFound: [],
        financialFieldsFound: [],
        intimidationFound: [],
        isFormHosting: false,
        totalFormFields: 0,
        score: 0,
        notes: [],
    };

    try {
        // Unduh HTML mentah (tanpa eksekusi JS)
        const response = await axios.get(url, {
            timeout: 10000,
            maxRedirects: 10,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'id-ID,id;q=0.9,en;q=0.5',
            },
            // Hanya ambil teks HTML, jangan download file besar
            responseType: 'text',
            maxContentLength: 2 * 1024 * 1024, // Max 2MB
        });

        const html = response.data;
        if (typeof html !== 'string') return result;

        const $ = cheerio.load(html);

        // --- Cek apakah ini hosted di platform form ---
        try {
            const parsedUrl = new URL(url);
            result.isFormHosting = FORM_HOSTING_DOMAINS.some(d => parsedUrl.hostname.includes(d));
        } catch (e) { /* ignore */ }

        // --- Ekstraksi semua form fields ---
        const fieldTexts = [];

        // Input fields
        $('input').each((_, el) => {
            const attrs = [
                $(el).attr('name'),
                $(el).attr('placeholder'),
                $(el).attr('aria-label'),
                $(el).attr('id'),
            ].filter(Boolean);
            fieldTexts.push(...attrs);
        });

        // Textarea
        $('textarea').each((_, el) => {
            const attrs = [
                $(el).attr('name'),
                $(el).attr('placeholder'),
                $(el).attr('aria-label'),
                $(el).attr('id'),
            ].filter(Boolean);
            fieldTexts.push(...attrs);
        });

        // Select fields
        $('select').each((_, el) => {
            const attrs = [
                $(el).attr('name'),
                $(el).attr('aria-label'),
                $(el).attr('id'),
            ].filter(Boolean);
            fieldTexts.push(...attrs);
        });

        // Label text
        $('label').each((_, el) => {
            const text = $(el).text().trim();
            if (text && text.length < 200) fieldTexts.push(text);
        });

        // Google Forms specific: pertanyaan ada di div[role="heading"]
        $('[role="heading"]').each((_, el) => {
            const text = $(el).text().trim();
            if (text && text.length < 200) fieldTexts.push(text);
        });

        // Google Forms: data-params attribute contains question text
        $('[data-params]').each((_, el) => {
            const params = $(el).attr('data-params');
            if (params) fieldTexts.push(params);
        });

        result.totalFormFields = $('input, textarea, select').length;

        // --- Pencocokan Pola Identitas ---
        const allFieldText = fieldTexts.join(' | ');

        for (const pattern of IDENTITY_PATTERNS) {
            const matches = allFieldText.match(pattern);
            if (matches) {
                result.identityFieldsFound.push(matches[0]);
            }
        }

        // --- Pencocokan Pola Finansial / Rahasia ---
        for (const pattern of FINANCIAL_PATTERNS) {
            const matches = allFieldText.match(pattern);
            if (matches) {
                result.financialFieldsFound.push(matches[0]);
            }
        }

        // --- Deteksi Intimidasi di body text ---
        const bodyText = $('body').text().substring(0, 10000); // Limit
        for (const pattern of INTIMIDATION_PATTERNS) {
            const matches = bodyText.match(pattern);
            if (matches) {
                result.intimidationFound.push(matches[0]);
            }
        }

        // ==================== HITUNG SKOR ====================

        const hasIdentity = result.identityFieldsFound.length > 0;
        const hasFinancial = result.financialFieldsFound.length > 0;
        const hasIntimidation = result.intimidationFound.length > 0;

        // ANCAMAN KRITIS: Identitas + Finansial di satu form
        if (hasIdentity && hasFinancial) {
            result.isCredentialHarvesting = true;
            result.score += 100;
            result.notes.push(`🚨 CREDENTIAL HARVESTING — Formulir ini meminta data identitas (${result.identityFieldsFound.join(', ')}) DAN data rahasia keuangan (${result.financialFieldsFound.join(', ')}) secara bersamaan. Formulir resmi TIDAK PERNAH meminta PIN/OTP/CVV.`);
        }

        // Finansial saja tanpa identitas: tetap berbahaya
        if (hasFinancial && !hasIdentity) {
            result.score += 70;
            result.notes.push(`⚠️ Formulir meminta data keuangan sensitif (${result.financialFieldsFound.join(', ')}). Waspadai pencurian data.`);
        }

        // Jika ada intimidasi (pasal hukum dll)
        if (hasIntimidation) {
            result.isIntimidation = true;
            result.score += 30;
            result.notes.push(`⚠️ Halaman mengandung kata-kata intimidasi hukum (${result.intimidationFound.slice(0, 3).join(', ')}). Penipu sering menggunakan ancaman agar korban panik.`);
        }

        // Form hosting + credential harvesting = anomali absolut
        if (result.isFormHosting && (hasFinancial || result.isCredentialHarvesting)) {
            result.score += 30;
            result.notes.push(`🚨 AUTHORITY SPOOFING — Data sensitif diminta melalui platform formulir gratisan. Institusi resmi TIDAK menggunakan Google Forms/Typeform untuk mengumpulkan data keuangan.`);
        }

        console.log(`[DOM Inspector] URL: ${url} | Fields: ${result.totalFormFields} | Identity: ${result.identityFieldsFound.length} | Financial: ${result.financialFieldsFound.length} | Intimidation: ${result.intimidationFound.length} | Score: ${result.score}`);

    } catch (error) {
        // Gagal download = skip (jangan crash)
        // Simpan HTTP status code untuk digunakan oleh analyzeLink (dead page detection)
        if (error.response && error.response.status) {
            result.httpStatus = error.response.status;
        }
        // Jangan print error jika hanya karena redirect loop (terjadi di banyak situs legitimate yang butuh cookies)
        if (!error.message.includes('redirects exceeded') && !error.message.includes('timeout')) {
            console.error(`[DOM Inspector] Gagal inspeksi ${url}: ${error.message}`);
        }
    }

    return result;
}

module.exports = { inspectDOM };
