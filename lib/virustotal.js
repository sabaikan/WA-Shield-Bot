/**
 * VirusTotal API Module
 * Cek file dan link menggunakan VirusTotal API v3
 * 
 * Rate Limiter: Free tier VT = 4 requests/menit
 * Auto-submit URL baru yang belum dikenal
 */
require('dotenv').config();
const axios = require('axios');
const crypto = require('crypto');
const FormData = require('form-data');

const API_KEY = process.env.VT_API_KEY || '';

if (!API_KEY) {
    console.warn('[VT] ⚠️ VT_API_KEY tidak ditemukan di .env — fitur VirusTotal nonaktif');
}

// ==================== HELPERS ====================
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function calculateHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// VT API v3 requires base64url encoding (RFC 4648 Section 5)
// Standard base64 uses +/ but base64url uses -_ 
function getUrlId(url) {
    return Buffer.from(url).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// ==================== ANALYSIS RESULT POLLER ====================
async function waitForResult(analysisId) {
    let maxRetries = 4;
    while (maxRetries > 0) {
        await delay(2000);
        try {
            const response = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': API_KEY },
                timeout: 3000
            });
            const attributes = response.data.data.attributes;

            if (attributes.status === 'completed') {
                return {
                    last_analysis_stats: attributes.stats
                };
            }
            maxRetries--;
        } catch (e) { maxRetries--; }
    }
    return null;
}

// ==================== BACKGROUND FILE UPLOAD ====================
async function uploadToVTInBackground(bufferFile, fileName) {
    try {
        const formData = new FormData();
        formData.append('file', bufferFile, { filename: fileName });

        await axios.post(`https://www.virustotal.com/api/v3/files`, formData, {
            headers: {
                'x-apikey': API_KEY,
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
            timeout: 15000
        });

        console.log(`[VT Background] File "${fileName}" berhasil diunggah ke antrean VT!`);
    } catch (uploadErr) {
        console.error("[VT Background Upload Error]", uploadErr.message);
    }
}

// ==================== BACKGROUND URL SUBMIT ====================
async function submitUrlToVTInBackground(url) {
    try {
        await axios.post(`https://www.virustotal.com/api/v3/urls`,
            `url=${encodeURIComponent(url)}`,
            {
                headers: {
                    'x-apikey': API_KEY,
                    'content-type': 'application/x-www-form-urlencoded'
                },
                timeout: 5000
            }
        );
        console.log(`[VT Background] URL "${url}" berhasil disubmit ke VT untuk di-scan!`);
    } catch (err) {
        console.error("[VT Background URL Submit Error]", err.message);
    }
}

// ==================== CEK FILE ====================
async function cekFile(bufferFile, fileName = 'file_mencurigakan.bin') {
    if (!API_KEY) return { found: false, error: 'VT_API_KEY not configured' };

    try {
        const fileHash = calculateHash(bufferFile);
        console.log(`[VT File] Cek Hash: ${fileHash}`);

        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
            headers: { 'x-apikey': API_KEY },
            timeout: 3000
        });

        console.log("[VT] Data ditemukan di Cache Global!");

        return {
            found: true,
            data: response.data.data.attributes
        };

    } catch (error) {
        if (error.response && error.response.status === 404) {
            console.log("[VT] File belum dikenal. Upload di background...");
            uploadToVTInBackground(bufferFile, fileName).catch(console.error);
            return { found: false };
        }

        return { found: false, error: error.message };
    }
}

// ==================== CEK LINK ====================
async function cekLink(url) {
    if (!API_KEY) return { found: false, error: 'VT_API_KEY not configured' };

    try {
        console.log(`[VT Link] Lookup: ${url}`);
        const urlId = getUrlId(url);

        const responseLookup = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': API_KEY },
            timeout: 3000
        });

        const stats = responseLookup.data.data.attributes.last_analysis_stats;
        const bahaya = (stats.malicious || 0) + (stats.suspicious || 0);
        console.log(`[VT] Data Link ditemukan! Malicious: ${stats.malicious || 0}, Suspicious: ${stats.suspicious || 0}, Harmless: ${stats.harmless || 0}`);
        return {
            found: true,
            data: stats
        };

    } catch (error) {
        if (error.response && error.response.status === 404) {
            console.log("[VT] Link belum ada di database. Submit ke VT di background...");
            submitUrlToVTInBackground(url).catch(console.error);
        } else {
            console.log(`[VT] Link lookup error (HTTP ${error.response?.status || '?'}): ${error.message}`);
        }
        return { found: false };
    }
}

module.exports = { cekLink, cekFile };