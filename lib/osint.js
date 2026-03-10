/**
 * Modul Open-Source Intelligence (OSINT) Heuristik untuk Analisis Nomor Telepon
 * 
 * Mendeteksi:
 * - Nomor virtual (burner phone) dari operator Indonesia
 * - Nomor luar negeri dengan tingkat risiko penipuan
 * - Anomali format nomor
 * - Prefix operator Indonesia dan pola VoIP
 */

// ==================== DATABASE KODE NEGARA ====================
const COUNTRY_RISKS = {
    // Asia Tenggara
    '62': { name: 'Indonesia', risk: 'LOW', type: 'LOCAL' },
    '60': { name: 'Malaysia', risk: 'LOW', type: 'FOREIGN' },
    '65': { name: 'Singapura', risk: 'LOW', type: 'FOREIGN' },
    '66': { name: 'Thailand', risk: 'LOW', type: 'FOREIGN' },
    '84': { name: 'Vietnam', risk: 'MEDIUM', type: 'FOREIGN' },
    '63': { name: 'Filipina', risk: 'MEDIUM', type: 'FOREIGN' },
    '95': { name: 'Myanmar', risk: 'HIGH', type: 'FOREIGN' },   // Scam compound
    '855': { name: 'Kamboja', risk: 'HIGH', type: 'FOREIGN' },  // Scam compound
    '856': { name: 'Laos', risk: 'HIGH', type: 'FOREIGN' },     // Scam compound

    // Risiko Tinggi (Sering dipakai penipuan lintas negara)
    '1': { name: 'USA/Canada', risk: 'HIGH', type: 'FOREIGN' },
    '44': { name: 'United Kingdom', risk: 'HIGH', type: 'FOREIGN' },
    '234': { name: 'Nigeria', risk: 'CRITICAL', type: 'FOREIGN' },
    '233': { name: 'Ghana', risk: 'CRITICAL', type: 'FOREIGN' },
    '254': { name: 'Kenya', risk: 'HIGH', type: 'FOREIGN' },
    '27': { name: 'Afrika Selatan', risk: 'MEDIUM', type: 'FOREIGN' },
    '91': { name: 'India', risk: 'MEDIUM', type: 'FOREIGN' },
    '92': { name: 'Pakistan', risk: 'HIGH', type: 'FOREIGN' },
    '880': { name: 'Bangladesh', risk: 'HIGH', type: 'FOREIGN' },

    // Negara umum lainnya
    '81': { name: 'Jepang', risk: 'LOW', type: 'FOREIGN' },
    '82': { name: 'Korea Selatan', risk: 'LOW', type: 'FOREIGN' },
    '86': { name: 'Tiongkok', risk: 'HIGH', type: 'FOREIGN' },
    '852': { name: 'Hong Kong', risk: 'MEDIUM', type: 'FOREIGN' },
    '971': { name: 'UAE', risk: 'MEDIUM', type: 'FOREIGN' },
    '966': { name: 'Arab Saudi', risk: 'MEDIUM', type: 'FOREIGN' },
    '7': { name: 'Rusia', risk: 'HIGH', type: 'FOREIGN' },
    '380': { name: 'Ukraina', risk: 'HIGH', type: 'FOREIGN' },
    '90': { name: 'Turki', risk: 'MEDIUM', type: 'FOREIGN' },
};

// ==================== OPERATOR INDONESIA ====================
// Prefix 4 digit setelah kode negara (62)
const OPERATOR_INDONESIA = {
    // Telkomsel (operator terbesar, relatif aman)x.js
    '0811': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0812': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0813': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0821': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0822': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0823': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0851': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0852': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },
    '0853': { operator: 'Telkomsel', type: 'REGULAR', risk: 0 },

    // by.U (Telkomsel digital — MUDAH registrasi tanpa KTP fisik)
    '0851': { operator: 'by.U (Telkomsel)', type: 'VIRTUAL', risk: 10 },

    // Indosat Ooredoo
    '0814': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0815': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0816': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0855': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0856': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0857': { operator: 'Indosat', type: 'REGULAR', risk: 0 },
    '0858': { operator: 'Indosat', type: 'REGULAR', risk: 0 },

    // XL Axiata
    '0817': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },
    '0818': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },
    '0819': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },
    '0859': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },
    '0878': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },
    '0877': { operator: 'XL Axiata', type: 'REGULAR', risk: 0 },

    // AXIS (XL digital — mudah dapat nomor baru)
    '0831': { operator: 'AXIS', type: 'BUDGET', risk: 5 },
    '0832': { operator: 'AXIS', type: 'BUDGET', risk: 5 },
    '0833': { operator: 'AXIS', type: 'BUDGET', risk: 5 },
    '0838': { operator: 'AXIS', type: 'BUDGET', risk: 5 },

    // Tri (3) — Sangat murah, SERING dipakai penipu
    '0895': { operator: 'Tri (3)', type: 'BUDGET', risk: 15 },
    '0896': { operator: 'Tri (3)', type: 'BUDGET', risk: 15 },
    '0897': { operator: 'Tri (3)', type: 'BUDGET', risk: 15 },
    '0898': { operator: 'Tri (3)', type: 'BUDGET', risk: 15 },
    '0899': { operator: 'Tri (3)', type: 'BUDGET', risk: 15 },

    // Smartfren — Sering dipakai nomor sekali pakai
    '0881': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0882': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0883': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0884': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0885': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0886': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0887': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0888': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
    '0889': { operator: 'Smartfren', type: 'BUDGET', risk: 10 },
};

// ==================== DETEKSI OPERATOR INDONESIA ====================
function detectIndonesianOperator(normalizedNumber) {
    // normalizedNumber format: 628xxxxxxxxx
    if (!normalizedNumber.startsWith('62')) return null;

    // Konversi ke format 08xx
    const localNumber = '0' + normalizedNumber.substring(2);
    const prefix4 = localNumber.substring(0, 4);

    const operatorInfo = OPERATOR_INDONESIA[prefix4];
    if (operatorInfo) {
        return {
            operator: operatorInfo.operator,
            type: operatorInfo.type,
            riskScore: operatorInfo.risk,
            prefix: prefix4
        };
    }

    return { operator: 'Unknown', type: 'UNKNOWN', riskScore: 5, prefix: prefix4 };
}

// ==================== MAIN OSINT CHECK ====================
function checkOsintProfile(normalizedNumber) {
    let countryData = { name: 'Unknown', risk: 'UNKNOWN', type: 'UNKNOWN' };
    let countryCodeUsed = '';
    let isVoipPattern = false;
    let anomalyNotes = [];

    // Deteksi Country Code (1 sampai 3 digit pertama)
    for (let i = 3; i >= 1; i--) {
        let prefix = normalizedNumber.substring(0, i);
        if (COUNTRY_RISKS[prefix]) {
            countryData = COUNTRY_RISKS[prefix];
            countryCodeUsed = prefix;
            break;
        }
    }

    // Deteksi anomali panjang nomor
    const len = normalizedNumber.length;
    if (len < 10 || len > 15) {
        anomalyNotes.push("Panjang nomor tidak lazim (Anomali Format)");
    }

    // ---- Analisis Khusus Nomor Indonesia ----
    let operatorInfo = null;
    if (countryCodeUsed === '62') {
        operatorInfo = detectIndonesianOperator(normalizedNumber);

        if (operatorInfo) {
            anomalyNotes.push(`Operator: ${operatorInfo.operator} (${operatorInfo.prefix})`);

            if (operatorInfo.type === 'VIRTUAL') {
                anomalyNotes.push("⚠️ Nomor dari provider virtual (mudah registrasi tanpa KTP fisik)");
            }
            if (operatorInfo.type === 'BUDGET') {
                anomalyNotes.push("ℹ️ Nomor dari provider budget (sering dipakai nomor sekali pakai)");
            }
        }

        // Deteksi nomor baru jika sangat pendek (kurang dari 11 digit lokal)
        const localLen = normalizedNumber.length - 2; // minus "62"
        if (localLen < 9) {
            anomalyNotes.push("Nomor terlalu pendek untuk Indonesia (kemungkinan tidak valid)");
        }
    }

    // ---- Heuristik VoIP International ----
    if (countryCodeUsed === '1') {
        const tollFreePattern = /^(1800|1888|1877|1866|1855|1844|1833)/;
        if (tollFreePattern.test(normalizedNumber)) {
            isVoipPattern = true;
            anomalyNotes.push("Terdeteksi Toll-Free/Virtual Number AS (TextNow, Google Voice, dll)");
        }
    }

    // Negara-negara scam compound Asia Tenggara
    if (['855', '856', '95'].includes(countryCodeUsed)) {
        anomalyNotes.push("⚠️ Negara ini dikenal memiliki jaringan scam compound internasional");
    }

    // ---- Hitung Skor Risiko ----
    let osintRiskScore = 0;

    // Skor berdasarkan negara
    if (countryData.risk === 'CRITICAL') osintRiskScore += 80;
    else if (countryData.risk === 'HIGH') osintRiskScore += 50;
    else if (countryData.risk === 'MEDIUM') osintRiskScore += 20;

    // Skor VoIP
    if (isVoipPattern) osintRiskScore += 40;

    // Skor anomali panjang
    if (len < 10 || len > 15) osintRiskScore += 15;

    // Skor operator Indonesia
    if (operatorInfo) {
        osintRiskScore += operatorInfo.riskScore;
    }

    return {
        country: countryData.name,
        countryCode: countryCodeUsed,
        countryRiskLevel: countryData.risk,
        isForeign: countryData.type === 'FOREIGN',
        isSuspiciousVoip: isVoipPattern,
        operator: operatorInfo ? operatorInfo.operator : null,
        operatorType: operatorInfo ? operatorInfo.type : null,
        notes: anomalyNotes,
        score: osintRiskScore
    };
}

module.exports = { checkOsintProfile };
