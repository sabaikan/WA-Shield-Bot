/**
 * Modul Forensik SSL/TLS & DNS (Deep Transport Layer Inspection)
 * 
 * Menganalisis sertifikat SSL dan record DNS dari suatu domain
 * untuk mendeteksi situs phishing yang menyalahgunakan HTTPS gratisan.
 * 
 * Menggunakan modul bawaan Node.js: tls, dns, url — tanpa dependency tambahan.
 */

const tls = require('tls');
const dns = require('dns');
const { URL } = require('url');

// Daftar Certificate Authority gratisan yang sering disalahgunakan
const FREE_CA_ISSUERS = [
    "let's encrypt",
    "letsencrypt",
    "r3",               // Let's Encrypt intermediate
    "r10",              // Let's Encrypt intermediate baru
    "r11",              // Let's Encrypt intermediate baru
    "e5",               // Let's Encrypt ECDSA
    "e6",               // Let's Encrypt ECDSA
    "zerossl",
    "buypass",
    "cloudflare origin",
    "cloudflare inc",
    "google trust services", // GTS — gratis tapi legitimate, skor lebih rendah
];

// Brand finansial Indonesia yang sering dipakai untuk phishing
const FINANCIAL_BRANDS = [
    'dana', 'bca', 'bri', 'mandiri', 'bni', 'gopay', 'ovo', 'shopee',
    'jenius', 'jago', 'cimb', 'permata', 'tokopedia', 'bukalapak',
    'linkaja', 'flip', 'kredivo', 'akulaku', 'indodax', 'kemenkes',
    'pajak', 'bpjs', 'telkomsel', 'gojek', 'grab', 'traveloka'
];

// Domain resmi yang TIDAK boleh dianggap mencurigakan (whitelist)
const TRUSTED_DOMAINS = [
    'google.com', 'google.co.id', 'youtube.com', 'facebook.com',
    'instagram.com', 'twitter.com', 'x.com', 'whatsapp.com',
    'microsoft.com', 'github.com', 'wikipedia.org',
    'bca.co.id', 'bri.co.id', 'mandiri.co.id', 'bni.co.id',
    'dana.id', 'gopay.co.id', 'ovo.id', 'shopee.co.id',
    'tokopedia.com', 'bukalapak.com', 'gojek.com', 'grab.com',
    'traveloka.com', 'telkomsel.com', 'pajak.go.id', 'bpjs-kesehatan.go.id',
    'kemnaker.go.id', 'kemkes.go.id'
];

/**
 * Mengecek apakah domain termasuk dalam whitelist (trusted)
 */
function isTrustedDomain(hostname) {
    return TRUSTED_DOMAINS.some(trusted =>
        hostname === trusted || hostname.endsWith('.' + trusted)
    );
}

/**
 * inspectSSL — Membuka koneksi TLS langsung ke server target
 * dan mengekstrak informasi sertifikat SSL.
 * 
 * @param {string} hostname - Domain yang akan diinspeksi
 * @returns {Promise<Object>} Detail sertifikat + skor risiko
 */
function inspectSSL(hostname) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            resolve({
                success: false,
                error: 'Connection timeout',
                score: 0,
                notes: []
            });
        }, 8000); // 8 detik timeout

        try {
            const socket = tls.connect(443, hostname, {
                servername: hostname,     // SNI
                rejectUnauthorized: false // Terima semua cert agar bisa dianalisis
            }, () => {
                clearTimeout(timeout);
                try {
                    const cert = socket.getPeerCertificate(true);
                    socket.destroy();

                    if (!cert || !cert.subject) {
                        resolve({
                            success: false,
                            error: 'No certificate found',
                            score: 20,
                            notes: ['Server tidak memiliki sertifikat SSL yang valid']
                        });
                        return;
                    }

                    // Ekstrak data sertifikat
                    const issuerOrg = (cert.issuer?.O || '').toLowerCase();
                    const issuerCN = (cert.issuer?.CN || '').toLowerCase();
                    const subjectCN = (cert.subject?.CN || '').toLowerCase();
                    const validFrom = new Date(cert.valid_from);
                    const validTo = new Date(cert.valid_to);
                    const now = new Date();

                    // Hitung umur sertifikat dalam hari
                    const certAgeDays = Math.floor((now - validFrom) / (1000 * 60 * 60 * 24));
                    const certLifetimeDays = Math.floor((validTo - validFrom) / (1000 * 60 * 60 * 24));

                    // Cek apakah issuer gratisan
                    const issuerFull = `${issuerOrg} ${issuerCN}`.toLowerCase();
                    const isFreeCert = FREE_CA_ISSUERS.some(ca => issuerFull.includes(ca));

                    // Cek apakah self-signed
                    const isSelfSigned = (cert.issuer?.CN === cert.subject?.CN) &&
                        (cert.issuer?.O === cert.subject?.O) &&
                        (!cert.issuer?.O || cert.issuer?.O === '');

                    // Cek apakah domain mengandung brand finansial
                    const containsBrand = FINANCIAL_BRANDS.some(brand =>
                        hostname.includes(brand)
                    );

                    // --- Kalkulasi Skor Risiko ---
                    let score = 0;
                    let notes = [];

                    // 1. Self-signed certificate
                    if (isSelfSigned) {
                        score += 50;
                        notes.push('⚠️ Sertifikat SSL SELF-SIGNED (tidak diverifikasi otoritas manapun)');
                    }

                    // 2. Sertifikat baru + issuer gratisan
                    if (isFreeCert) {
                        if (certAgeDays <= 7) {
                            score += 40;
                            notes.push(`🚨 Sertifikat SSL baru diterbitkan ${certAgeDays} hari lalu oleh CA gratisan (${issuerOrg || issuerCN})`);
                        } else if (certAgeDays <= 30) {
                            score += 25;
                            notes.push(`⚠️ Sertifikat SSL masih muda (${certAgeDays} hari) dari CA gratisan (${issuerOrg || issuerCN})`);
                        } else if (certAgeDays <= 90) {
                            score += 10;
                            notes.push(`ℹ️ Sertifikat SSL dari CA gratisan (${issuerOrg || issuerCN}), umur ${certAgeDays} hari`);
                        }
                    }

                    // 3. Brand finansial + cert gratisan = sangat mencurigakan
                    if (containsBrand && isFreeCert && certAgeDays <= 30) {
                        score += 35;
                        notes.push(`🚨 Domain mengandung nama brand finansial tapi menggunakan sertifikat gratisan yang baru!`);
                    }

                    // 4. Sertifikat lifetime sangat pendek (90 hari — ciri khas Let's Encrypt)
                    // Ini bukan otomatis bahaya, tapi jadi konteks tambahan
                    if (certLifetimeDays <= 90 && containsBrand) {
                        score += 10;
                        notes.push('ℹ️ Masa berlaku sertifikat hanya 90 hari (ciri khas penyedia gratisan)');
                    }

                    // 5. Cert sudah expired
                    if (now > validTo) {
                        score += 30;
                        notes.push('🚨 Sertifikat SSL sudah KEDALUWARSA!');
                    }

                    // 6. Subject CN tidak cocok dengan hostname
                    if (subjectCN !== hostname && !subjectCN.startsWith('*.')) {
                        // Cek wildcard match
                        const wildcardMatch = subjectCN.startsWith('*.') &&
                            hostname.endsWith(subjectCN.slice(1));
                        if (!wildcardMatch) {
                            // Cek SAN (Subject Alternative Names)
                            const san = cert.subjectaltname || '';
                            const sanHosts = san.split(',').map(s => s.trim().replace('DNS:', '').toLowerCase());
                            if (!sanHosts.includes(hostname)) {
                                score += 20;
                                notes.push(`⚠️ Nama domain di sertifikat (${subjectCN}) tidak cocok dengan URL`);
                            }
                        }
                    }

                    const sslDetails = {
                        issuer: issuerOrg || issuerCN || 'Unknown',
                        subject: subjectCN,
                        validFrom: validFrom.toISOString().split('T')[0],
                        validTo: validTo.toISOString().split('T')[0],
                        certAgeDays,
                        certLifetimeDays,
                        isFreeCert,
                        isSelfSigned
                    };

                    console.log(`[SSL Forensik] ${hostname}: Issuer=${sslDetails.issuer}, Umur=${certAgeDays}hari, Free=${isFreeCert}, Score=+${score}`);

                    resolve({
                        success: true,
                        score,
                        notes,
                        details: sslDetails
                    });

                } catch (certError) {
                    socket.destroy();
                    resolve({
                        success: false,
                        error: certError.message,
                        score: 10,
                        notes: ['Gagal membaca sertifikat SSL']
                    });
                }
            });

            socket.on('error', (err) => {
                clearTimeout(timeout);
                console.log(`[SSL Forensik] Koneksi gagal ke ${hostname}: ${err.message}`);
                resolve({
                    success: false,
                    error: err.message,
                    score: 15,
                    notes: ['Server tidak mendukung koneksi SSL/TLS']
                });
            });

        } catch (e) {
            clearTimeout(timeout);
            resolve({
                success: false,
                error: e.message,
                score: 0,
                notes: []
            });
        }
    });
}

/**
 * inspectDNS — Query DNS record (TXT dan A) dari domain
 * untuk mendeteksi anomali routing / domain baru tanpa konfigurasi.
 * 
 * @param {string} hostname - Domain yang akan diinspeksi
 * @returns {Promise<Object>} Detail DNS + skor risiko
 */
function inspectDNS(hostname) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            resolve({ success: false, score: 0, notes: [], details: {} });
        }, 5000);

        const results = {
            txtRecords: null,
            aRecords: null,
            hasSPF: false,
            hasDMARC: false,
            hasDKIM: false,
        };

        let completed = 0;
        const totalQueries = 2;

        function checkDone() {
            completed++;
            if (completed >= totalQueries) {
                clearTimeout(timeout);

                let score = 0;
                let notes = [];

                // Analisis TXT records
                if (results.txtRecords === null || results.txtRecords.length === 0) {
                    score += 15;
                    notes.push('ℹ️ Domain tidak memiliki DNS TXT record (kemungkinan domain baru/tidak dikonfigurasi)');
                } else {
                    const allTxt = results.txtRecords.flat().join(' ').toLowerCase();
                    results.hasSPF = allTxt.includes('v=spf1');
                    results.hasDMARC = allTxt.includes('v=dmarc1');
                }

                // Domain yang mengandung brand tapi tanpa SPF/DMARC = mencurigakan
                const containsBrand = FINANCIAL_BRANDS.some(brand => hostname.includes(brand));
                if (containsBrand && !results.hasSPF && !results.hasDMARC && results.txtRecords !== null) {
                    score += 10;
                    notes.push('⚠️ Domain mengandung nama brand tapi tidak memiliki konfigurasi email security (SPF/DMARC)');
                }

                console.log(`[DNS Forensik] ${hostname}: TXT=${results.txtRecords?.length || 0} records, SPF=${results.hasSPF}, DMARC=${results.hasDMARC}, Score=+${score}`);

                resolve({
                    success: true,
                    score,
                    notes,
                    details: {
                        hasSPF: results.hasSPF,
                        hasDMARC: results.hasDMARC,
                        txtRecordCount: results.txtRecords?.length || 0,
                        ipAddresses: results.aRecords || []
                    }
                });
            }
        }

        // Query TXT records
        dns.resolveTxt(hostname, (err, records) => {
            if (!err) results.txtRecords = records;
            else results.txtRecords = null;
            checkDone();
        });

        // Query A records (IPv4)
        dns.resolve4(hostname, (err, addresses) => {
            if (!err) results.aRecords = addresses;
            checkDone();
        });
    });
}

/**
 * forensicScan — Fungsi utama orchestrator.
 * Parse URL, lalu panggil inspectSSL + inspectDNS secara paralel.
 * 
 * @param {string} urlString - URL lengkap yang akan dianalisis
 * @returns {Promise<Object>} Hasil gabungan skor + catatan forensik
 */
async function forensicScan(urlString) {
    try {
        // Pastikan URL valid dan HTTPS
        if (!urlString.startsWith('http')) {
            urlString = 'http://' + urlString;
        }

        const parsed = new URL(urlString);
        const hostname = parsed.hostname.toLowerCase();

        // Skip analisis forensik untuk domain yang di-whitelist
        if (isTrustedDomain(hostname)) {
            console.log(`[Forensik] ${hostname} ada di whitelist — skip forensik SSL/DNS`);
            return {
                score: 0,
                notes: [],
                sslDetails: null,
                dnsDetails: null,
                skipped: true,
                reason: 'Domain terpercaya (whitelist)'
            };
        }

        // Hanya analisis SSL untuk HTTPS
        if (parsed.protocol !== 'https:') {
            console.log(`[Forensik] ${urlString} bukan HTTPS — skip inspeksi SSL, hanya DNS`);
            const dnsResult = await inspectDNS(hostname);
            return {
                score: dnsResult.score,
                notes: dnsResult.notes,
                sslDetails: null,
                dnsDetails: dnsResult.details || null,
                skipped: false
            };
        }

        // Jalankan SSL dan DNS inspection secara paralel
        const [sslResult, dnsResult] = await Promise.all([
            inspectSSL(hostname),
            inspectDNS(hostname)
        ]);

        const totalScore = sslResult.score + dnsResult.score;
        const allNotes = [...sslResult.notes, ...dnsResult.notes];

        console.log(`[Forensik] Total skor forensik untuk ${hostname}: ${totalScore}`);

        return {
            score: totalScore,
            notes: allNotes,
            sslDetails: sslResult.details || null,
            dnsDetails: dnsResult.details || null,
            skipped: false
        };

    } catch (e) {
        console.error('[Forensik] Error:', e.message);
        return {
            score: 0,
            notes: [],
            sslDetails: null,
            dnsDetails: null,
            skipped: true,
            reason: 'Error: ' + e.message
        };
    }
}

module.exports = { forensicScan, inspectSSL, inspectDNS };
