/**
 * Modul Analisis Link — Multi-Layer URL Threat Detection
 * 
 * Lapisan Inspeksi:
 * 1. Reputasi dasar (punycode, IP, TLD, brand impersonation)
 * 2. Forensik SSL/TLS & DNS (via sslforensics.js)
 * 3. Strict TLD Whitelisting untuk Authority Spoofing
 * 4. Inspeksi DOM untuk Credential Harvesting (via dominspector.js)
 */

const { URL } = require('url');
const axios = require('axios');
const { forensicScan } = require('./sslforensics');
const { inspectDOM } = require('./dominspector');
require('dotenv').config();

const SUSPICIOUS_PATTERNS = [
    'dana-kaget', 'free-fire', 'diamond-gratis', 'login-ig', 'verify-account',
    'bank-bri', 'bca-mobile', 'brimo-apk', 'video-viral', 'hadiah-gratis',
    'pulsa-gratis', 'kuota-gratis', 'wa.me/settings', 'whatsapp.com/otp'
];

const SPAMMY_TLDS = ['.xyz', '.top', '.club', '.tk', '.gq', '.cn', '.ru', '.ml', '.cc', '.click', '.site', '.online', '.website'];

const IP_LOGGERS = ['grabify.link', 'iplogger.org', 'bit.ly', 'is.gd', 'tinyurl.com', 's.id', 'shorturl.at', 'cutt.ly'];

const SUSPICIOUS_HOSTS = [
    'ngrok.io', 'vercel.app', 'pages.dev', 'bukaolshop.site', '000webhostapp.com',
    'firebaseapp.com', 'pythonanywhere.com', 'repl.co', 'glitch.me',
    // Tambahan platform hosting gratis yang sering disalahgunakan
    'netlify.app', 'herokuapp.com', 'surge.sh', 'onrender.com', 'fly.dev',
    'railway.app', 'web.app', 'appspot.com', 'azurewebsites.net',
    'cloudflare.dev', 'workers.dev', 'deno.dev', 'github.io',
    'infinityfreeapp.com', 'epizy.com', 'rf.gd',
];

// Indikator Google Ads tracking — sering dipakai scammer untuk drive traffic ke phishing
const SUSPICIOUS_AD_PARAMS = ['gad_source', 'gad_campaignid', 'gbraid', 'wbraid', 'gclid'];

// Heuristik: analisis subdomain pada platform hosting gratis
// Mendeteksi nama acak/gibberish DAN nama panjang tanpa makna yang jelas
// Situs legitimate: "my-portfolio", "cool-blog", "johnsmith"
// Scammer: "bafamilinga", "xk2j4m", "a1b2c3d4"
// Returns: { score: number, note: string|null }
function analyzeSubdomain(hostname) {
    for (const host of SUSPICIOUS_HOSTS) {
        if (hostname.endsWith('.' + host)) {
            const subdomain = hostname.replace('.' + host, '');
            if (!subdomain || subdomain.length < 3) continue;

            const lowerSub = subdomain.toLowerCase();
            const vowels = (lowerSub.match(/[aeiou]/g) || []).length;
            const consonants = (lowerSub.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;
            const totalLetters = vowels + consonants;
            const digitCount = (lowerSub.match(/\d/g) || []).length;

            // === TIER 1: Jelas gibberish/random (skor tinggi) ===

            // Sangat sedikit vokal → random string (e.g., "xk2j4m", "bcdfgh")
            if (totalLetters >= 6) {
                const vowelRatio = vowels / totalLetters;
                if (vowelRatio < 0.2) {
                    return { score: 30, note: `⚠️ Subdomain "${subdomain}" pada hosting gratis terlihat acak/random — sangat umum dipakai situs penipuan.` };
                }
            }

            // Kluster konsonan berturut-turut >= 4 (e.g., "strng", "brfkl")
            if (/[bcdfghjklmnpqrstvwxyz]{4,}/i.test(lowerSub)) {
                return { score: 30, note: `⚠️ Subdomain "${subdomain}" memiliki pola huruf tidak wajar — umum dipakai situs penipuan.` };
            }

            // Banyak angka pada subdomain panjang (e.g., "site123abc456")
            if (lowerSub.length >= 8 && digitCount >= 3) {
                return { score: 25, note: `⚠️ Subdomain "${subdomain}" mengandung banyak angka acak — pola mencurigakan.` };
            }

            // === TIER 2: Kata panjang tanpa makna pada hosting gratis (skor sedang) ===
            // Situs legit biasanya punya nama pendek atau bermakna:
            //   "my-blog", "portfolio", "cool-app", "johndoe"
            // Scammer sering pakai kata nonsens panjang:
            //   "bafamilinga", "xoranthesk", "plintova"

            const KNOWN_SEGMENTS = [
                'blog', 'app', 'web', 'site', 'page', 'dev', 'code', 'test', 'demo',
                'api', 'admin', 'dash', 'panel', 'store', 'shop', 'game', 'play',
                'music', 'photo', 'video', 'news', 'info', 'docs', 'wiki', 'learn',
                'studio', 'design', 'agency', 'team', 'home', 'main', 'lab', 'hub',
                'cloud', 'chat', 'mail', 'tool', 'bot', 'social', 'media', 'link',
                'health', 'food', 'travel', 'sport', 'art', 'tech', 'data', 'work',
                'portfolio', 'project', 'landing', 'personal', 'business', 'company',
                'creative', 'digital', 'official', 'resume', 'profile', 'react',
                'angular', 'next', 'node', 'python', 'flask', 'django', 'gallery',
                'showcase', 'template', 'starter', 'hello', 'world', 'example',
                'crypto', 'market', 'trade', 'finance', 'invest', 'education',
                'school', 'university', 'college', 'academy', 'clinic', 'hospital',
                'doctor', 'lawyer', 'office', 'restaurant', 'cafe', 'hotel',
                'booking', 'rental', 'weather', 'recipe', 'fitness', 'yoga',
            ];

            // Subdomain panjang (>= 8 huruf), tanpa pemisah, tanpa kata bermakna
            if (lowerSub.length >= 8 && !lowerSub.includes('-') && digitCount === 0) {
                const hasKnownSegment = KNOWN_SEGMENTS.some(w => lowerSub.includes(w));
                if (!hasKnownSegment) {
                    return { score: 25, note: `⚠️ Subdomain "${subdomain}" pada hosting gratis tidak mengandung kata bermakna — pola umum situs penipuan.` };
                }
            }

            // Subdomain pendek tapi campuran huruf-angka aneh (e.g., "ab3k", "x1y2")
            if (lowerSub.length >= 4 && digitCount >= 2 && totalLetters >= 2) {
                return { score: 20, note: `⚠️ Subdomain "${subdomain}" adalah campuran huruf-angka acak — pola mencurigakan.` };
            }

            return { score: 0, note: null };
        }
    }
    return { score: 0, note: null };
}

const FINANCIAL_BRANDS = ['dana', 'bca', 'bri', 'pulsa', 'gopay', 'ovo', 'shopee', 'mandiri', 'bni', 'jenius', 'jago'];
const OFFICIAL_TLDS = ['.com', '.co.id', '.id', '.net', '.org', '.go.id', '.ac.id', '.sch.id', '.mil.id'];

// Domain terpercaya yang TIDAK perlu di-scan (whitelist)
// Mencegah false positive dari VT / DNS / DOM pada situs populer
const TRUSTED_DOMAINS = [
    'google.com', 'google.co.id', 'youtube.com', 'youtu.be',
    'facebook.com', 'fb.com', 'instagram.com', 'threads.net',
    'twitter.com', 'x.com', 'linkedin.com', 'pinterest.com',
    'whatsapp.com', 'wa.me', 'telegram.org', 't.me',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'github.com', 'gitlab.com', 'stackoverflow.com',
    'wikipedia.org', 'wikimedia.org',
    'apple.com', 'icloud.com', 'amazon.com', 'netflix.com',
    'spotify.com', 'zoom.us', 'discord.com', 'discord.gg',
    'reddit.com', 'tiktok.com', 'snapchat.com',
    'bca.co.id', 'bri.co.id', 'mandiri.co.id', 'bni.co.id',
    'dana.id', 'gopay.co.id', 'ovo.id', 'shopee.co.id',
    'tokopedia.com', 'bukalapak.com', 'lazada.co.id', 'blibli.com',
    'gojek.com', 'grab.com', 'traveloka.com',
    'telkomsel.com', 'indosat.com', 'xl.co.id',
    'detik.com', 'kompas.com', 'tribunnews.com', 'liputan6.com',
    'cnnindonesia.com', 'cnbcindonesia.com', 'tempo.co', 'kumparan.com',
    'pajak.go.id', 'bpjs-kesehatan.go.id', 'kemnaker.go.id', 'kemkes.go.id',
];

// ==================== AUTHORITY SPOOFING DETECTION ====================
// Keywords konteks pelaporan/kepolisian/pemerintah
const AUTHORITY_CONTEXT_KEYWORDS = [
    // Kepolisian / Hukum
    /lapor\s*(polisi|kepolisian|cyber|online)/i,
    /cyber\s*crime/i,
    /bareskrim|polda|polres|polsek|mabes|korlantas|divhumas/i,
    /formulir.*?(lapor|aduan|pengaduan)/i,
    /aduan.*?(kepolisian|polisi|cyber)/i,
    /kepolisian|polri/i,
    /kejahatan\s*siber/i,
    /tilang|e-?tilang|etle/i,
    /pengaduan.*?online/i,

    // Pajak / DJP / Keuangan Negara
    /pajak|tax/i,
    /djp|direktorat.*?pajak/i,
    /npwp|e-?fin|efin/i,
    /spt\s*tahunan/i,
    /refund.*?pajak|pengembalian.*?pajak|restitusi/i,
    /kelebihan.*?bayar.*?pajak/i,
    /bea\s*materai|e-?materai/i,

    // BPJS / Kesehatan
    /bpjs|jamsostek/i,
    /jaminan.*?kesehatan|jaminan.*?sosial|jaminan.*?pensiun|jaminan.*?hari.*?tua/i,
    /kartu.*?indonesia.*?sehat|kis\b/i,
    /kemenkes|kementerian.*?kesehatan/i,

    // Bea Cukai / Ekspor Impor
    /bea\s*cukai|beacukai/i,
    /custom|pabean/i,
    /paket.*?(tertahan|ditahan|bea|sita)/i,

    // Imigrasi / Paspor
    /imigrasi|ditjen.*?imigrasi/i,
    /paspor|pasport|e-?paspor/i,
    /visa.*?(ditolak|bermasalah|approval)/i,
    /kitas|kitap/i,

    // BPN / Pertanahan / ATR
    /bpn|pertanahan|atr\/bpn/i,
    /sertifikat.*?tanah|ptsl/i,
    /sengketa.*?lahan|sengketa.*?tanah/i,

    // Listrik / Energi (BUMN)
    /pln|perusahaan.*?listrik/i,
    /tagihan.*?listrik|token.*?listrik|meteran.*?listrik/i,
    /tunggakan.*?(listrik|pln)/i,
    /pemutusan.*?(listrik|pln)/i,
    /pertamina|mypertamina/i,
    /pgn|gas.*?negara/i,

    // Air / PAM / PDAM
    /pdam|pam\s*jaya|paljaya|air.*?minum/i,
    /tagihan.*?air|tunggakan.*?air/i,

    // Telekomunikasi (Telkom BUMN & Kominfo)
    /telkom|telkomsel|indihome/i,
    /kominfo|pse|kementerian.*?komunikasi/i,
    /pemblokiran.*?nomor|blokir.*?kominfo/i,

    // Pengadilan / Hukum / Kejaksaan
    /pengadilan|mahkamah/i,
    /surat.*?panggilan|relaas/i,
    /somasi/i,
    /kejaksaan|kejari|kejati|kejagung/i,
    /kemenkumham/i,

    // Lembaga Independen & Pengawas
    /ojk|otoritas.*?jasa.*?keuangan/i,
    /kpk|komisi.*?pemberantasan.*?korupsi/i,
    /bi|bank.*?indonesia/i,
    /lps|lembaga.*?penjamin.*?simpanan/i,
    /ppatk/i,
    /ombudsman/i,
    /bnn|narkotika/i,
    /bnpb|basarnas|bmkg/i,
    /kpu|bawaslu/i,

    // Kementerian Sosial / Bansos / Ketenagakerjaan
    /kemensos|bantuan.*?sosial/i,
    /bansos|blt|bantuan.*?langsung.*?tunai/i,
    /pks|pkh|program.*?keluarga.*?harapan/i,
    /prakerja|kartu.*?prakerja/i,
    /kemnaker|ketenagakerjaan|bantuan.*?upah|bsu/i,

    // Dukcapil / Kependudukan
    /dukcapil|kependudukan/i,
    /kk|kartu.*?keluarga/i,
    /ktp|e-?ktp|ktp-?el/i,
    /akta.*?kelahiran/i,
    /identitas.*?kependudukan.*?digital|ikd/i,

    // Perhubungan / Transportasi
    /kemenhub|perhubungan/i,
    /jasamarga|jasa.*?raharja/i,
    /kai|kereta.*?api/i,
    /pelni|angkasa.*?pura/i,

    // Pendidikan / Agama
    /kemdikbud|kemendikbud|ristekdikti/i,
    /kemenag|kementerian.*?agama/i,
    /kip|kartu.*?indonesia.*?pintar/i,
    /snmptn|sbmptn|utbk|snbp|snbt/i,
    /lpdp/i,
];

const GOVERNMENT_DOMAINS = [
    '.go.id',
    '.polri.go.id',
    '.mil.id',
    '.lapor.go.id',
    '.desa.id',
];

/**
 * Cek apakah konteks pesan mengindikasikan klaim otoritas
 * @param {string} messageContext - Teks pesan yang menyertai URL
 * @returns {boolean}
 */
function hasAuthorityContext(messageContext) {
    if (!messageContext) return false;
    return AUTHORITY_CONTEXT_KEYWORDS.some(pattern => pattern.test(messageContext));
}

/**
 * Cek apakah domain termasuk domain pemerintah resmi
 * @param {string} hostname 
 * @returns {boolean}
 */
function isGovernmentDomain(hostname) {
    return GOVERNMENT_DOMAINS.some(gov => hostname.endsWith(gov));
}

// ==================== URL UNSHORTENER ====================
async function unshortenUrl(urlString, depth = 0) {
    if (depth >= 5) return urlString; // Max 5 redirect

    try {
        const response = await axios.head(urlString, {
            maxRedirects: 0, // Jangan ikuti otomatis
            timeout: 5000,
            validateStatus: status => status >= 200 && status < 400
        });

        // Jika ada lokasi redirect
        if (response.headers.location) {
            let nextUrl = response.headers.location;
            if (!nextUrl.startsWith('http')) {
                const parsedOriginal = new URL(urlString);
                nextUrl = `${parsedOriginal.protocol}//${parsedOriginal.host}${nextUrl}`;
            }
            return unshortenUrl(nextUrl, depth + 1);
        }

        return urlString;
    } catch (error) {
        // Fallback ke GET request jika HEAD ditolak
        try {
            const getResponse = await axios.get(urlString, {
                maxRedirects: 0,
                timeout: 5000,
                validateStatus: status => status >= 200 && status < 400
            });

            if (getResponse.headers.location) {
                let nextUrl = getResponse.headers.location;
                if (!nextUrl.startsWith('http')) {
                    const parsedOriginal = new URL(urlString);
                    nextUrl = `${parsedOriginal.protocol}//${parsedOriginal.host}${nextUrl}`;
                }
                return unshortenUrl(nextUrl, depth + 1);
            }
            return urlString;
        } catch (e) {
            return urlString;
        }
    }
}

// ==================== FUNGSI ANALISIS UTAMA ====================
/**
 * Analisis link secara komprehensif
 * @param {string} originalUrlString - URL target
 * @param {string} [messageContext] - Teks pesan yang menyertai URL (untuk konteks authority spoofing)
 * @returns {Promise<object>} Hasil analisis
 */
async function analyzeLink(originalUrlString, messageContext = '') {
    let score = 0;
    const notes = []; // Catatan forensik/ancaman tambahan

    try {
        let urlString = originalUrlString;
        if (!urlString.startsWith('http')) {
            urlString = 'http://' + urlString;
        }

        const initialParsed = new URL(urlString);
        const initialHostname = initialParsed.hostname.toLowerCase();

        // === EARLY EXIT: Skip analisis untuk domain terpercaya ===
        // Mencegah false positive dari VT / DNS / DOM pada situs populer (YouTube, Google, dll)
        const isTrusted = TRUSTED_DOMAINS.some(trusted =>
            initialHostname === trusted || initialHostname.endsWith('.' + trusted)
        );
        if (isTrusted) {
            console.log(`[Link] ${initialHostname} adalah domain terpercaya — skip analisis`);
            return {
                status: 'AMAN',
                score: 0,
                riskPercentage: 0,
                domain: initialHostname,
                forensicNotes: [],
                sslDetails: null,
                dnsDetails: null,
                authoritySpoofDetected: false,
                credentialHarvesting: false,
                safeBrowsingFlag: false,
                trusted: true,
            };
        }

        // Deteksi generik untuk URL Shortener (domain pendek, path pendek)
        // contoh: bit.ly/XyZ123, s.id/promo
        const isLikelyShortener = (initialHostname.length <= 15 && initialParsed.pathname.length <= 12 && initialParsed.pathname.length > 1) ||
            IP_LOGGERS.some(domain => initialHostname.includes(domain));

        if (isLikelyShortener) {
            const expandedUrl = await unshortenUrl(urlString);
            if (expandedUrl !== urlString) {
                notes.push(`🔗 LINK UNSHORTENER — Tautan pendek ini aslinya mengarah ke: ${expandedUrl}`);
                urlString = expandedUrl;
            }
        }

        const parsed = new URL(urlString);
        const hostname = parsed.hostname.toLowerCase();
        const pathname = decodeURIComponent(parsed.pathname).toLowerCase();

        // ============================================================
        //  LAYER 1: REPUTASI DASAR
        // ============================================================

        // 1. Punycode (Homograph Attack) Detection
        if (hostname.startsWith('xn--')) {
            score += 100;
        }

        // 2. Raw IP Address Detection
        const isIpAddress = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostname);
        if (isIpAddress) {
            score += 50;
        }

        if (IP_LOGGERS.some(domain => hostname.includes(domain))) {
            score += 30;
        }

        // 3. Spammy TLDs Reputation
        const endsWithSpammyTld = SPAMMY_TLDS.some(tld => hostname.endsWith(tld));
        if (endsWithSpammyTld) {
            score += 20;
            if (FINANCIAL_BRANDS.some(brand => hostname.includes(brand))) {
                score += 40;
            }
        }

        if (SUSPICIOUS_HOSTS.some(host => hostname.endsWith(host))) {
            score += 20;
        }

        // 4. Typosquatting (Brand Impersonation)
        const containsBrand = FINANCIAL_BRANDS.some(brand => hostname.includes(brand));
        const hasOfficialTld = OFFICIAL_TLDS.some(tld => hostname.endsWith(tld));

        if (containsBrand && !hasOfficialTld && !isIpAddress && !hostname.startsWith('xn--') && !endsWithSpammyTld) {
            score += 30;
        }

        SUSPICIOUS_PATTERNS.forEach(pattern => {
            if (hostname.includes(pattern)) {
                score += 50;
            } else if (pathname.includes(pattern)) {
                score += 20;
            }
        });

        // 5. Analisis subdomain pada hosting gratis (gibberish + nonsens)
        const subdomainResult = analyzeSubdomain(hostname);
        if (subdomainResult.score > 0) {
            score += subdomainResult.score;
            if (subdomainResult.note) notes.push(subdomainResult.note);
        }

        // 6. Suspicious Ad Tracking Parameters
        const searchParams = parsed.searchParams;
        const adParamsFound = SUSPICIOUS_AD_PARAMS.filter(p => searchParams.has(p));
        if (adParamsFound.length > 0 && SUSPICIOUS_HOSTS.some(host => hostname.endsWith(host))) {
            score += 20;
            notes.push(`⚠️ URL mengandung parameter iklan berbayar (${adParamsFound.join(', ')}) yang mengarah ke hosting gratis — pola umum penipuan via Google Ads.`);
        }

        // ============================================================
        //  LAYER 2 & 4 & 5: FORENSIK SSL/TLS, DNS, DOM & SAFE BROWSING (CONCURRENT)
        // ============================================================
        const [forensicResult, domResult, safeBrowsingResult] = await Promise.all([
            forensicScan(urlString).catch(e => { console.error('[Link] Forensik error:', e.message); return { score: 0, notes: [], sslDetails: null, dnsDetails: null }; }),
            inspectDOM(urlString).catch(e => { console.error('[Link] DOM Inspector error:', e.message); return { score: 0, notes: [], isCredentialHarvesting: false }; }),
            checkSafeBrowsing(urlString).catch(e => { console.error('[Link] Safe Browsing error:', e.message); return { isMalicious: false, threats: [] }; })
        ]);

        score += forensicResult.score + domResult.score;
        if (forensicResult.notes && forensicResult.notes.length > 0) notes.push(...forensicResult.notes);
        if (domResult.notes && domResult.notes.length > 0) notes.push(...domResult.notes);

        if (safeBrowsingResult.isMalicious) {
            score += 80;
            const threats = safeBrowsingResult.threats.join(', ');
            notes.push(`🚨 GOOGLE SAFE BROWSING — URL ini terdeteksi oleh Google sebagai situs berbahaya! Kategori: ${threats}`);
        }

        // ============================================================
        //  LAYER 3: STRICT TLD WHITELISTING (Authority Spoofing)
        // ============================================================
        let authoritySpoofDetected = false;

        if (hasAuthorityContext(messageContext)) {
            // Konteks pesan mengklaim ini dari otoritas
            if (!isGovernmentDomain(hostname)) {
                authoritySpoofDetected = true;
                score += 100;
                notes.push(`🚨 AUTHORITY SPOOFING — Pesan mengklaim ini dari kepolisian/pemerintah, tetapi domain "${hostname}" BUKAN domain resmi pemerintah (.go.id/.polri.go.id). Institusi resmi tidak pernah menggunakan domain gratisan.`);
                console.log(`[Authority Spoofing] DETECTED: ${hostname} bukan .go.id — konteks: "${messageContext.substring(0, 80)}"`);
            }
        }

        // Cek domain yang mengandung nama instansi pemerintah tapi bukan otomatis ekstensi resmi .go.id / .desa.id
        const fakeAuthorityPatterns = /(?:polisi|polri|polda|polres|bareskrim|cyber.?polisi|tilang|etle|djp.?online|pajak|bpjs|bea.?cukai|imigrasi|paspor|pengadilan|mahkamah|kejaksaan|ojk.?online|kpk|kemensos|bansos|prakerja|kemnaker|dukcapil|kominfo|pln.?tagihan|pertamina|pdam|bpn.?online|kemenag|kemdikbud|jasamarga|jasa.?raharja)/i;
        if (fakeAuthorityPatterns.test(hostname) && !isGovernmentDomain(hostname)) {
            if (!authoritySpoofDetected) {
                score += 80;
                notes.push(`🚨 DOMAIN PALSU — Domain "${hostname}" mengandung nama instansi pemerintah tetapi BUKAN domain resmi Indonesia (.go.id). Ini sangat mencurigakan.`);
            }
        }

        // ============================================================
        //  LAYER 4.5: DEAD PAGE DETECTION (Free Hosting)
        // ============================================================
        // Halaman phishing yang sudah di-takedown sering mengembalikan error HTTP.
        // Jika situs di hosting gratis mengembalikan 4xx/5xx → sangat mencurigakan.
        const isOnFreeHosting = SUSPICIOUS_HOSTS.some(host => hostname.endsWith(host));
        if (isOnFreeHosting && domResult.httpStatus && domResult.httpStatus >= 400) {
            score += 20;
            notes.push(`⚠️ Situs pada hosting gratis mengembalikan HTTP ${domResult.httpStatus} — kemungkinan halaman phishing yang sudah dihapus/ditakedown.`);
        }

        // ============================================================
        //  FINAL SCORING
        // ============================================================
        let status = 'AMAN';
        if (score >= 50) status = 'BAHAYA';
        else if (score > 0) status = 'WARNING';

        let riskPercentage = Math.min(Math.round((score / 100) * 100), 100);

        return {
            status,
            score,
            riskPercentage,
            domain: hostname,
            finalUrl: urlString !== originalUrlString ? urlString : undefined,
            forensicNotes: [...(forensicResult.notes || []), ...notes],
            sslDetails: forensicResult.sslDetails || null,
            dnsDetails: forensicResult.dnsDetails || null,
            authoritySpoofDetected,
            credentialHarvesting: domResult.isCredentialHarvesting || false,
            safeBrowsingFlag: safeBrowsingResult.isMalicious || false,
        };

    } catch (e) {
        return { status: 'ERROR', score: 0 };
    }
}

// ==================== GOOGLE SAFE BROWSING API ====================
/**
 * Cek URL di Google Safe Browsing Lookup API v4
 * @param {string} url - URL yang akan dicek
 * @returns {Promise<{isMalicious: boolean, threats: string[]}>}
 */
async function checkSafeBrowsing(url) {
    const apiKey = process.env.SAFE_BROWSING_API_KEY;
    if (!apiKey) {
        return { isMalicious: false, threats: [] };
    }

    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                client: {
                    clientId: 'wa-shield-bot',
                    clientVersion: '1.0.0'
                },
                threatInfo: {
                    threatTypes: [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    platformTypes: ['ANY_PLATFORM'],
                    threatEntryTypes: ['URL'],
                    threatEntries: [{ url }]
                }
            },
            { timeout: 5000 }
        );

        const matches = response.data.matches;
        if (matches && matches.length > 0) {
            const threatLabels = {
                'MALWARE': 'Malware',
                'SOCIAL_ENGINEERING': 'Phishing/Social Engineering',
                'UNWANTED_SOFTWARE': 'Software Berbahaya',
                'POTENTIALLY_HARMFUL_APPLICATION': 'Aplikasi Berpotensi Bahaya'
            };
            const threats = matches.map(m => threatLabels[m.threatType] || m.threatType);
            console.log(`[Safe Browsing] BAHAYA: ${url} — ${threats.join(', ')}`);
            return { isMalicious: true, threats };
        }

        console.log(`[Safe Browsing] ${url} — Tidak ditemukan ancaman`);
        return { isMalicious: false, threats: [] };

    } catch (error) {
        const status = error.response?.status;
        if (status === 403) {
            console.error(`[Safe Browsing] ❌ API key tidak memiliki akses (HTTP 403). Pastikan "Safe Browsing API" sudah di-ENABLE di Google Cloud Console: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com`);
        } else if (status === 400) {
            console.error(`[Safe Browsing] ❌ Request tidak valid (HTTP 400): ${error.response?.data?.error?.message || error.message}`);
        } else {
            console.error(`[Safe Browsing] Error: ${error.message}`);
        }
        return { isMalicious: false, threats: [] };
    }
}

module.exports = { analyzeLink, unshortenUrl };