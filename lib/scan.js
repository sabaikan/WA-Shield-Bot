const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const ApkReader = require('adbkit-apkreader');

// ==================== MALWARE HASH CACHE ====================
const HASH_CACHE_PATH = path.join(__dirname, '..', 'data', 'malware_hashes.json');

function loadHashCache() {
    try {
        if (fs.existsSync(HASH_CACHE_PATH)) {
            return JSON.parse(fs.readFileSync(HASH_CACHE_PATH, 'utf-8'));
        }
    } catch (e) {
        console.error('[Hash Cache] Gagal load cache:', e.message);
    }
    return {};
}

function saveHashCache(cache) {
    try {
        const dir = path.dirname(HASH_CACHE_PATH);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(HASH_CACHE_PATH, JSON.stringify(cache, null, 2));
    } catch (e) {
        console.error('[Hash Cache] Gagal save cache:', e.message);
    }
}

function computeSHA256(filePath) {
    try {
        const fileBuffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(fileBuffer).digest('hex');
    } catch (e) {
        return null;
    }
}

/**
 * Tambahkan hash file berbahaya ke cache lokal.
 * Bisa dipanggil dari luar modul (misal dari index.js setelah VirusTotal confirm).
 */
function addMalwareHash(sha256, info = {}) {
    const cache = loadHashCache();
    cache[sha256] = {
        detectedAt: new Date().toISOString(),
        riskLevel: info.riskLevel || 'BAHAYA',
        reason: info.reason || 'Confirmed malware',
        fileName: info.fileName || 'Unknown',
        score: info.score || 100
    };
    saveHashCache(cache);
    console.log(`[Hash Cache] Added: ${sha256.substring(0, 16)}...`);
}

function checkHashCache(sha256) {
    const cache = loadHashCache();
    return cache[sha256] || null;
}

// ==================== DANGEROUS PERMISSIONS (APK) ====================
const DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': 50,
    'android.permission.RECEIVE_SMS': 50,
    'android.permission.SEND_SMS': 40,
    'android.permission.READ_CONTACTS': 35,
    'android.permission.CAMERA': 20,
    'android.permission.RECORD_AUDIO': 20,
    'android.permission.SYSTEM_ALERT_WINDOW': 15,
    'android.permission.REQUEST_INSTALL_PACKAGES': 15,
    'android.permission.BIND_ACCESSIBILITY_SERVICE': 50,
    'android.permission.READ_CALL_LOG': 30,
    'android.permission.WRITE_EXTERNAL_STORAGE': 10,
    'android.permission.READ_EXTERNAL_STORAGE': 10,
    'android.permission.ACCESS_FINE_LOCATION': 15,
    'android.permission.READ_PHONE_STATE': 20,
    'android.permission.RECEIVE_BOOT_COMPLETED': 10,
    'android.permission.FOREGROUND_SERVICE': 5,
    'android.permission.BIND_DEVICE_ADMIN': 60,
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 40,
    'android.permission.QUERY_ALL_PACKAGES': 15,
    'android.permission.USE_FULL_SCREEN_INTENT': 10,
    'android.permission.PACKAGE_USAGE_STATS': 20,
};

// ==================== MAGIC NUMBERS ====================
const MAGIC_NUMBERS = {
    '25504446': 'pdf',
    '4d5a': 'exe',
    '504b0304': 'zip', // APK is also a ZIP
    '7f454c46': 'elf',
    'd0cf11e0': 'doc',
    '89504e47': 'png',
    'ffd8ffe0': 'jpg',
    'ffd8ffe1': 'jpg',
    'ffd8ffdb': 'jpg',
    '52617221': 'rar',
    '1f8b08': 'gz',
    '7b5c7274': 'rtf',
};

// ==================== EKSTENSI BERBAHAYA ====================
const DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.ps1', '.pif', '.com', '.msi', '.dll', '.lnk',
    '.hta', '.cpl', '.inf', '.reg', '.rgs', '.sct', '.shb'
];

// ==================== YARA RULES (Expanded) ====================
const YARA_RULES = {
    // --- C2 & Exfiltration Channels ---
    'Telegram Bot Token': /api\.telegram\.org\/bot\d+:[a-zA-Z0-9_-]+/g,
    'Discord Webhook': /discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/g,
    'Ngrok Tunnel': /https?:\/\/[a-z0-9-]+\.ngrok-free\.app/g,
    'Ngrok Legacy': /https?:\/\/[a-z0-9-]+\.ngrok\.io/g,
    'WebSocket C2': /wss?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    'Raw IP HTTP': /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]/g,

    // --- Exploit Tools ---
    'Metasploit Shellcode': /meterpreter|metasploit|reverse_tcp|reverse_https/gi,
    'SpyNote RAT': /spynote|spy_note/gi,
    'AhMyth RAT': /ahmyth/gi,

    // --- PowerShell / Windows Obfuscation ---
    'PowerShell Encoded': /powershell\s+.*-[eE]nc(?:odedcommand)?\s+[A-Za-z0-9+\/=]{20,}/g,
    'PowerShell Hidden': /powershell\s+.*-[wW](?:indowstyle)?\s+[hH]idden/g,
    'PowerShell Download': /powershell\s+.*(?:Invoke-WebRequest|iwr|curl|wget|DownloadString|DownloadFile)/gi,
    'CMD Hidden Execute': /cmd\s*\/c\s+.*start\s+\/min/gi,
    'Base64 Blob': /[A-Za-z0-9+\/]{500,}={0,2}/g, // Tingkatkan min length dari 100 ke 500 untuk menghindari false positive pada teks normal

    // --- Credential / Data Theft Indicators ---
    'Browser Data Path': /\\(?:User Data|Default|Login Data|Cookies|Web Data)\\/gi,
    'Crypto Wallet Path': /\\(?:Ethereum|Exodus|Electrum|Atomic|Metamask)\\/gi,
    'Password/Keylog Keyword': /(?:keylog|password_stealer|credential_harvest|grab_passwords)/gi,
};

// ==================== PDF MALICIOUS TAGS ====================
// Fitur-fitur ini sah dalam standar PDF (spt /JS untuk form), tapi sering dieksploitasi.
// Skor diturunkan agar tidak false-positive pada PDF portofolio dari Canva/Adobe.
const PDF_DANGEROUS_TAGS = {
    '/JS': 10,           // Sering ada di PDF modern (diturunkan dari 40)
    '/JavaScript': 15,   // Sering ada di PDF modern (diturunkan dari 50)
    '/OpenAction': 15,   // Diturunkan dari 30
    '/AA': 5,            // Additional Actions: Sangat umum di PDF interaktif Adobe (diturunkan dari 25)
    '/Launch': 60,       // SANGAT BAHAYA: mencoba menjalankan .exe eksternal (dinaikkan dari 45)
    '/EmbeddedFile': 25, // Bisa jadi dropper malware (diturunkan dari 30)
    '/RichMedia': 10,    // Flash/Video jadul (diturunkan dari 20)
    '/ObjStm': 5,        // Object Streams (diturunkan dari 15)
    '/XFA': 15,          // XML Forms Architecture (diturunkan dari 25)
    '/URI': 0,           // Eksternal link: normal, tidak perlu skor (diturunkan dari 5)
    '/SubmitForm': 15,   // Formulir phising internal (diturunkan dari 35)
    '/ImportData': 15,   // (diturunkan dari 30)
};

// ==================== KNOWN MALWARE PACKAGE NAMES ====================
const MALWARE_PACKAGE_NAMES = [
    'metasploit', 'spynote', 'ahmyth', 'dendroid', 'cerberus',
    'anubis', 'hydra', 'teabot', 'sharkbot', 'sova', 'brata',
    'flubot', 'medusa', 'xenomorph', 'godfather', 'hookbot',
    'ermac', 'octo', 'vultur', 'nexus'
];

// ==================== YARA SCAN (Memory-Safe) ====================
const MAX_YARA_READ_BYTES = 50 * 1024 * 1024; // Maksimal 50MB untuk YARA scan

async function yaraScan(filePath) {
    let score = 0;
    const detections = [];
    try {
        const stats = fs.statSync(filePath);
        const readSize = Math.min(stats.size, MAX_YARA_READ_BYTES);
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(readSize);
        fs.readSync(fd, buffer, 0, readSize, 0);
        fs.closeSync(fd);
        const content = buffer.toString('utf-8');
        for (const [ruleName, regex] of Object.entries(YARA_RULES)) {
            // Reset regex lastIndex for global patterns
            regex.lastIndex = 0;
            if (regex.test(content)) {
                // Base64 Blob tidak perlu +60 karena sering false positive di PDF
                const penalty = ruleName === 'Base64 Blob' ? 15 : 60;
                score += penalty;
                detections.push(ruleName);
                console.log(`[YARA] Detected: ${ruleName} (+${penalty})`);
            }
        }
    } catch (e) { }
    return { score, detections };
}

// ==================== PDF SCAN ====================
function scanPdfContent(filePath) {
    let score = 0;
    const detections = [];
    try {
        const buffer = fs.readFileSync(filePath);
        const content = buffer.toString('latin1'); // PDF uses latin1 encoding

        for (const [tag, tagScore] of Object.entries(PDF_DANGEROUS_TAGS)) {
            if (tagScore === 0) continue; // Skip if score is 0

            const regex = new RegExp(tag.replace('/', '\\/'), 'gi');
            const matches = content.match(regex);

            if (matches && matches.length > 0) {
                // Batasi multiplier hanya sampai 2x agar PDF dengan banyak AutoAction tidak instan 100+ score
                const multiplier = Math.min(matches.length, 2);
                const appliedScore = tagScore * multiplier;
                score += appliedScore;
                detections.push(`${tag} (x${matches.length})`);
                console.log(`[PDF] Tag detected: ${tag} (appearance: ${matches.length} | +${appliedScore})`);
            }
        }

        // Detect obfuscated streams (hex-encoded JavaScript)
        const hexStreams = content.match(/stream[\s\S]{0,20}(?:[0-9a-fA-F]{2}\s){20,}/g);
        if (hexStreams) {
            score += 30;
            detections.push('Obfuscated hex stream');
            console.log('[PDF] Obfuscated hex stream detected');
        }

    } catch (e) {
        console.error('[PDF Scan Error]', e.message);
    }
    return { score, detections };
}

// ==================== DOUBLE EXTENSION CHECK (ZIP Entries) ====================
function checkDoubleExtension(entryName) {
    const basename = path.basename(entryName);
    const parts = basename.split('.');

    // File like "foto.jpg.apk" or "resi.pdf.exe"
    if (parts.length >= 3) {
        const lastExt = '.' + parts[parts.length - 1].toLowerCase();
        const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();

        // If the real extension is dangerous
        if (DANGEROUS_EXTENSIONS.includes(lastExt)) {
            // And the decoy extension looks normal
            const safeDecoys = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.txt', '.xls', '.xlsx', '.mp4', '.mp3'];
            if (safeDecoys.includes(secondLastExt)) {
                return { isSpoofed: true, realExt: lastExt, decoyExt: secondLastExt };
            }
        }

        // APK disguised as document
        if (lastExt === '.apk' && ['.pdf', '.doc', '.jpg', '.png', '.txt'].includes(secondLastExt)) {
            return { isSpoofed: true, realExt: '.apk', decoyExt: secondLastExt };
        }
    }

    return { isSpoofed: false };
}

// ==================== ZIP ENTRY SCAN (with Zip Slip Protection) ====================

/**
 * Sanitasi nama entry ZIP untuk mencegah serangan Zip Slip / Path Traversal.
 * Menghapus komponen ".." dan path absolut dari nama entry.
 */
function sanitizeZipEntryName(entryName) {
    // Normalize separators
    let safe = entryName.replace(/\\/g, '/');
    // Remove leading slashes (absolute paths)
    safe = safe.replace(/^\/+/, '');
    // Remove any ".." path traversal components
    const parts = safe.split('/').filter(p => p !== '..' && p !== '.');
    return parts.join('/');
}

/**
 * Cek apakah nama entry ZIP mengandung pola path traversal berbahaya.
 */
function isZipSlipAttempt(entryName) {
    const normalized = entryName.replace(/\\/g, '/');
    return normalized.includes('../') ||
        normalized.includes('..\\') ||
        normalized.startsWith('/') ||
        /^[a-zA-Z]:/.test(normalized); // Windows absolute path (C:\...)
}

function scanZipEntries(zipEntries) {
    let score = 0;
    const detections = [];

    for (const entry of zipEntries) {
        const entryName = entry.entryName;
        const ext = path.extname(entryName).toLowerCase();

        // 0. Check for Zip Slip / Path Traversal attack
        if (isZipSlipAttempt(entryName)) {
            score += 90;
            detections.push(`Zip Slip Attack terdeteksi: "${entryName}" (Path Traversal)`);
            console.log(`[ZIP] ⚠️ ZIP SLIP ATTACK DETECTED: ${entryName}`);
        }

        // 1. Check double extension spoofing
        const doubleExtCheck = checkDoubleExtension(entryName);
        if (doubleExtCheck.isSpoofed) {
            score += 80;
            detections.push(`Double Extension Spoofing: "${entryName}" (real: ${doubleExtCheck.realExt})`);
            console.log(`[ZIP] Double extension spoofing: ${entryName}`);
        }

        // 2. Check for standalone dangerous files
        if (DANGEROUS_EXTENSIONS.includes(ext) && ext !== '.js') {
            score += 50;
            detections.push(`Dangerous file in ZIP: "${entryName}" (${ext})`);
            console.log(`[ZIP] Dangerous file type in ZIP: ${entryName}`);
        }

        // 3. Hidden/dot files that are executables
        const basename = path.basename(entryName);
        if (basename.startsWith('.') && DANGEROUS_EXTENSIONS.includes(ext)) {
            score += 30;
            detections.push(`Hidden executable: "${entryName}"`);
            console.log(`[ZIP] Hidden executable in ZIP: ${entryName}`);
        }
    }

    return { score, detections };
}

// ==================== OFFICE MACRO DETECTION ====================
const OFFICE_EXTENSIONS = ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm'];
const OFFICE_DANGEROUS_FILES = {
    'vbaproject.bin': { score: 70, label: 'VBA Macro (vbaProject.bin)' },
    'vbadata.xml': { score: 40, label: 'VBA Data XML' },
    'activex': { score: 50, label: 'ActiveX Control' },
    'oleobject': { score: 45, label: 'OLE Embedded Object' },
    'editdata.mso': { score: 35, label: 'MSO Edit Data (macro container)' },
    '.bin': { score: 15, label: 'Binary file inside Office document' },
};

function scanOfficeMacro(filePath, ext) {
    let score = 0;
    const detections = [];

    // Only scan Office formats
    if (!OFFICE_EXTENSIONS.includes(ext)) {
        return { score, detections };
    }

    try {
        const zip = new AdmZip(filePath);
        const entries = zip.getEntries();

        for (const entry of entries) {
            const entryLower = entry.entryName.toLowerCase();

            for (const [pattern, info] of Object.entries(OFFICE_DANGEROUS_FILES)) {
                if (entryLower.includes(pattern)) {
                    score += info.score;
                    detections.push(`Office Macro: ${info.label} ditemukan di "${entry.entryName}"`);
                    console.log(`[Office] Dangerous file in Office doc: ${entry.entryName}`);
                }
            }

            // Check for external relationships (external links to download payload)
            if (entryLower.endsWith('.rels') || entryLower.endsWith('.xml')) {
                try {
                    const content = entry.getData().toString('utf-8');
                    // External template injection (OLE/macro download)
                    if (/Target\s*=\s*"https?:\/\//i.test(content) && /TargetMode\s*=\s*"External"/i.test(content)) {
                        score += 60;
                        detections.push(`Office External Template Injection: link download eksternal ditemukan di "${entry.entryName}"`);
                        console.log(`[Office] External template injection detected in: ${entry.entryName}`);
                    }
                } catch (e) { /* ignore read errors on individual entries */ }
            }
        }

        // .docm/.xlsm/.pptm = macro-enabled by definition
        if (['.docm', '.xlsm', '.pptm'].includes(ext)) {
            score += 30;
            detections.push(`Format file macro-enabled (${ext})`);
            console.log(`[Office] Macro-enabled format: ${ext}`);
        }

    } catch (e) {
        // Not a valid ZIP/Office = could be old .doc format, skip
        console.log(`[Office] Cannot parse as ZIP: ${e.message}`);
    }

    return { score, detections };
}

// ==================== SAFE ZIP EXTRACTION (Anti Zip-Slip) ====================
function safeExtractEntry(zip, entry, targetDir) {
    const entryName = sanitizeZipEntryName(entry.entryName);
    const resolvedPath = path.resolve(targetDir, path.basename(entryName));
    const resolvedDir = path.resolve(targetDir);

    // Final safety check: extracted path must be within target directory
    if (!resolvedPath.startsWith(resolvedDir)) {
        console.error(`[ZIP] ⛔ Blocked Zip Slip attempt: ${entry.entryName} -> ${resolvedPath}`);
        return null;
    }

    // Extract safely
    zip.extractEntryTo(entry, targetDir, false, true);
    return resolvedPath;
}

// ==================== APK HEURISTICS (Enhanced) ====================
function checkObfuscationHeuristic(manifest, filePath) {
    let score = 0;
    const detections = [];

    try {
        const stats = fs.statSync(filePath);

        // 1. Dropper Detection: APK sangat kecil (<200KB) + permission bahaya
        if (stats.size < 200000) {
            const perms = manifest.usesPermissions || [];
            const sensitivePerms = perms.map(p => typeof p === 'string' ? p : p.name).filter(p => DANGEROUS_PERMISSIONS[p]);
            if (sensitivePerms.length >= 2) {
                score += 50;
                detections.push('APK sangat kecil dengan permission bahaya (Dropper)');
                console.log("[Heuristic] APK berukuran kecil dengan permission bahaya (Dropper detected)");
            }
        }

        // 2. Oversized APK: APK terlalu besar (>100MB) bisa jadi menyembunyikan payload
        if (stats.size > 100 * 1024 * 1024) {
            score += 15;
            detections.push('APK sangat besar (>100MB), kemungkinan menyembunyikan payload');
            console.log("[Heuristic] APK berukuran sangat besar (>100MB)");
        }
    } catch (e) { }

    return { score, detections };
}

function checkDeviceAdmin(manifest) {
    let score = 0;
    const detections = [];

    try {
        // Check for Device Admin in receivers
        const receivers = manifest.application?.receivers || manifest.receivers || [];
        for (const receiver of receivers) {
            const intentFilters = receiver?.intentFilters || [];
            for (const filter of intentFilters) {
                const actions = filter?.actions || [];
                for (const action of actions) {
                    const actionName = typeof action === 'string' ? action : action?.name || '';
                    if (actionName.includes('DEVICE_ADMIN_ENABLED') || actionName.includes('device_admin')) {
                        score += 70;
                        detections.push('APK meminta Device Admin (sulit dihapus, indikasi Ransomware)');
                        console.log('[Heuristic] APK requests Device Admin - highly suspicious');
                    }
                }
            }
        }
    } catch (e) { }

    return { score, detections };
}

function checkHiddenApp(manifest) {
    let score = 0;
    const detections = [];

    try {
        // Check if app has a LAUNCHER category (visible icon)
        let hasLauncher = false;
        const activities = manifest.application?.activities || manifest.activities || [];
        for (const activity of activities) {
            const intentFilters = activity?.intentFilters || [];
            for (const filter of intentFilters) {
                const categories = filter?.categories || [];
                for (const cat of categories) {
                    const catName = typeof cat === 'string' ? cat : cat?.name || '';
                    if (catName.includes('LAUNCHER')) {
                        hasLauncher = true;
                    }
                }
            }
        }

        // APK without launcher icon = hidden app (very suspicious)
        if (!hasLauncher && activities.length > 0) {
            score += 50;
            detections.push('APK tanpa ikon launcher (aplikasi tersembunyi/gaib)');
            console.log('[Heuristic] APK has no LAUNCHER category - hidden app');
        }
    } catch (e) { }

    return { score, detections };
}

// ==================== MAGIC BYTES CHECK ====================
async function checkMagicBytes(filePath, originalExtension) {
    try {
        const buffer = Buffer.alloc(8);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buffer, 0, 8, 0);
        fs.closeSync(fd);

        const hex = buffer.toString('hex').toLowerCase();

        let realType = 'unknown';
        for (let signature in MAGIC_NUMBERS) {
            if (hex.startsWith(signature)) {
                realType = MAGIC_NUMBERS[signature];
                break;
            }
        }

        if ((originalExtension === '.pdf' || originalExtension === '.doc') && realType === 'exe') return 'SPOOFING_EXE_AS_DOC';
        if (originalExtension === '.txt' && realType === 'exe') return 'SPOOFING_EXE_AS_TXT';
        if (originalExtension === '.jpg' && realType === 'exe') return 'SPOOFING_EXE_AS_JPG';
        if (originalExtension === '.png' && realType === 'exe') return 'SPOOFING_EXE_AS_PNG';
        if (originalExtension === '.pdf' && realType === 'zip') return 'SPOOFING_APK_AS_PDF';
        if (originalExtension === '.pdf' && realType === 'rar') return 'SPOOFING_RAR_AS_PDF';
        if (originalExtension === '.jpg' && realType === 'zip') return 'SPOOFING_ZIP_AS_JPG';
        if (originalExtension === '.png' && realType === 'zip') return 'SPOOFING_ZIP_AS_PNG';
        if (originalExtension === '.mp3' && realType === 'exe') return 'SPOOFING_EXE_AS_MP3';

        return 'OK';
    } catch (e) {
        return 'ERROR';
    }
}

// ==================== DEEP SCAN (Main Function) ====================
async function deepScan(filePath, originalName) {
    let extractedPath = null;
    let targetFile = filePath;
    let totalScore = 0;
    let allDetections = [];

    try {
        const ext = path.extname(originalName).toLowerCase();

        // --- Phase 0: SHA-256 Hash Check (Instant Detection) ---
        const fileHash = computeSHA256(filePath);
        if (fileHash) {
            const cachedResult = checkHashCache(fileHash);
            if (cachedResult) {
                console.log(`[Hash Cache] HIT! ${fileHash.substring(0, 16)}... = ${cachedResult.riskLevel}`);
                return {
                    status: 'success',
                    riskLevel: cachedResult.riskLevel,
                    score: cachedResult.score,
                    riskPercentage: Math.min(cachedResult.score, 100),
                    reason: `Hash dikenali: ${cachedResult.reason}`,
                    sha256: fileHash,
                    detections: [`SHA-256 Match: File ini sudah pernah terdeteksi sebagai ${cachedResult.riskLevel} (${cachedResult.reason})`, `Hash: ${fileHash}`]
                };
            }
        }

        // --- Phase 1: Magic Bytes Check ---
        const magicCheck = await checkMagicBytes(filePath, ext);
        if (magicCheck.startsWith('SPOOFING')) {
            // Auto-cache spoofed files as malware
            if (fileHash) addMalwareHash(fileHash, { riskLevel: 'BAHAYA', reason: `Ekstensi dipalsukan (${magicCheck})`, fileName: originalName, score: 100 });
            return {
                status: 'success',
                riskLevel: 'BAHAYA',
                score: 100,
                riskPercentage: 100,
                reason: `Ekstensi file dipalsukan (${magicCheck})`,
                sha256: fileHash,
                detections: [magicCheck]
            };
        }

        // --- Phase 2: ZIP/RAR Handling ---
        if (ext === '.zip' || ext === '.rar') {
            try {
                const zip = new AdmZip(filePath);
                const zipEntries = zip.getEntries();

                // Scan all ZIP entries for suspicious patterns
                const zipScanResult = scanZipEntries(zipEntries);
                totalScore += zipScanResult.score;
                allDetections.push(...zipScanResult.detections);

                let apkEntry = null;
                for (const entry of zipEntries) {
                    if (entry.entryName.toLowerCase().endsWith('.apk')) {
                        apkEntry = entry;
                        break;
                    }
                }

                if (apkEntry) {
                    // Cek indikasi ZIP Bomb (uncompressed size > 200MB)
                    if (apkEntry.header.size > 200 * 1024 * 1024) {
                        return { status: 'error', reason: 'Indikasi ZIP Bomb (Uncompressed > 200MB)' };
                    }

                    // Safe extraction with Zip Slip protection
                    const tempDir = path.dirname(filePath);
                    const extractedFile = safeExtractEntry(zip, apkEntry, tempDir);
                    if (!extractedFile) {
                        totalScore += 90;
                        allDetections.push('Zip Slip attack terdeteksi saat ekstraksi APK');
                        return {
                            status: 'success',
                            riskLevel: 'BAHAYA',
                            score: totalScore,
                            riskPercentage: 100,
                            reason: 'Zip Slip Path Traversal Attack',
                            sha256: fileHash,
                            detections: allDetections
                        };
                    }
                    targetFile = extractedFile;
                    extractedPath = targetFile;
                } else {
                    // ZIP without APK - still run YARA scan
                    const yaraResult = await yaraScan(filePath);
                    totalScore += yaraResult.score;
                    allDetections.push(...yaraResult.detections);

                    let riskZip = totalScore >= 60 ? 'BAHAYA' : (totalScore > 0 ? 'WARNING' : 'AMAN');
                    let riskPercentage = Math.min(Math.round((totalScore / 100) * 100), 100);
                    return {
                        status: 'success',
                        riskLevel: riskZip,
                        reason: 'ZIP Tanpa APK',
                        score: totalScore,
                        riskPercentage,
                        detections: allDetections
                    };
                }
            } catch (e) {
                return { status: 'error', reason: 'ZIP Rusak' };
            }
        }

        // --- Phase 3: YARA Scan ---
        const yaraResult = await yaraScan(targetFile);
        totalScore += yaraResult.score;
        allDetections.push(...yaraResult.detections);

        // --- Phase 4: PDF-Specific Analysis ---
        if (ext === '.pdf') {
            const pdfResult = scanPdfContent(filePath);
            totalScore += pdfResult.score;
            allDetections.push(...pdfResult.detections);
        }

        // --- Phase 4b: Office Macro Analysis ---
        if (OFFICE_EXTENSIONS.includes(ext)) {
            const officeResult = scanOfficeMacro(filePath, ext);
            totalScore += officeResult.score;
            allDetections.push(...officeResult.detections);
        }

        // --- Jika bukan APK, analisis berhenti di sini ---
        if (ext !== '.zip' && ext !== '.rar' && ext !== '.apk') {
            let riskDokumen = 'AMAN';
            if (totalScore >= 60) riskDokumen = 'BAHAYA';
            else if (totalScore > 0) riskDokumen = 'WARNING';

            let riskPercentage = Math.min(Math.round((totalScore / 100) * 100), 100);

            // Auto-cache dangerous documents
            if (fileHash && riskDokumen === 'BAHAYA') {
                addMalwareHash(fileHash, { riskLevel: riskDokumen, reason: `Dokumen berbahaya (${ext})`, fileName: originalName, score: totalScore });
            }

            let reasonStr = 'Analisis YARA Dokumen';
            if (ext === '.pdf') reasonStr = 'Analisis PDF & YARA';
            else if (OFFICE_EXTENSIONS.includes(ext)) reasonStr = 'Analisis Office Macro & YARA';

            return {
                status: 'success',
                riskLevel: riskDokumen,
                score: totalScore,
                riskPercentage: riskPercentage,
                reason: reasonStr,
                appName: '-',
                packageName: '-',
                version: '-',
                sha256: fileHash,
                detections: allDetections
            };
        }

        // --- Phase 5: APK Manifest Analysis ---
        let manifest;
        try {
            const reader = await ApkReader.open(targetFile);
            manifest = await reader.readManifest();
        } catch (e) {
            console.error("[ApkReader Error] Gagal membaca manifest (kemungkinan obfuscated):", e.message);
            totalScore += 40;
            allDetections.push('APK Manifest rusak/obfuscated');

            let riskLevel = totalScore >= 60 ? 'BAHAYA' : (totalScore > 0 ? 'WARNING' : 'AMAN');
            let riskPercentage = Math.min(Math.round((totalScore / 100) * 100), 100);
            return {
                status: 'success',
                riskLevel: riskLevel,
                score: totalScore,
                riskPercentage: riskPercentage,
                reason: 'APK Rusak atau AXML Obfuscated',
                detections: allDetections
            };
        }

        // --- Phase 6: Malware Package Name Check ---
        try {
            const packageName = (manifest.package || "").toLowerCase();
            for (const malwareName of MALWARE_PACKAGE_NAMES) {
                if (packageName.includes(malwareName)) {
                    totalScore += 100;
                    allDetections.push(`Package name mengandung "${malwareName}"`);
                    console.log(`[Package] Known malware package name detected: ${malwareName}`);
                    break;
                }
            }
        } catch (e) { }

        // --- Phase 7: Obfuscation / Dropper Heuristic ---
        const obfResult = checkObfuscationHeuristic(manifest, targetFile);
        totalScore += obfResult.score;
        allDetections.push(...obfResult.detections);

        // --- Phase 8: Device Admin Detection ---
        const deviceAdminResult = checkDeviceAdmin(manifest);
        totalScore += deviceAdminResult.score;
        allDetections.push(...deviceAdminResult.detections);

        // --- Phase 9: Hidden App (No Launcher Icon) ---
        const hiddenAppResult = checkHiddenApp(manifest);
        totalScore += hiddenAppResult.score;
        allDetections.push(...hiddenAppResult.detections);

        // --- Phase 10: Permission Scoring ---
        const permissions = manifest.usesPermissions || [];
        const dangerousPermsFound = [];

        permissions.forEach(p => {
            const permName = typeof p === 'string' ? p : p.name;
            if (DANGEROUS_PERMISSIONS[permName]) {
                const score = DANGEROUS_PERMISSIONS[permName];
                totalScore += score;
                dangerousPermsFound.push(permName.split('.').pop());
            }
        });

        if (dangerousPermsFound.length > 0) {
            allDetections.push(`Permission bahaya: ${dangerousPermsFound.join(', ')}`);
        }

        // --- Combo multiplier: Banyak permission bahaya sekaligus = lebih curiga ---
        if (dangerousPermsFound.length >= 5) {
            const comboBonus = 30;
            totalScore += comboBonus;
            allDetections.push(`Combo: ${dangerousPermsFound.length} permission bahaya sekaligus (+${comboBonus})`);
            console.log(`[Heuristic] Permission combo bonus: ${dangerousPermsFound.length} dangerous permissions`);
        }

        // --- Final Risk Calculation ---
        let riskLevel = 'AMAN';
        if (totalScore >= 60) riskLevel = 'BAHAYA';
        else if (totalScore > 0) riskLevel = 'WARNING';

        let riskPercentage = Math.min(Math.round((totalScore / 100) * 100), 100);

        // Auto-cache dangerous APKs
        if (fileHash && riskLevel === 'BAHAYA') {
            addMalwareHash(fileHash, { riskLevel, reason: `APK Malware (${manifest.package || 'unknown'})`, fileName: originalName, score: totalScore });
        }

        return {
            status: 'success',
            riskLevel: riskLevel,
            score: totalScore,
            riskPercentage: riskPercentage,
            appName: manifest.applicationLabel || 'Unknown',
            packageName: manifest.package || 'Unknown',
            version: manifest.versionName || '1.0',
            sha256: fileHash,
            detections: allDetections
        };

    } catch (error) {
        console.error("[DeepScan Error]", error);
        return { status: 'error', reason: 'Gagal scan' };
    } finally {
        if (extractedPath && fs.existsSync(extractedPath)) {
            try { fs.unlinkSync(extractedPath); } catch (e) { }
        }
    }
}

module.exports = { deepScan, addMalwareHash, computeSHA256 };