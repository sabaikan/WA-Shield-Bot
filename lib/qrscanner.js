/**
 * Advanced QR Code Scanner - Anti-Quishing Module v4
 * 
 * Dioptimasi untuk kasus tersulit:
 * - QR gelap dengan efek listrik/neon
 * - QR bercampur dengan gambar anime berwarna-warni
 * - QR menyatu dengan background putih/gelap
 * 
 * Pendekatan utama:
 * 1. Saturation Filter → Isolasi QR (B/W) dari elemen berwarna (anime/efek)
 * 2. Multi-strategy jsQR scanning (12+ strategi)
 * 3. Sliding Window systematic scan
 * 4. Gemini Vision AI fallback (jika semua gagal)
 */

const { Jimp } = require('jimp');
const jsQR = require('jsqr');

const QZ_PAD = 40;

/**
 * Main scanner — mencoba semua strategi, terakhir AI fallback
 * @param {Buffer} imageBuffer
 * @param {object} [aiModel] - Gemini model untuk fallback (optional)
 * @returns {Promise<string|null>}
 */
async function scanQRCode(imageBuffer, aiModel) {
    const original = await Jimp.read(imageBuffer);

    const MAX_DIM = 1200;
    if (original.width > MAX_DIM || original.height > MAX_DIM) {
        original.scaleToFit({ w: MAX_DIM, h: MAX_DIM });
    }

    let result;

    // ==================== LOCAL DETECTION ====================

    // Phase 1: Quick scans
    result = quickScan(original);
    if (result) return result;

    // Phase 2: SATURATION FILTER — Kunci untuk gambar anime/berwarna!
    // QR code = hitam/putih (low saturation)
    // Anime/efek = berwarna (high saturation)
    // → Buang pixel berwarna, sisakan QR code
    result = saturationFilterScan(original);
    if (result) return result;

    // Phase 3: Dark image recovery
    result = darkImageScan(original);
    if (result) return result;

    // Phase 4: Noise reduction
    result = noiseReductionScan(original);
    if (result) return result;

    // Phase 5: Standard preprocessing
    result = standardScan(original);
    if (result) return result;

    // Phase 6: Per-channel
    result = channelScan(original);
    if (result) return result;

    // Phase 7: Adaptive threshold
    result = adaptiveScan(original);
    if (result) return result;

    // Phase 8: Inverted + edge
    result = invertedAndEdgeScan(original);
    if (result) return result;

    // Phase 9: Combo pipelines
    result = comboScan(original);
    if (result) return result;

    // Phase 10: Multi-scale
    result = multiScaleScan(original);
    if (result) return result;

    // Phase 11: Sliding Window Scan (lebih banyak posisi dari region scan)
    result = await slidingWindowScan(original);
    if (result) return result;

    // Phase 12: Region scan with all preprocessing
    result = await regionScan(original);
    if (result) return result;

    // ==================== AI FALLBACK ====================
    // Phase 13: Gemini Vision (jika model disediakan & semua gagal)
    if (aiModel) {
        result = await geminiVisionScan(imageBuffer, aiModel);
        if (result) return result;
    }

    return null;
}

// ============================================================
//                    SCANNING PHASES
// ============================================================

function quickScan(img) {
    let r = tryDecode(img);
    if (r) return r;
    r = tryWithPadding(img);
    if (r) return r;
    // Quick greyscale
    const grey = img.clone().greyscale().contrast(0.5);
    r = tryDecode(grey);
    if (r) return r;
    return tryWithPadding(grey);
}

/**
 * SATURATION FILTER SCAN
 * QR codes punya saturasi rendah (hitam/putih).
 * Anime art & efek dekorasi punya saturasi tinggi (berwarna).
 * → Buang pixel berwarna → QR code terisolasi
 */
function saturationFilterScan(img) {
    // Berbagai threshold saturasi
    for (const satThreshold of [0.15, 0.25, 0.35, 0.50, 0.65]) {
        // Mode: buang warna, jadikan putih (untuk QR gelap di bg terang)
        const filtered = desaturateColorful(img, satThreshold, 255);
        let r = tryDecode(filtered);
        if (r) return r;
        r = tryWithPadding(filtered);
        if (r) return r;

        // Binarize hasil filter
        for (const thr of [100, 128, 160]) {
            const bin = filtered.clone();
            binarize(bin, thr);
            r = tryDecode(bin);
            if (r) return r;
            r = tryWithPadding(bin);
            if (r) return r;
        }

        // Mode: buang warna, jadikan hitam (untuk QR terang di elemen gelap)
        const filteredBlack = desaturateColorful(img, satThreshold, 0);
        r = tryDecode(filteredBlack);
        if (r) return r;
        r = tryWithPadding(filteredBlack);
        if (r) return r;
    }

    // Saturation + histogram equalize
    for (const satThr of [0.2, 0.4]) {
        const filtered = desaturateColorful(img, satThr, 255);
        const eq = histogramEqualize(filtered);
        let r = tryDecode(eq);
        if (r) return r;
        r = tryWithPadding(eq);
        if (r) return r;
    }

    // Saturation + gamma (untuk gelap)
    for (const gamma of [0.4, 0.6]) {
        const filtered = desaturateColorful(img, 0.3, 255);
        const corrected = gammaCorrect(filtered, gamma);
        let r = tryDecode(corrected);
        if (r) return r;
        r = tryWithPadding(corrected);
        if (r) return r;
    }

    return null;
}

function darkImageScan(img) {
    // Histogram equalization
    const eq = histogramEqualize(img.clone().greyscale());
    let r = tryDecode(eq);
    if (r) return r;
    r = tryWithPadding(eq);
    if (r) return r;

    // Gamma correction
    for (const gamma of [0.3, 0.4, 0.5, 0.6, 0.7, 1.5, 2.0, 2.5]) {
        const corrected = gammaCorrect(img.clone().greyscale(), gamma);
        r = tryDecode(corrected);
        if (r) return r;
        r = tryWithPadding(corrected);
        if (r) return r;
    }

    // Extreme brightness
    for (const bright of [0.3, 0.5, 0.7]) {
        const boosted = img.clone().greyscale().brightness(bright).contrast(0.8);
        r = tryDecode(boosted);
        if (r) return r;
        r = tryWithPadding(boosted);
        if (r) return r;
    }

    return null;
}

function noiseReductionScan(img) {
    for (const radius of [2, 3, 5]) {
        const blurred = boxBlur(img.clone().greyscale(), radius);
        let r = tryDecode(blurred);
        if (r) return r;

        for (const thr of [80, 100, 128, 160, 200]) {
            const bin = blurred.clone();
            binarize(bin, thr);
            r = tryDecode(bin);
            if (r) return r;
            r = tryWithPadding(bin);
            if (r) return r;
        }
    }

    // Blur + equalize
    const be = histogramEqualize(boxBlur(img.clone().greyscale(), 3));
    let r = tryDecode(be);
    if (r) return r;
    r = tryWithPadding(be);
    if (r) return r;

    // Blur + gamma
    for (const gamma of [0.4, 0.6]) {
        const bg = gammaCorrect(boxBlur(img.clone().greyscale(), 3), gamma);
        r = tryDecode(bg);
        if (r) return r;
        const bin = bg.clone();
        binarize(bin, 128);
        r = tryDecode(bin);
        if (r) return r;
        r = tryWithPadding(bin);
        if (r) return r;
    }

    return null;
}

function standardScan(img) {
    for (const c of [0.3, 0.5, 0.7, 0.9]) {
        const grey = img.clone().greyscale().contrast(c);
        let r = tryDecode(grey);
        if (r) return r;
        r = tryWithPadding(grey);
        if (r) return r;
    }
    for (const thr of [80, 100, 128, 160, 200, 220]) {
        const bin = img.clone().greyscale();
        binarize(bin, thr);
        let r = tryDecode(bin);
        if (r) return r;
        r = tryWithPadding(bin);
        if (r) return r;
    }
    return null;
}

function channelScan(img) {
    for (const ch of [0, 1, 2]) {
        const chImg = extractChannel(img, ch);
        let r = tryDecode(chImg);
        if (r) return r;
        const chEq = histogramEqualize(chImg.clone());
        r = tryDecode(chEq);
        if (r) return r;
        const bin = chImg.clone();
        binarize(bin, 128);
        r = tryDecode(bin);
        if (r) return r;
        r = tryWithPadding(bin);
        if (r) return r;
    }
    return null;
}

function adaptiveScan(img) {
    for (const bs of [15, 31, 51]) {
        const a = adaptiveThreshold(img, bs, 10);
        let r = tryDecode(a);
        if (r) return r;
        r = tryWithPadding(a);
        if (r) return r;
    }
    for (const bs of [21, 41]) {
        const eq = histogramEqualize(img.clone().greyscale());
        const a = adaptiveThresholdFromGrey(eq, bs, 8);
        let r = tryDecode(a);
        if (r) return r;
        r = tryWithPadding(a);
        if (r) return r;
    }
    return null;
}

function invertedAndEdgeScan(img) {
    const inv = img.clone().greyscale().invert();
    let r = tryDecode(inv);
    if (r) return r;
    r = tryWithPadding(inv, 0x000000FF);
    if (r) return r;
    const invEq = histogramEqualize(inv.clone());
    r = tryDecode(invEq);
    if (r) return r;

    const edged = edgeEnhance(img);
    r = tryDecode(edged);
    if (r) return r;
    r = tryWithPadding(edged);
    if (r) return r;
    return null;
}

function comboScan(img) {
    for (const blurR of [2, 3, 5]) {
        for (const thr of [100, 128, 160]) {
            const combo = histogramEqualize(boxBlur(img.clone().greyscale(), blurR));
            binarize(combo, thr);
            let r = tryDecode(combo);
            if (r) return r;
            r = tryWithPadding(combo);
            if (r) return r;
        }
    }
    // Saturation filter + blur + binarize combo
    for (const satThr of [0.25, 0.4]) {
        const sat = desaturateColorful(img, satThr, 255);
        const blurred = boxBlur(sat, 3);
        binarize(blurred, 128);
        let r = tryDecode(blurred);
        if (r) return r;
        r = tryWithPadding(blurred);
        if (r) return r;
    }
    return null;
}

function multiScaleScan(img) {
    const factors = [];
    if (img.width < 500 || img.height < 500) factors.push(2, 3);
    factors.push(0.75, 0.5);
    for (const sf of factors) {
        const s = img.clone().scale(sf);
        let r = tryDecode(s);
        if (r) return r;
        r = tryWithPadding(s);
        if (r) return r;
        const sEq = histogramEqualize(s.clone().greyscale());
        r = tryDecode(sEq);
        if (r) return r;
        // Saturation filter on scaled
        const sSat = desaturateColorful(s, 0.3, 255);
        r = tryDecode(sSat);
        if (r) return r;
        r = tryWithPadding(sSat);
        if (r) return r;
    }
    return null;
}

/**
 * Sliding Window Scan
 * Scan gambar dengan window kecil yang bergeser per langkah.
 * Lebih detail dari region scan — cari QR di mana saja.
 */
async function slidingWindowScan(original) {
    const w = original.width;
    const h = original.height;
    if (w < 150 || h < 150) return null;

    // Window sizes: 40%, 50%, 60%, 70% dari ukuran gambar
    const windowRatios = [0.4, 0.5, 0.6, 0.7];
    const stepRatio = 0.15; // 15% step

    for (const ratio of windowRatios) {
        const winW = Math.floor(w * ratio);
        const winH = Math.floor(h * ratio);
        const stepX = Math.floor(w * stepRatio);
        const stepY = Math.floor(h * stepRatio);

        if (winW < 100 || winH < 100) continue;

        for (let y = 0; y <= h - winH; y += stepY) {
            for (let x = 0; x <= w - winW; x += stepX) {
                try {
                    const cropped = original.clone().crop({ x, y, w: winW, h: winH });

                    // Quick pipeline per window
                    let r = tryDecode(cropped);
                    if (r) return r;
                    r = tryWithPadding(cropped);
                    if (r) return r;

                    // Greyscale + contrast
                    const grey = cropped.clone().greyscale().contrast(0.6);
                    r = tryDecode(grey);
                    if (r) return r;

                    // Saturation filter
                    const sat = desaturateColorful(cropped, 0.3, 255);
                    r = tryDecode(sat);
                    if (r) return r;
                    r = tryWithPadding(sat);
                    if (r) return r;

                    // Equalize
                    const eq = histogramEqualize(cropped.clone().greyscale());
                    r = tryDecode(eq);
                    if (r) return r;

                    // Binarize
                    const bin = cropped.clone().greyscale();
                    binarize(bin, 128);
                    r = tryWithPadding(bin);
                    if (r) return r;
                } catch (e) { }
            }
        }
    }
    return null;
}

async function regionScan(original) {
    const w = original.width;
    const h = original.height;
    if (w < 200 || h < 200) return null;

    const regions = [];
    const stepX = Math.floor(w / 3);
    const stepY = Math.floor(h / 3);
    for (let row = 0; row < 3; row++) {
        for (let col = 0; col < 3; col++) {
            regions.push({
                x: col * stepX, y: row * stepY,
                w: Math.min(stepX + 20, w - col * stepX),
                h: Math.min(stepY + 20, h - row * stepY)
            });
        }
    }
    // Center 60%
    regions.push({
        x: Math.floor(w * 0.2), y: Math.floor(h * 0.2),
        w: Math.floor(w * 0.6), h: Math.floor(h * 0.6)
    });

    for (const reg of regions) {
        const rx = Math.max(0, reg.x);
        const ry = Math.max(0, reg.y);
        const rw = Math.min(reg.w, w - rx);
        const rh = Math.min(reg.h, h - ry);
        if (rw < 80 || rh < 80) continue;

        try {
            const cropped = original.clone().crop({ x: rx, y: ry, w: rw, h: rh });
            const variants = [
                cropped,
                cropped.clone().greyscale().contrast(0.6),
                histogramEqualize(cropped.clone().greyscale()),
                desaturateColorful(cropped, 0.3, 255),
                gammaCorrect(cropped.clone().greyscale(), 0.5),
            ];
            const bb = boxBlur(cropped.clone().greyscale(), 2);
            binarize(bb, 128);
            variants.push(bb);

            for (const v of variants) {
                let r = tryDecode(v);
                if (r) return r;
                r = tryWithPadding(v);
                if (r) return r;
            }
        } catch (e) { }
    }
    return null;
}

// ============================================================
//                    GEMINI VISION AI FALLBACK
// ============================================================

/**
 * Gunakan Gemini Vision utk baca QR code dari gambar
 * Paling akurat untuk gambar sangat kompleks (anime, efek, dll)
 */
async function geminiVisionScan(imageBuffer, aiModel) {
    try {
        console.log('[Anti-Quishing] Menggunakan AI Vision untuk deteksi QR...');

        const base64Image = imageBuffer.toString('base64');
        const prompt = `Analyze this image carefully. Is there a QR code in this image?
If YES, decode the QR code and respond ONLY with the exact URL or data contained in the QR code, nothing else.
If NO QR code is found, respond with exactly: NO_QR_FOUND
Do not add any explanation, formatting, or extra text. Just the raw URL/data or NO_QR_FOUND.`;

        const result = await aiModel.generateContent([
            { text: prompt },
            {
                inlineData: {
                    mimeType: 'image/jpeg',
                    data: base64Image
                }
            }
        ]);

        const response = result.response.text().trim();
        console.log('[Anti-Quishing] AI Vision response:', response);

        if (response && response !== 'NO_QR_FOUND' && !response.includes('NO_QR')) {
            // Bersihkan response — extract URL jika ada
            const urlMatch = response.match(/(https?:\/\/[^\s"'<>]+)/);
            if (urlMatch) {
                return urlMatch[1];
            }
            // Kalau bukan URL tapi ada data
            if (response.length > 3 && response.length < 2000) {
                return response;
            }
        }
    } catch (e) {
        console.error('[Anti-Quishing] AI Vision error:', e.message);
    }
    return null;
}

// ============================================================
//                    CORE FUNCTIONS
// ============================================================

function tryDecode(image) {
    try {
        const code = jsQR(
            new Uint8ClampedArray(image.bitmap.data),
            image.bitmap.width,
            image.bitmap.height
        );
        if (code && code.data && code.data.trim().length > 0) {
            return code.data;
        }
    } catch (e) { }
    return null;
}

function tryWithPadding(image, bgColor = 0xFFFFFFFF) {
    const padded = addBorder(image, QZ_PAD, bgColor);
    return tryDecode(padded);
}

function addBorder(image, padding, bgColor) {
    const newW = image.width + padding * 2;
    const newH = image.height + padding * 2;
    const padded = new Jimp({ width: newW, height: newH, color: bgColor });
    padded.composite(image, padding, padding);
    return padded;
}

// ============================================================
//                    IMAGE PROCESSING
// ============================================================

function binarize(image, threshold) {
    const d = image.bitmap.data;
    for (let i = 0; i < d.length; i += 4) {
        const v = d[i] >= threshold ? 255 : 0;
        d[i] = v; d[i + 1] = v; d[i + 2] = v;
    }
}

function extractChannel(image, channel) {
    const img = image.clone();
    const d = img.bitmap.data;
    for (let i = 0; i < d.length; i += 4) {
        const v = d[i + channel];
        d[i] = v; d[i + 1] = v; d[i + 2] = v;
    }
    return img;
}

/**
 * DESATURATE COLORFUL PIXELS
 * Kunci untuk gambar dengan anime / efek berwarna-warni!
 * 
 * Cara kerja:
 * 1. Hitung saturasi setiap pixel (dari HSL)
 * 2. Jika saturasi > threshold → ganti dengan replaceValue (putih/hitam)
 * 3. Pixel low-saturation (hitam/putih/abu = QR) tetap utuh
 * 
 * Hasilnya: QR code terisolasi, elemen berwarna dihapus
 */
function desaturateColorful(image, satThreshold, replaceValue) {
    const img = image.clone();
    const d = img.bitmap.data;
    for (let i = 0; i < d.length; i += 4) {
        const r = d[i] / 255;
        const g = d[i + 1] / 255;
        const b = d[i + 2] / 255;
        const max = Math.max(r, g, b);
        const min = Math.min(r, g, b);
        const l = (max + min) / 2;
        let s = 0;
        if (max !== min) {
            s = l > 0.5
                ? (max - min) / (2 - max - min)
                : (max - min) / (max + min);
        }
        if (s > satThreshold) {
            d[i] = replaceValue;
            d[i + 1] = replaceValue;
            d[i + 2] = replaceValue;
        } else {
            // Convert remaining to greyscale
            const grey = Math.round((d[i] * 0.299 + d[i + 1] * 0.587 + d[i + 2] * 0.114));
            d[i] = grey; d[i + 1] = grey; d[i + 2] = grey;
        }
    }
    return img;
}

function histogramEqualize(image) {
    const d = image.bitmap.data;
    const hist = new Array(256).fill(0);
    const total = image.width * image.height;
    for (let i = 0; i < d.length; i += 4) hist[d[i]]++;
    const cdf = new Array(256);
    cdf[0] = hist[0];
    for (let i = 1; i < 256; i++) cdf[i] = cdf[i - 1] + hist[i];
    let cdfMin = 0;
    for (let i = 0; i < 256; i++) { if (cdf[i] > 0) { cdfMin = cdf[i]; break; } }
    const map = new Array(256);
    for (let i = 0; i < 256; i++) {
        map[i] = Math.max(0, Math.min(255, Math.round(((cdf[i] - cdfMin) / (total - cdfMin)) * 255)));
    }
    for (let i = 0; i < d.length; i += 4) {
        const v = map[d[i]]; d[i] = v; d[i + 1] = v; d[i + 2] = v;
    }
    return image;
}

function gammaCorrect(image, gamma) {
    const d = image.bitmap.data;
    const lut = new Uint8Array(256);
    for (let i = 0; i < 256; i++) lut[i] = Math.round(255 * Math.pow(i / 255, gamma));
    for (let i = 0; i < d.length; i += 4) {
        d[i] = lut[d[i]]; d[i + 1] = lut[d[i + 1]]; d[i + 2] = lut[d[i + 2]];
    }
    return image;
}

function boxBlur(image, radius) {
    const w = image.width, h = image.height;
    const src = new Uint8Array(image.bitmap.data);
    const d = image.bitmap.data;
    const size = radius * 2 + 1, area = size * size;
    for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
            let s = 0;
            for (let dy = -radius; dy <= radius; dy++) {
                for (let dx = -radius; dx <= radius; dx++) {
                    const nx = Math.max(0, Math.min(w - 1, x + dx));
                    const ny = Math.max(0, Math.min(h - 1, y + dy));
                    s += src[(ny * w + nx) * 4];
                }
            }
            const idx = (y * w + x) * 4;
            const v = Math.round(s / area);
            d[idx] = v; d[idx + 1] = v; d[idx + 2] = v;
        }
    }
    return image;
}

function adaptiveThreshold(image, blockSize, C) {
    return adaptiveThresholdFromGrey(image.clone().greyscale(), blockSize, C);
}

function adaptiveThresholdFromGrey(src, blockSize, C) {
    const out = src.clone();
    const w = src.bitmap.width, h = src.bitmap.height;
    const sd = src.bitmap.data, od = out.bitmap.data;
    const half = Math.floor(blockSize / 2);
    const integral = new Float64Array((w + 1) * (h + 1));
    for (let y = 0; y < h; y++) {
        let rs = 0;
        for (let x = 0; x < w; x++) {
            rs += sd[(y * w + x) * 4];
            integral[(y + 1) * (w + 1) + (x + 1)] = rs + integral[y * (w + 1) + (x + 1)];
        }
    }
    for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
            const x1 = Math.max(0, x - half), y1 = Math.max(0, y - half);
            const x2 = Math.min(w - 1, x + half), y2 = Math.min(h - 1, y + half);
            const cnt = (x2 - x1 + 1) * (y2 - y1 + 1);
            const sum = integral[(y2 + 1) * (w + 1) + (x2 + 1)]
                - integral[y1 * (w + 1) + (x2 + 1)]
                - integral[(y2 + 1) * (w + 1) + x1]
                + integral[y1 * (w + 1) + x1];
            const idx = (y * w + x) * 4;
            const v = sd[idx] > (sum / cnt - C) ? 255 : 0;
            od[idx] = v; od[idx + 1] = v; od[idx + 2] = v;
        }
    }
    return out;
}

function edgeEnhance(image) {
    const img = image.clone().greyscale();
    const w = img.bitmap.width, h = img.bitmap.height;
    const src = new Uint8Array(img.bitmap.data);
    const d = img.bitmap.data;
    for (let y = 1; y < h - 1; y++) {
        for (let x = 1; x < w - 1; x++) {
            const idx = (y * w + x) * 4;
            const v = Math.max(0, Math.min(255,
                src[idx] * 5
                - src[((y - 1) * w + x) * 4]
                - src[((y + 1) * w + x) * 4]
                - src[(y * w + x - 1) * 4]
                - src[(y * w + x + 1) * 4]
            ));
            d[idx] = v; d[idx + 1] = v; d[idx + 2] = v;
        }
    }
    return img;
}

module.exports = { scanQRCode };
