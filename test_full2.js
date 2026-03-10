const fs = require('fs');
const { analyzeLink } = require('./lib/link');
const { cekLink } = require('./lib/virustotal');

async function testFull() {
    let logStr = "Starting testFull...\n";
    try {
        const targetUrl = "https://bafamilinga.netlify.app/?gad_source=1&gad_campaignid=23578";
        const textBody = "";

        logStr += `Cek Link: ${targetUrl}\n`;
        const localResult = await analyzeLink(targetUrl, textBody);
        logStr += "localResult: " + JSON.stringify(localResult, null, 2) + "\n";

        let vtResult = { found: false };
        if (!localResult.trusted) {
            const urlForVT = localResult.finalUrl || targetUrl;
            try { vtResult = await cekLink(urlForVT); } catch (e) { logStr += "VT Error: " + e.message + "\n"; }
        }

        logStr += "vtResult: " + JSON.stringify(vtResult, null, 2) + "\n";

        let isDangerous = false;
        let finalScore = localResult ? localResult.score : 0;

        if (vtResult.found) {
            const vtLinkStats = vtResult.data;
            const bahaya = (vtLinkStats.malicious || 0) + (vtLinkStats.suspicious || 0);
            finalScore += (bahaya * 60);
        }

        if (finalScore >= 50) {
            isDangerous = true;
        }

        logStr += "Final Score: " + finalScore + "\n";

        let finalRiskPercentage = Math.min(Math.round((finalScore / 100) * 100), 100);
        logStr += "Percent: " + finalRiskPercentage + "\n";

        if (localResult && localResult.forensicNotes && localResult.forensicNotes.length > 0) {
            const notes = localResult.forensicNotes.map(note => `- ${note}`).join('\n');
            logStr += "Notes length: " + notes.length + "\n";
        }

        logStr += "Test finished successfully.\n";

    } catch (e) {
        logStr += "Test Error: " + e.stack + "\n";
    }
    fs.writeFileSync('test_full_clean.txt', logStr, 'utf8');
}
testFull();
