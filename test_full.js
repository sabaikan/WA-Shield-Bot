const { analyzeLink } = require('./lib/link');
const { cekLink } = require('./lib/virustotal');

async function testFull() {
    console.log("Starting testFull...");
    try {
        const targetUrl = "https://bafamilinga.netlify.app/?gad_source=1&gad_campaignid=23578";
        const textBody = "";

        console.log(`Cek Link: ${targetUrl}`);
        const localResult = await analyzeLink(targetUrl, textBody);
        console.log("localResult:", localResult);

        let vtResult = { found: false };
        if (!localResult.trusted) {
            const urlForVT = localResult.finalUrl || targetUrl;
            try { vtResult = await cekLink(urlForVT); } catch (e) { console.error("VT Error:", e); }
        }

        console.log("vtResult:", vtResult);

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

        console.log("Final Score:", finalScore);

        let finalRiskPercentage = Math.min(Math.round((finalScore / 100) * 100), 100);
        console.log("Percent:", finalRiskPercentage);

        if (localResult && localResult.forensicNotes && localResult.forensicNotes.length > 0) {
            const notes = localResult.forensicNotes.map(note => `- ${note}`).join('\n');
            console.log("Notes length:", notes.length);
        }

        console.log("Test finished successfully.");

    } catch (e) {
        console.error("Test Error:", e);
    }
}
testFull();
