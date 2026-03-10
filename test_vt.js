const { cekLink } = require('./lib/virustotal');

async function test() {
    console.log("Starting test...");
    try {
        const result = await cekLink("https://bafamilinga.netlify.app/?gad_source=1&gad_campaignid=23578");
        console.log("Result:", result);
    } catch (e) {
        console.error("Caught error:", e);
    }
}
test();
