const truecallerjs = require('truecallerjs');

async function cariNomor(nomor) {
    try {
        let cleanNumber = nomor.replace(/[^0-9]/g, '');

        if (cleanNumber.startsWith('08')) {
            cleanNumber = '62' + cleanNumber.slice(1);
        } else if (cleanNumber.startsWith('62')) {
        } else {
            cleanNumber = '62' + cleanNumber;
        }

        const searchData = {
            number: cleanNumber,
            countryCode: 'ID',
            installationId: '',
            output: 'JSON'
        }

        const response = await truecallerjs.search(searchData);

        const data = typeof response === 'string' ? JSON.parse(response) : response;

        if (data.data && data.data[0]) {
            return {
                found: true,
                name: data.data[0].name || "Tidak ada nama",
                carrier: data.data[0].phones[0].carrier || "Tidak diketahui",
                email: data.data[0].internetAddresses[0]?.id || "Tidak ada",
                spamScore: data.data[0].spamScore || 0,
                provider: "Truecaller"
            };
        } else {
            return { found: false };
        }

    } catch (error) {
        return { found: false, error: error.message };
    }
}

module.exports = { cariNomor };