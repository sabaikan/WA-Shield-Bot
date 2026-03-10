require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
axios.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${process.env.GEMINI_API_KEY}`)
    .then(res => {
        let out = '';
        res.data.models.forEach(m => out += m.name + '\n');
        fs.writeFileSync('out_utf8.txt', out, 'utf-8');
    })
    .catch(err => fs.writeFileSync('out_utf8.txt', err.message, 'utf-8'));
