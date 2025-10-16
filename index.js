const express = require('express');
const multer = require('multer');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const upload = multer();

app.use(bodyParser.json());

// Função HDKF expandida
function expandHKDF(mediaKey, salt, info, length) {
  const prk = crypto.createHmac('sha256', salt).update(mediaKey).digest();
  const buffers = [];
  let prev = Buffer.alloc(0);
  let i = 0;
  while (Buffer.concat(buffers).length < length) {
    i++;
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    buffers.push(prev);
  }
  return Buffer.concat(buffers).slice(0, length);
}

app.post('/decifrar', upload.single('file'), (req, res) => {
  try {
    const mediaKeyBase64 = req.body.mediaKey;
    const encryptedAudio = req.file?.buffer;

    if (!mediaKeyBase64 || !encryptedAudio) {
      return res.status(400).json({ error: 'Faltando mediaKey ou file' });
    }

    const mediaKey = Buffer.from(mediaKeyBase64, 'base64');
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('WhatsApp Audio Keys', 'utf-8');

    const expandedKey = expandHKDF(mediaKey, salt, info, 112);
    const iv = expandedKey.slice(0, 16);
    const cipherKey = expandedKey.slice(16, 48);
    const macKey = expandedKey.slice(48, 80);

    const fileMac = encryptedAudio.slice(encryptedAudio.length - 10);
    const fileCipher = encryptedAudio.slice(0, encryptedAudio.length - 10);

    const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
    const decrypted = Buffer.concat([
      decipher.update(fileCipher),
      decipher.final(),
    ]);

    res.set('Content-Type', 'audio/ogg');
    return res.send(decrypted);
  } catch (err) {
    console.error('Erro ao decifrar:', err);
    return res.status(500).json({ error: 'Falha ao decifrar' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor decifrador rodando na porta ${PORT}`);
});
