const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const app = express();
const upload = multer();

app.post('/decrypt', upload.single('file'), async (req, res) => {
  try {
    const encrypted = req.file.buffer;
    const mediaKeyB64 = req.body.mediaKey;
    const rawMime = req.body.mime || 'audio/ogg';
    
    const mediaKey = Buffer.from(mediaKeyB64, 'base64');
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('WhatsApp Audio Keys', 'utf8');

    const prk = crypto.createHmac('sha256', salt).update(mediaKey).digest();
    let prev = Buffer.alloc(0);
    const out = [];

    for (let i = 1; Buffer.concat(out).length < 112; i++) {
      const h = crypto.createHmac('sha256', prk);
      h.update(prev);
      h.update(info);
      h.update(Buffer.from([i]));
      prev = h.digest();
      out.push(prev);
    }

    const expanded = Buffer.concat(out).slice(0, 112);
    const iv = expanded.slice(0, 16);
    const cipherKey = expanded.slice(16, 48);
    const macKey = expanded.slice(48, 80);

    const macFromFile = encrypted.slice(encrypted.length - 10);
    const cipherBytes = encrypted.slice(0, encrypted.length - 10);

    const calcMac = crypto.createHmac('sha256', macKey)
      .update(Buffer.concat([iv, cipherBytes]))
      .digest()
      .slice(0, 10);

    if (!crypto.timingSafeEqual(macFromFile, calcMac)) {
      throw new Error('MAC inválido: mediaKey não condiz com o arquivo');
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
    const plain = Buffer.concat([decipher.update(cipherBytes), decipher.final()]);

    res.set({
      'Content-Type': rawMime,
      'Content-Disposition': 'attachment; filename="whatsapp.ogg"'
    });

    return res.send(plain);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Decrypt Server Online ✅');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Rodando na porta ${PORT}`));
