const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const port = 3000;

const API_KEY = '1234567890abcdef';
const ENCRYPTION_KEY = crypto.randomBytes(32); // Chave de 256 bits
const IV_LENGTH = 16; // Comprimento do vetor de inicialização

app.use(express.json());
app.use(cors());

// Middleware de autenticação da chave de API
const authenticateAPIKey = (req, res, next) => {
  const apiKey = req.header('x-api-key');

  if (!apiKey) {
    return res.status(401).json({ message: 'Chave de API ausente.' });
  }

  if (apiKey !== API_KEY) {
    return res.status(403).json({ message: 'Chave de API inválida.' });
  }

  next();
};

// Aplicando o middleware de autenticação
app.use(authenticateAPIKey);

// Função para criptografar uma mensagem
const encryptMessage = (message) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
};

// Função para descriptografar uma mensagem
const decryptMessage = (encryptedMessage) => {
  const [ivHex, encrypted] = encryptedMessage.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Endpoint para criptografar uma mensagem
app.post('/encrypt', (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ message: 'Mensagem ausente.' });
  }
  const encryptedMessage = encryptMessage(message);
  res.status(200).json({ encryptedMessage });
});

// Endpoint para descriptografar uma mensagem
app.post('/decrypt', (req, res) => {
  const { encryptedMessage } = req.body;
  if (!encryptedMessage) {
    return res.status(400).json({ message: 'Mensagem criptografada ausente.' });
  }
  try {
    const decryptedMessage = decryptMessage(encryptedMessage);
    res.status(200).json({ decryptedMessage });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao descriptografar a mensagem.' });
  }
});

// Outros endpoints já existentes
app.get('/items', (req, res) => {
  try {
    const items = [
      { id: 1, nome: 'Item 1' },
      { id: 2, nome: 'Item 2' },
      { id: 3, nome: 'Item 3' }
    ];
    res.status(200).json(items);
  } catch (error) {
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/items', (req, res) => {
  try {
    const newItem = req.body;
    res.status(201).json(newItem);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar item' });
  }
});

// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
