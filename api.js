import express from 'express';
import cors from 'cors';
import xlsx from 'xlsx';
import dotenv from 'dotenv';
import fs from 'fs';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

dotenv.config();
const app = express();
const PORT = 5000;
const EXCEL_FILE = 'data/Products.xlsx';
const UPLOAD_DIR = 'uploads';
const _SECRET_KEY = 'Gh@$$@anSlaiman';

app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, file.originalname),
});

const upload = multer({ storage });

const readExcel = () => {
  if (!fs.existsSync(EXCEL_FILE)) return [];
  const workbook = xlsx.readFile(EXCEL_FILE);
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  return xlsx.utils.sheet_to_json(sheet);
};

const writeExcel = (data) => {
  const workSheet = xlsx.utils.json_to_sheet(data);
  const workBook = xlsx.utils.book_new();
  xlsx.utils.book_append_sheet(workBook, workSheet, 'Products');
  xlsx.writeFile(workBook, EXCEL_FILE);
};

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).json('No token provided!!!');
  jwt.verify(token, _SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'UnAuthorized' });
    req.user = decoded;
    next();
  });
};

const users = [];

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  if (users.some(user => user.username === username)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPwd = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPwd });

  res.status(201).json({ message: 'User Registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Check if username and password are provided
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  // Find user by username
  const user = users.find(x => x.username === username);

  if (!user) {
    console.log(`Login attempt failed: User ${username} not found.`);
    return res.status(401).json({ message: 'User not found' });
  }

  // Check if the password matches
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    console.log(`Login attempt failed: Invalid credentials for user ${username}.`);
    return res.status(401).json({ message: 'Invalid Credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ username }, _SECRET_KEY, { expiresIn: '1h' });

  // Respond with the token
  res.json({ token });
});


app.get('/products', (req, res) => {
  const products = readExcel();
  const productsWithImageUrls = products.map(product => ({
    ...product,
    imageUrl: `/uploads/${product.image}`,
  }));

  res.json(productsWithImageUrls);
});

app.post('/products', authenticate, (req, res) => {
  const products = readExcel();
  const newProduct = { id: products.length + 1, ...req.body };
  products.push(newProduct);
  writeExcel(products);
  res.json(newProduct);
});

app.put('/products/:id', authenticate, (req, res) => {
  let products = readExcel();
  products = products.map(p => (p.id == req.params.id ? { ...p, ...req.body } : p));
  writeExcel(products);
  res.json({ message: 'Product updated' });
});

app.patch('/products/:id/deactivate', authenticate, (req, res) => {
  let products = readExcel();
  products = products.map(p => (p.id == req.params.id ? { ...p, active: false } : p));
  writeExcel(products);
  res.json({ message: 'Product deactivated' });
});

app.post('/upload', authenticate, upload.single('file'), (req, res) => {
  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ message: 'File uploaded', imageUrl });
});

app.get('/download/:filename', authenticate, (req, res) => {
  const filepath = path.join(UPLOAD_DIR, req.params.filename);
  if (fs.existsSync(filepath)) res.download(filepath);
  else res.status(404).json({ message: 'File not found' });
});

app.get('/test-read-excel', (req, res) => {
  const data = readExcel();
  res.json(data);
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

app.use('/uploads', express.static(path.join(__dirname, UPLOAD_DIR)));

app.listen(PORT, () => {
  console.log('API is running');
});
