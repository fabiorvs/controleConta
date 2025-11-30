require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Configurar diretório do banco de dados
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "financeiro.db");

// Inicializar SQLite
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL"); // Melhor performance

// Criar tabelas
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL,
    initial_balance REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
    amount REAL NOT NULL,
    comment TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date);
`);

// Middleware de autenticação
const auth = (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new Error();

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "secret-key-123"
    );
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: "Não autenticado" });
  }
};

// Rotas
app.post("/api/register", async (req, res) => {
  try {
    const { password, initialBalance } = req.body;

    if (!password || password.length < 4) {
      return res
        .status(400)
        .json({ error: "Senha deve ter pelo menos 4 caracteres" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare(
      "INSERT INTO users (password, initial_balance) VALUES (?, ?)"
    );
    const result = stmt.run(hashedPassword, initialBalance || 0);

    const token = jwt.sign(
      { userId: result.lastInsertRowid },
      process.env.JWT_SECRET || "secret-key-123"
    );

    res.status(201).json({ token, userId: result.lastInsertRowid });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar conta" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { password } = req.body;

    const stmt = db.prepare("SELECT * FROM users LIMIT 1");
    const user = stmt.get();

    if (!user) {
      return res
        .status(404)
        .json({ error: "Nenhuma conta encontrada. Crie uma conta primeiro." });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Senha incorreta" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || "secret-key-123"
    );
    res.json({ token, userId: user.id });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro no login" });
  }
});

app.get("/api/user", auth, (req, res) => {
  try {
    const stmt = db.prepare(
      "SELECT id, initial_balance, created_at FROM users WHERE id = ?"
    );
    const user = stmt.get(req.userId);

    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    res.json({
      _id: user.id,
      initialBalance: user.initial_balance,
      createdAt: user.created_at,
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao buscar usuário" });
  }
});

app.put("/api/user/balance", auth, (req, res) => {
  try {
    const { initialBalance } = req.body;

    const stmt = db.prepare(
      "UPDATE users SET initial_balance = ? WHERE id = ?"
    );
    stmt.run(initialBalance, req.userId);

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao atualizar saldo" });
  }
});

app.get("/api/transactions", auth, (req, res) => {
  try {
    const stmt = db.prepare(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC"
    );
    const transactions = stmt.all(req.userId);

    // Formatar para compatibilidade com frontend
    const formatted = transactions.map((t) => ({
      _id: t.id,
      type: t.type,
      amount: t.amount,
      comment: t.comment,
      date: t.date,
    }));

    res.json(formatted);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao buscar transações" });
  }
});

app.post("/api/transactions", auth, (req, res) => {
  try {
    const { type, amount, comment } = req.body;

    if (!type || !amount || !["income", "expense"].includes(type)) {
      return res.status(400).json({ error: "Dados inválidos" });
    }

    const stmt = db.prepare(
      "INSERT INTO transactions (user_id, type, amount, comment) VALUES (?, ?, ?, ?)"
    );
    const result = stmt.run(req.userId, type, amount, comment || null);

    const transaction = {
      _id: result.lastInsertRowid,
      type,
      amount,
      comment,
      date: new Date().toISOString(),
    };

    res.status(201).json(transaction);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar transação" });
  }
});

app.delete("/api/transactions/:id", auth, (req, res) => {
  try {
    const stmt = db.prepare(
      "DELETE FROM transactions WHERE id = ? AND user_id = ?"
    );
    stmt.run(req.params.id, req.userId);

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao deletar transação" });
  }
});

// Backup endpoint (opcional)
app.get("/api/backup", auth, (req, res) => {
  try {
    res.download(DB_PATH, "backup.db");
  } catch (error) {
    res.status(400).json({ error: "Erro ao fazer backup" });
  }
});

// Graceful shutdown
process.on("SIGINT", () => {
  db.close();
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
  console.log(`📁 Banco de dados em: ${DB_PATH}`);
});
