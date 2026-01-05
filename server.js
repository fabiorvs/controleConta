require("dotenv").config();
const express = require("express");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "financeiro.db");
const BACKUP_DIR = path.join(DATA_DIR, "backups");

const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || crypto.randomBytes(32).toString("hex");

let db;

// Criar diretórios necessários
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// Inicializar sql.js
async function initDb() {
  const SQL = await initSqlJs();

  try {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } catch {
    db = new SQL.Database();

    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        initial_balance REAL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
        amount REAL NOT NULL,
        comment TEXT,
        category TEXT,
        source TEXT NOT NULL DEFAULT 'account' CHECK(source IN ('account', 'credit')),
        date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
      CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
    `);

    saveDb();
  }
}

// Salvar banco
function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, data);
}

// Backup automático
function createBackup() {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = path.join(BACKUP_DIR, `backup-${timestamp}.db`);
    fs.copyFileSync(DB_PATH, backupPath);

    const backups = fs
      .readdirSync(BACKUP_DIR)
      .filter((f) => f.startsWith("backup-"))
      .sort()
      .reverse();

    if (backups.length > 10) {
      backups.slice(10).forEach((f) => fs.unlinkSync(path.join(BACKUP_DIR, f)));
    }

    console.log(`✅ Backup criado: ${backupPath}`);
  } catch (error) {
    console.error("❌ Erro ao criar backup:", error);
  }
}

setInterval(createBackup, 6 * 60 * 60 * 1000);

// Auth middleware
const auth = (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new Error();

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido ou expirado" });
  }
};

// Limpar refresh tokens expirados
function cleanExpiredTokens() {
  try {
    const now = new Date().toISOString();
    db.run("DELETE FROM refresh_tokens WHERE expires_at < ?", [now]);
    saveDb();
  } catch (error) {
    console.error("Erro ao limpar tokens:", error);
  }
}
setInterval(cleanExpiredTokens, 24 * 60 * 60 * 1000);

// Helpers
function rowToTransaction(row) {
  // schema:
  // 0 id, 1 user_id, 2 type, 3 amount, 4 comment, 5 category, 6 source, 7 date
  return {
    _id: row[0],
    type: row[2],
    amount: Number(row[3]) || 0,
    comment: row[4],
    category: row[5],
    source: row[6] || "account",
    dateISO: row[7], // string sqlite
  };
}

// ROTAS

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, initialBalance } = req.body;

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Preencha todos os campos obrigatórios" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Senha deve ter pelo menos 6 caracteres" });
    }

    const existingUser = db.exec(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ error: "Usuário ou email já cadastrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    db.run(
      "INSERT INTO users (username, email, password, initial_balance) VALUES (?, ?, ?, ?)",
      [username, email, hashedPassword, Number(initialBalance) || 0]
    );

    const result = db.exec("SELECT last_insert_rowid() as id")[0];
    const userId = result.values[0][0];

    saveDb();
    createBackup();

    const token = jwt.sign({ userId, username }, JWT_SECRET, {
      expiresIn: "1h",
    });
    const refreshToken = jwt.sign({ userId, username }, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();
    db.run(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [userId, refreshToken, expiresAt]
    );
    saveDb();

    res.status(201).json({ token, refreshToken, userId, username });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar conta" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Preencha usuário e senha" });
    }

    const result = db.exec(
      "SELECT id, username, email, password FROM users WHERE username = ? OR email = ?",
      [username, username]
    );

    if (!result.length) {
      return res.status(401).json({ error: "Usuário ou senha incorretos" });
    }

    const user = {
      id: result[0].values[0][0],
      username: result[0].values[0][1],
      email: result[0].values[0][2],
      password: result[0].values[0][3],
    };

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(401).json({ error: "Usuário ou senha incorretos" });

    db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [
      user.id,
    ]);
    saveDb();

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();
    db.run(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [user.id, refreshToken, expiresAt]
    );
    saveDb();

    res.json({ token, refreshToken, userId: user.id, username: user.username });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro no login" });
  }
});

// Refresh
app.post("/api/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: "Refresh token não fornecido" });

    const result = db.exec(
      "SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?",
      [refreshToken]
    );

    if (!result.length)
      return res.status(401).json({ error: "Refresh token inválido" });

    const expiresAt = result[0].values[0][1];
    if (new Date(expiresAt) < new Date()) {
      return res.status(401).json({ error: "Refresh token expirado" });
    }

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const newToken = jwt.sign(
      { userId: decoded.userId, username: decoded.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token: newToken });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: "Refresh token inválido" });
  }
});

// Logout
app.post("/api/logout", auth, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      db.run("DELETE FROM refresh_tokens WHERE token = ?", [refreshToken]);
      saveDb();
    }
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "Erro ao fazer logout" });
  }
});

// User
app.get("/api/user", auth, (req, res) => {
  try {
    const result = db.exec(
      "SELECT id, username, email, initial_balance, created_at, last_login FROM users WHERE id = ?",
      [req.userId]
    );
    if (!result.length)
      return res.status(404).json({ error: "Usuário não encontrado" });

    const user = {
      _id: result[0].values[0][0],
      username: result[0].values[0][1],
      email: result[0].values[0][2],
      initialBalance: result[0].values[0][3],
      createdAt: result[0].values[0][4],
      lastLogin: result[0].values[0][5],
    };

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao buscar usuário" });
  }
});

// Dashboard (corrigido: índices + objetos)
app.get("/api/dashboard", auth, (req, res) => {
  try {
    const userResult = db.exec(
      "SELECT initial_balance FROM users WHERE id = ?",
      [req.userId]
    );
    const initialBalance = Number(userResult[0]?.values[0][0] || 0);

    const result = db.exec(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC",
      [req.userId]
    );

    const rows = result[0]?.values || [];
    const transactions = rows.map(rowToTransaction);

    // separar por source
    const accountTransactions = transactions.filter(
      (t) => t.source === "account"
    );
    const creditTransactions = transactions.filter(
      (t) => t.source === "credit"
    );

    const accountBalance = accountTransactions.reduce((acc, t) => {
      return t.type === "income" ? acc + t.amount : acc - t.amount;
    }, initialBalance);

    // gastos no cartão este mês
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);

    const creditExpensesThisMonth = creditTransactions
      .filter((t) => t.type === "expense" && new Date(t.dateISO) >= firstDay)
      .reduce((acc, t) => acc + t.amount, 0);

    // total cartão (fatura estimada)
    const creditTotal = creditTransactions.reduce((acc, t) => {
      return t.type === "expense" ? acc + t.amount : acc - t.amount;
    }, 0);

    res.json({
      accountBalance,
      creditExpensesThisMonth,
      creditTotal,
      totalTransactions: transactions.length,
      accountTransactions: accountTransactions.length,
      creditTransactions: creditTransactions.length,
      transactions,
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(400).json({ error: "Erro ao carregar dashboard" });
  }
});

// Atualizar saldo inicial
app.put("/api/user/balance", auth, (req, res) => {
  try {
    const { initialBalance } = req.body;
    db.run("UPDATE users SET initial_balance = ? WHERE id = ?", [
      Number(initialBalance) || 0,
      req.userId,
    ]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao atualizar saldo" });
  }
});

// Buscar transações (corrigido: date/source)
app.get("/api/transactions", auth, (req, res) => {
  try {
    const result = db.exec(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC",
      [req.userId]
    );

    const rows = result[0]?.values || [];
    const transactions = rows.map(rowToTransaction);
    res.json(transactions);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao buscar transações" });
  }
});

// Criar transação
app.post("/api/transactions", auth, (req, res) => {
  try {
    const { type, amount, comment, category, source = "account" } = req.body;

    const amt = Number(amount);
    if (
      !type ||
      !Number.isFinite(amt) ||
      !["income", "expense"].includes(type) ||
      !["account", "credit"].includes(source)
    ) {
      return res.status(400).json({ error: "Dados inválidos" });
    }

    db.run(
      "INSERT INTO transactions (user_id, type, amount, comment, category, source) VALUES (?, ?, ?, ?, ?, ?)",
      [req.userId, type, amt, comment || null, category || null, source]
    );

    const result = db.exec("SELECT last_insert_rowid() as id")[0];
    const id = result.values[0][0];

    saveDb();

    res.status(201).json({
      _id: id,
      type,
      amount: amt,
      comment: comment || null,
      category: category || null,
      source,
      dateISO: new Date().toISOString(),
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar transação" });
  }
});

// EDITAR transação (ADICIONADO)
app.put("/api/transactions/:id", auth, (req, res) => {
  try {
    const { type, amount, comment, category, source } = req.body;
    const amt = Number(amount);

    if (
      !type ||
      !Number.isFinite(amt) ||
      !["income", "expense"].includes(type) ||
      (source && !["account", "credit"].includes(source))
    ) {
      return res.status(400).json({ error: "Dados inválidos" });
    }

    db.run(
      `UPDATE transactions
       SET type = ?, amount = ?, comment = ?, category = ?, source = ?
       WHERE id = ? AND user_id = ?`,
      [
        type,
        amt,
        comment || null,
        category || null,
        source || "account",
        req.params.id,
        req.userId,
      ]
    );

    saveDb();
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao editar transação" });
  }
});

// Deletar transação
app.delete("/api/transactions/:id", auth, (req, res) => {
  try {
    db.run("DELETE FROM transactions WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao deletar transação" });
  }
});

// Download backup manual
app.get("/api/backup/download", auth, (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    res.download(DB_PATH, `controle-financeiro-${timestamp}.db`);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao fazer backup" });
  }
});

// Listar backups
app.get("/api/backup/list", auth, (req, res) => {
  try {
    const backups = fs
      .readdirSync(BACKUP_DIR)
      .filter((f) => f.startsWith("backup-"))
      .map((f) => ({
        filename: f,
        date: f.replace("backup-", "").replace(".db", ""),
        size: fs.statSync(path.join(BACKUP_DIR, f)).size,
      }))
      .sort((a, b) => b.date.localeCompare(a.date));

    res.json(backups);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao listar backups" });
  }
});

// Start
initDb().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
    console.log(`📁 Banco de dados: ${DB_PATH}`);
    console.log(`💾 Backups em: ${BACKUP_DIR}`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
  });
});
