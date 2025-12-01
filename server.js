require("dotenv").config();
const express = require("express");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "financeiro.db");

let db;

// Inicializar sql.js
async function initDb() {
  const SQL = await initSqlJs();

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  try {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } catch {
    db = new SQL.Database();

    db.run(`
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
    `);

    saveDb();
  }
}

// Salvar banco de dados
function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, data);
}

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
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run("INSERT INTO users (password, initial_balance) VALUES (?, ?)", [
      hashedPassword,
      initialBalance || 0,
    ]);

    const result = db.exec("SELECT last_insert_rowid() as id")[0];
    const userId = result.values[0][0];

    saveDb();

    const token = jwt.sign(
      { userId },
      process.env.JWT_SECRET || "secret-key-123"
    );
    res.status(201).json({ token, userId });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar conta" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { password } = req.body;
    const result = db.exec("SELECT * FROM users LIMIT 1");

    if (!result.length) {
      return res.status(404).json({ error: "Nenhuma conta encontrada" });
    }

    const user = {
      id: result[0].values[0][0],
      password: result[0].values[0][1],
    };

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
    res.status(400).json({ error: "Erro no login" });
  }
});

app.get("/api/user", auth, (req, res) => {
  try {
    const result = db.exec(
      "SELECT id, initial_balance, created_at FROM users WHERE id = ?",
      [req.userId]
    );

    if (!result.length) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const user = {
      _id: result[0].values[0][0],
      initialBalance: result[0].values[0][1],
      createdAt: result[0].values[0][2],
    };

    res.json(user);
  } catch (error) {
    res.status(400).json({ error: "Erro ao buscar usuário" });
  }
});

app.put("/api/user/balance", auth, (req, res) => {
  try {
    const { initialBalance } = req.body;
    db.run("UPDATE users SET initial_balance = ? WHERE id = ?", [
      initialBalance,
      req.userId,
    ]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: "Erro ao atualizar saldo" });
  }
});

app.get("/api/transactions", auth, (req, res) => {
  try {
    const result = db.exec(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC",
      [req.userId]
    );

    if (!result.length) {
      return res.json([]);
    }

    const transactions = result[0].values.map((row) => {
      // Força data atual do Brasil UTC-3
      const dateBR = new Date().toLocaleString("sv-SE", {
        timeZone: "America/Sao_Paulo",
      });

      return {
        _id: row[0],
        type: row[2],
        amount: row[3],
        comment: row[4],
        date: dateBR, // Data já formatada em UTC-3
      };
    });

    res.json(transactions);
  } catch (error) {
    res.status(400).json({ error: "Erro ao buscar transações" });
  }
});

app.post("/api/transactions", auth, (req, res) => {
  try {
    const { type, amount, comment } = req.body;

    db.run(
      "INSERT INTO transactions (user_id, type, amount, comment) VALUES (?, ?, ?, ?)",
      [req.userId, type, amount, comment || null]
    );

    const result = db.exec("SELECT last_insert_rowid() as id")[0];
    const id = result.values[0][0];

    saveDb();

    res.status(201).json({
      _id: id,
      type,
      amount,
      comment,
      date: new Date().toISOString(),
    });
  } catch (error) {
    res.status(400).json({ error: "Erro ao criar transação" });
  }
});

app.delete("/api/transactions/:id", auth, (req, res) => {
  try {
    db.run("DELETE FROM transactions WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: "Erro ao deletar transação" });
  }
});

// Iniciar servidor
initDb().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
    console.log(`📁 Banco de dados em: ${DB_PATH}`);
  });
});
