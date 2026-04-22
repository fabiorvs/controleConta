require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || crypto.randomBytes(32).toString("hex");

// auth middleware
const auth = (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new Error("Token ausente");

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido ou expirado" });
  }
};

function rowToTransaction(row) {
  return {
    _id: row.id,
    type: row.type,
    amount: Number(row.amount) || 0,
    comment: row.comment,
    category: row.category,
    source: row.source || "account",
    dateISO: row.date,
  };
}

// REGISTER
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

    const { data: existing, error: existingError } = await supabase
      .from("users")
      .select("id")
      .or(`username.eq.${username},email.eq.${email}`)
      .limit(1);

    if (existingError) throw existingError;
    if (existing && existing.length > 0) {
      return res.status(400).json({ error: "Usuário ou email já cadastrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const { data: insertedUser, error: insertError } = await supabase
      .from("users")
      .insert({
        username,
        email,
        password: hashedPassword,
        initial_balance: Number(initialBalance) || 0,
      })
      .select("id, username")
      .single();

    if (insertError) throw insertError;

    const userId = insertedUser.id;

    const token = jwt.sign({ userId, username }, JWT_SECRET, {
      expiresIn: "1h",
    });

    const refreshToken = jwt.sign({ userId, username }, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000,
    ).toISOString();

    const { error: tokenError } = await supabase.from("refresh_tokens").insert({
      user_id: userId,
      token: refreshToken,
      expires_at: expiresAt,
    });

    if (tokenError) throw tokenError;

    res.status(201).json({ token, refreshToken, userId, username });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar conta" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Preencha usuário e senha" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, email, password")
      .or(`username.eq.${username},email.eq.${username}`)
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    if (!user) {
      return res.status(401).json({ error: "Usuário ou senha incorretos" });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Usuário ou senha incorretos" });
    }

    await supabase
      .from("users")
      .update({ last_login: new Date().toISOString() })
      .eq("id", user.id);

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" },
    );

    const refreshToken = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_REFRESH_SECRET,
      { expiresIn: "7d" },
    );

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000,
    ).toISOString();

    const { error: tokenError } = await supabase.from("refresh_tokens").insert({
      user_id: user.id,
      token: refreshToken,
      expires_at: expiresAt,
    });

    if (tokenError) throw tokenError;

    res.json({ token, refreshToken, userId: user.id, username: user.username });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro no login" });
  }
});

// REFRESH
app.post("/api/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token não fornecido" });
    }

    const { data: saved, error } = await supabase
      .from("refresh_tokens")
      .select("user_id, expires_at")
      .eq("token", refreshToken)
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    if (!saved) {
      return res.status(401).json({ error: "Refresh token inválido" });
    }

    if (new Date(saved.expires_at) < new Date()) {
      return res.status(401).json({ error: "Refresh token expirado" });
    }

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const newToken = jwt.sign(
      { userId: decoded.userId, username: decoded.username },
      JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({ token: newToken });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: "Refresh token inválido" });
  }
});

// LOGOUT
app.post("/api/logout", auth, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      await supabase.from("refresh_tokens").delete().eq("token", refreshToken);
    }
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "Erro ao fazer logout" });
  }
});

// USER
app.get("/api/user", auth, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, email, initial_balance, created_at, last_login")
      .eq("id", req.userId)
      .single();

    if (error) throw error;

    res.json({
      _id: user.id,
      username: user.username,
      email: user.email,
      initialBalance: Number(user.initial_balance) || 0,
      createdAt: user.created_at,
      lastLogin: user.last_login,
    });
  } catch (error) {
    console.error(error);
    res.status(404).json({ error: "Usuário não encontrado" });
  }
});

// DASHBOARD
app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("initial_balance")
      .eq("id", req.userId)
      .single();

    if (userError) throw userError;

    const { data: txs, error: txError } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.userId)
      .order("date", { ascending: false });

    if (txError) throw txError;

    const initialBalance = Number(user.initial_balance) || 0;
    const transactions = (txs || []).map(rowToTransaction);

    const accountTransactions = transactions.filter(
      (t) => t.source === "account",
    );
    const creditTransactions = transactions.filter(
      (t) => t.source === "credit",
    );

    const accountBalance = accountTransactions.reduce((acc, t) => {
      return t.type === "income" ? acc + t.amount : acc - t.amount;
    }, initialBalance);

    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);

    const creditExpensesThisMonth = creditTransactions
      .filter((t) => t.type === "expense" && new Date(t.dateISO) >= firstDay)
      .reduce((acc, t) => acc + t.amount, 0);

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
    console.error(error);
    res.status(400).json({ error: "Erro ao carregar dashboard" });
  }
});

// UPDATE INITIAL BALANCE
app.put("/api/user/balance", auth, async (req, res) => {
  try {
    const { initialBalance } = req.body;

    const { error } = await supabase
      .from("users")
      .update({ initial_balance: Number(initialBalance) || 0 })
      .eq("id", req.userId);

    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao atualizar saldo" });
  }
});

// GET TRANSACTIONS
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.userId)
      .order("date", { ascending: false });

    if (error) throw error;

    res.json((data || []).map(rowToTransaction));
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao buscar transações" });
  }
});

// CREATE TRANSACTION
app.post("/api/transactions", auth, async (req, res) => {
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

    const { data, error } = await supabase
      .from("transactions")
      .insert({
        user_id: req.userId,
        type,
        amount: amt,
        comment: comment || null,
        category: category || null,
        source,
      })
      .select("*")
      .single();

    if (error) throw error;

    res.status(201).json(rowToTransaction(data));
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao criar transação" });
  }
});

// UPDATE TRANSACTION
app.put("/api/transactions/:id", auth, async (req, res) => {
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

    const { error } = await supabase
      .from("transactions")
      .update({
        type,
        amount: amt,
        comment: comment || null,
        category: category || null,
        source: source || "account",
      })
      .eq("id", req.params.id)
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao editar transação" });
  }
});

// DELETE TRANSACTION
app.delete("/api/transactions/:id", auth, async (req, res) => {
  try {
    const { error } = await supabase
      .from("transactions")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Erro ao deletar transação" });
  }
});

// opcional para rodar local
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
  });
}

module.exports = app;
