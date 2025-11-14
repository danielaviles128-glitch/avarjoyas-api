require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");
const nodemailer = require("nodemailer"); // si lo usas para algo más, si no, lo quitamos

const resend = new Resend(process.env.RESEND_API_KEY);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(
  cors({
    origin: "*",
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    allowedHeaders: "Content-Type,Authorization",
  })
);
app.use(express.json());

// ---------------------------------------------
// AUTENTICACIÓN (bcrypt + JWT)
// ---------------------------------------------

// Middleware para proteger rutas sensibles
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token faltante" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload.user;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// Login de administrador (usa variables de entorno)
app.post("/api/login", async (req, res) => {
  const { user, password } = req.body;

  if (!user || !password) {
    return res.status(400).json({ error: "Credenciales faltantes" });
  }

  const adminUser = process.env.ADMIN_USER;
  const adminHash = process.env.ADMIN_PASS_HASH;

  if (!adminUser || !adminHash) {
    return res.status(500).json({ error: "Autenticación no configurada" });
  }

  if (user !== adminUser) {
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  }

  const match = await bcrypt.compare(password, adminHash);
  if (!match) {
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  }

  const token = jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn: "8h" });

  res.json({ token });
});

// Ruta que valida el token (el frontend la usa al iniciar)
app.get("/api/auth-check", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token faltante" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ ok: true, user: payload.user });
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
});

app.get("/api/productos", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM productos ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener productos:", err);
    res.status(500).json({ error: "Error al obtener productos" });
  }
});

app.post("/api/productos", requireAuth, async (req, res) => {
  const { nombre, precio, categoria, stock, imagen, nueva_coleccion } = req.body;

  // Validaciones básicas
  if (!nombre || precio == null || !categoria || stock == null) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, precio, categoria, stock, imagen, nueva_coleccion)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [nombre, precio, categoria, stock, imagen, nueva_coleccion]
    );

    res.status(201).json({
      mensaje: "✅ Producto agregado correctamente",
      producto: result.rows[0]
    });
  } catch (err) {
    console.error("❌ Error al agregar producto:", err);
    res.status(500).json({ error: "Error al agregar producto" });
  }
});

app.put("/api/productos/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { nombre, precio, categoria, stock, imagen, nueva_coleccion } = req.body;

  // Validaciones básicas
  if (!nombre || precio == null || !categoria || stock == null) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  try {
    const result = await pool.query(
      `UPDATE productos 
       SET nombre=$1, precio=$2, categoria=$3, stock=$4, imagen=$5, nueva_coleccion=$6
       WHERE id=$7
       RETURNING *`,
      [nombre, precio, categoria, stock, imagen, nueva_coleccion, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    res.json({
      mensaje: "✅ Producto actualizado correctamente",
      producto: result.rows[0]
    });
  } catch (err) {
    console.error("❌ Error al actualizar producto:", err);
    res.status(500).json({ error: "Error al actualizar producto" });
  }
});


app.delete("/api/productos/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM productos WHERE id=$1", [id]);
    res.sendStatus(204);
  } catch (err) {
    console.error("Error al eliminar producto:", err);
    res.status(500).json({ error: "Error al eliminar producto" });
  }
});

// === 📩 Ruta para suscripción de correos ===
app.post("/api/suscribirse", async (req, res) => {
  const { email } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Correo electrónico no válido" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO suscriptores (email)
       VALUES ($1)
       ON CONFLICT (email) DO NOTHING
       RETURNING id, email, fecha`,
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(200).json({ message: "Ya estás suscrito 🥰" });
    }

    res.status(201).json({ message: "¡Gracias por suscribirte! 💌" });
  } catch (err) {
    console.error("Error al guardar suscripción:", err);
    res.status(500).json({ error: "Error al registrar la suscripción" });
  }
});
// === 📋 Obtener lista de suscriptores (con filtro y paginación) ===
app.get("/api/suscriptores", requireAuth, async (req, res) => {
  try {
    // Parámetros opcionales desde la URL
    const { search = "", limit = 50, offset = 0 } = req.query;

    // Si se envía un término de búsqueda, filtramos por email o fecha
    const query = `
      SELECT id, email, fecha
      FROM suscriptores
      WHERE email ILIKE $1 OR TO_CHAR(fecha, 'YYYY-MM-DD') ILIKE $1
      ORDER BY fecha DESC
      LIMIT $2 OFFSET $3
    `;

    const result = await pool.query(query, [`%${search}%`, limit, offset]);

    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener suscriptores:", err);
    res.status(500).json({ error: "Error al obtener la lista de suscriptores" });
  }
});
// === 🗑️ Eliminar un suscriptor por ID ===
app.delete("/api/suscriptores/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("DELETE FROM suscriptores WHERE id = $1 RETURNING *", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Suscriptor no encontrado" });
    }

    res.json({ message: "Suscriptor eliminado correctamente ✅" });
  } catch (err) {
    console.error("Error al eliminar suscriptor:", err);
    res.status(500).json({ error: "Error al eliminar el suscriptor" });
  }
});

app.get("/api/test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ ok: true, time: result.rows[0] });
  } catch (err) {
    console.error("❌ Error al probar conexión con Neon:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/contacto", async (req, res) => {
  const { nombre, email, mensaje } = req.body;

  if (!nombre || !email || !mensaje) {
    return res.status(400).json({ error: "Todos los campos son obligatorios." });
  }

  try {
    const resultado = await resend.emails.send({
      from: "AVAR Joyas 💎 <onboarding@resend.dev>",
      to: "avarjoyas@gmail.com",
      subject: "💌 Nuevo mensaje desde el formulario de contacto",
      html: `
        <h3>Nuevo mensaje de contacto</h3>
        <p><strong>Nombre:</strong> ${nombre}</p>
        <p><strong>Correo:</strong> ${email}</p>
        <p><strong>Mensaje:</strong></p>
        <p>${mensaje}</p>
      `,
    });

    console.log("📩 RESEND RESPONSE:", resultado);
    res.status(200).json({ success: "Mensaje enviado correctamente ✅" });
  } catch (error) {
    console.error("❌ Error al enviar mensaje con Resend:", error);
    res.status(500).json({
      error: "No se pudo enviar el mensaje. Intenta más tarde.",
      detalle: error.message,
    });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor ejecutándose en puerto ${PORT}`));