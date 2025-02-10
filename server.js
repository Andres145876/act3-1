const express = require('express');
const fs = require('fs/promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const secretKey = "secreto seguro";

app.use(bodyParser.json());

//  Función para leer archivos JSON de forma segura
const leerArchivoSeguro = async (ruta) => {
  try {
    const data = await fs.readFile(ruta, 'utf-8');
    return data ? JSON.parse(data) : [];
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.warn(` Archivo ${ruta} no encontrado, creando uno nuevo...`);
      await fs.writeFile(ruta, '[]'); // Si no existe, lo crea vacío
      return [];
    }
    console.error(` Error al leer ${ruta}:`, error);
    return [];
  }
};

//  Middleware de autenticación
const authMiddleware = async (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ mensaje: "No tienes autorización" });

  try {
    const verificado = jwt.verify(token.replace("Bearer ", ""), secretKey);
    req.user = verificado;
    next();
  } catch (error) {
    console.error(" Error en la autenticación:", error);
    res.status(400).json({ mensaje: "Token inválido" });
  }
};

//  Manejo de errores global
const errorHandler = (err, req, res, next) => {
  console.error(" Error interno:", err);
  res.status(500).json({ mensaje: "Error interno del servidor" });
};

//  Rutas de la API (CRUD de tareas)
app.get('/tareas', authMiddleware, async (req, res) => {
  try {
    const tareas = await leerArchivoSeguro('./tareas.json');
    res.json(tareas);
  } catch (error) {
    console.error(" Error al obtener tareas:", error);
    res.status(500).json({ mensaje: "Error al leer las tareas" });
  }
});

app.post('/tareas', authMiddleware, async (req, res) => {
  const { titulo, descripcion } = req.body;
  if (!titulo || !descripcion) {
    return res.status(400).json({ mensaje: "Título y descripción son requeridos" });
  }

  try {
    const tareas = await leerArchivoSeguro('./tareas.json');
    const nuevaTarea = { id: Date.now(), titulo, descripcion };
    tareas.push(nuevaTarea);
    await fs.writeFile('./tareas.json', JSON.stringify(tareas, null, 2));
    res.json(nuevaTarea);
  } catch (error) {
    console.error(" Error al agregar tarea:", error);
    res.status(500).json({ mensaje: "Error al agregar la tarea" });
  }
});

app.put('/tareas/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { titulo, descripcion } = req.body;

  try {
    let tareas = await leerArchivoSeguro('./tareas.json');
    let tareaEncontrada = false;

    tareas = tareas.map(t => {
      if (t.id == id) {
        tareaEncontrada = true;
        return { ...t, titulo, descripcion };
      }
      return t;
    });

    if (!tareaEncontrada) {
      return res.status(404).json({ mensaje: "Tarea no encontrada" });
    }

    await fs.writeFile('./tareas.json', JSON.stringify(tareas, null, 2));
    res.json({ mensaje: "Tarea actualizada" });
  } catch (error) {
    console.error(" Error al actualizar tarea:", error);
    res.status(500).json({ mensaje: "Error al actualizar la tarea" });
  }
});

app.delete('/tareas/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;

  try {
    let tareas = await leerArchivoSeguro('./tareas.json');
    const nuevaLista = tareas.filter(t => t.id != id);

    if (tareas.length === nuevaLista.length) {
      return res.status(404).json({ mensaje: "Tarea no encontrada" });
    }

    await fs.writeFile('./tareas.json', JSON.stringify(nuevaLista, null, 2));
    res.json({ mensaje: "Tarea eliminada" });
  } catch (error) {
    console.error(" Error al eliminar tarea:", error);
    res.status(500).json({ mensaje: "Error al eliminar la tarea" });
  }
});

//  Rutas de autenticación
app.post('/registro', async (req, res) => {
  const { nombre, contrasena } = req.body;
  if (!nombre || !contrasena) {
    return res.status(400).json({ mensaje: "Nombre y contraseña son requeridos" });
  }

  try {
    const usuarios = await leerArchivoSeguro('./usuarios.json');
    if (usuarios.find(u => u.nombre === nombre)) {
      return res.status(400).json({ mensaje: "El usuario ya existe" });
    }

    const hashedPassword = await bcrypt.hash(contrasena, 10);
    usuarios.push({ nombre, contrasena: hashedPassword });
    await fs.writeFile('./usuarios.json', JSON.stringify(usuarios, null, 2));
    res.json({ mensaje: "Usuario registrado" });
  } catch (error) {
    console.error(" Error al registrar usuario:", error);
    res.status(500).json({ mensaje: "Error al registrar el usuario" });
  }
});

app.post('/inicio', async (req, res) => {
  const { nombre, contrasena } = req.body;
  if (!nombre || !contrasena) {
    return res.status(400).json({ mensaje: "Nombre y contraseña son requeridos" });
  }

  try {
    const usuarios = await leerArchivoSeguro('./usuarios.json');
    const usuario = usuarios.find(u => u.nombre === nombre);

    if (!usuario || !await bcrypt.compare(contrasena, usuario.contrasena)) {
      return res.status(400).json({ mensaje: "Usuario o contraseña incorrectos" });
    }

    const token = jwt.sign({ nombre }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error(" Error al iniciar sesión:", error);
    res.status(500).json({ mensaje: "Error al iniciar sesión" });
  }
});

//  Iniciar el servidor
app.listen(port, () => {
  console.log(` Servidor corriendo en http://localhost:${port}`);
});

// Middleware global de manejo de errores
app.use(errorHandler);