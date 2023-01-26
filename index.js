const express = require('express');
const cors = require ('cors');
const path = require ('path')
const { dbConnection } = require('./db/config');
require('dotenv').config();

// Crear el servidor/ aplicación Express
const app = express();

// Conexión Base de datos
dbConnection();

//Directorio publico
app.use(express.static('public'))

//CORS
app.use(cors() );

// Lectura y parseo del body
app.use(express.json() );

/* Rutas */
app.use('/api/auth', require('./routes/auth'));

// Manejar demas rutas
app.get('*', (req, res)=>{
    res.sendFile( path.resolve(__dirname, 'public/index.html') )
})

app.listen( process.env.PORT, () => {
    console.log(`En puerto ${process.env.PORT}`);
})  