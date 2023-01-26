const { response } = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs')
const { generarJWT } = require('../helpers/jwt')


const crearUsuario = async (req, res = response)=>{

   const {email, name, password} = req.body;

   try  {

       //Verificar el Email

       const usuario = await Usuario.findOne({email});

       if (usuario){
         return res.status(400).json({
            ok:false,
            msg:'Email usado por otro usuario'
         })
       }


   //Crear Usuario 
       const dbUser = new Usuario (req.body);


   // Encriptar "Hash" Contraseña
       const salt = bcrypt.genSaltSync();
       dbUser.password = bcrypt.hashSync(password, salt);


   //Generar JWT

   const token = await generarJWT(dbUser.id, name)

   //Crear usuario de base de datos

   await dbUser.save();

   //Generar Respuesta exirosa

   return res.status(201).json({
      ok:true,
      uid: dbUser.id,
      name,
      email,
      token
   })
   
      
   } catch (error) {
      return res.status(500).json({
         ok:false,
         msg:'Por favor hable con el administrador'
      })
      
   }

  
    
   }

const loginUsuario = async(req, res = response)=>{

   const {email, password} = req.body

   try {

      const dbUser = await Usuario.findOne({email});

      if(!dbUser){
         return res.status(400).json({
            ok:false,
            msg:'Credenciales no válidas'
         })
      }
       // COnfirmar si password hace match

   const validarPassword = bcrypt.compareSync(password, dbUser.password);
   if(!validarPassword){
      return res.status(400).json({
         ok:false,
         msg:'Password no válido'
      })
   }

   //generar JWT
   const token = await generarJWT(dbUser.id, dbUser.name);

   //Respuesta del servicio

   return res.json({
      ok:true,
      uid: dbUser.id,
      name:dbUser.name,
      email: dbUser.email,
      token
   })
      
   } catch (error) {
      console.log(error);
      return res.status(500).json({
         ok:false,
         msg:'Hable con el administrador'
      })
   }


  
   
   
   }

const revalidarToken = async  (req, res = response)=>{

   const {uid} = req;

   //Leer base de datos para obtener Email
   const dbUser = await Usuario.findById(uid) ;

   const token = await generarJWT(uid, dbUser.name);

  /*  const token = req.header('x-token');

   if(!token){

      return res.status(401).json({
         ok: false,
         msg:'Error en el token'
      })
   } */
    return res.json({
       ok:true,
       uid,
       name:dbUser.name,
       email: dbUser.email,
       token
       
    })
   }


   module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
   }