const path = require('path');

const { Router } = require('express');
const router = Router();

const jwt = require('jsonwebtoken');
const config = require('../config');
const verifyToken = require('./verifyToken');

const User = require('../models/User');

router.post('/signup', async (req, res, next) => {
    const { username, email, password } = req.body;
    const user = new User(
       {
          username,
          email,
          password
       } 
    );

    // console.log("datos del usuario")
    // console.log(username, email, password)
    // console.log("usuario:")
    // console.log(user)

    user.password = await user.encryptPassword(user.password)
    await user.save();

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    })
    //res.json({message: 'Received'})
    res.json({auth: true, token})
})

router.get('/me', verifyToken, async (req, res, next) => {
    const user = await User.findById(req.userId, { password: 0 });
    if(!user){
        return res.status(404).send('No user found....!!!');
    }

    res.json(user);
})

router.post('/signin', async (req, res, next) => {
    const { email, password } = req.body; 
    console.log(email, password);
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).send("The user doesn't exists");
    }

    const validPassword = await user.validatePassword(password);
    //console.log(passwordIsValid);
    if(!validPassword){
        return res.status(401).json({auth: false, token: null});
    }

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    });
    
    res.json({auth: true, token});
})

router.get('/dashboard', verifyToken, (req, res, next) => {
    res.json('dashboard');
})

router.get('/iniciar', async(req, res, next) => {
    const loginPage = path.join(__dirname, '../../public/login.html')
    res.sendFile(loginPage)
})

router.get('/register', async(req, res, next) => {
    const registerPage = path.join(__dirname, '../../public/register.html')
    res.sendFile(registerPage)
})


module.exports = router