const path = require('path');

const jwt = require('jsonwebtoken');
const config = require('../config');

function verifyToken(req, res, next){
    const token = req.headers['x-access-token'];
    if(!token){
        const errorFilePath = path.join(__dirname, '../../public/error.html');
        return res.status(401).sendFile(errorFilePath);
    }

    const decoded = jwt.verify(token, config.secret);

    req.userId = decoded.id;
    next();

}

module.exports = verifyToken;