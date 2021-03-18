const express = require('express');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const {check, validationResult} = require('express-validator/check');
const config = require('config');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

router.get('/', auth, async (req, res)=>{
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
    }
    
});

router.post('/', [
    check('email', 'Enter valid Email').isEmail(),
    check('password', 'Password required').exists()
], async (req, res)=>{
    const error = validationResult(req);
    if(!error.isEmpty())
        return res.status(400).json({errors:error.array()});
    
    const {email, password} = req.body;

    try{
        let user = await User.findOne({email});
        if(!user)
            return res.status(401).json({errors:[{msg:'Invalid credentials'}]});
        
        const isMatch = await bcryptjs.compare(password, user.password);
        if(!isMatch)
            return res.status(401).json({errors:[{msg:'Invalid credentials'}]});

        const payload = {
            user:{
                id:user.id
            }
        };
        jwt.sign(payload, config.get('jwtSecret'), {expiresIn: 3600}, (err, token)=>{
            if(err)
                throw err;
            res.json({token});
        });

    }
    catch(error){
        console.error(error.message);
        res.status(500).send("Server error");
    }
    
});

module.exports = router;