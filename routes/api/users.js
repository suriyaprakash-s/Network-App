const express = require('express');
const {check, validationResult} = require('express-validator/check');
const gravatar = require('gravatar');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const User = require('./../../models/User');
const router = express.Router();


router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Enter valid Email').isEmail(),
    check('password', 'Enter a password with 6 or more characters').isLength({min:6})
], async (req, res)=>{
    console.log(req.body);
    const error = validationResult(req);
    if(!error.isEmpty())
        return res.status(400).json({errors:error.array()});
    
    const {name, email, password} = req.body;

    try{
        let user = await User.findOne({email});
        if(user)
            return res.status(400).json({errors:[{msg:'User already exists'}]});
        const avatar = gravatar.url(email, {
            s:'200',
            r:'pg',
            d:'mm'
        });
        
        user = new User({
            name,
            email,
            password,
            avatar
        });
    
        const salt = await bcryptjs.genSalt(10);
        user.password = await bcryptjs.hash(password, salt);

        await user.save();

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