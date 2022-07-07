const express = require('express')
const router = express.Router()
const auth = require('../../middleware/auth')
const jwt = require('jsonwebtoken')
const config = require('config');
const bcrypt = require('bcryptjs')
const { check, validationResult } = require('express-validator');
const User = require('../../models/User')

router.get('/', auth, async(req,res)=>{
    try{

        const user = await User.findById(req.user.id).select('-password')
        res.json(user);

    } catch(err){
        res.status(500).send('Server error!')
    }
})

router.post(
    '/',
    [ check('email', " Please include a valid email").isEmail(),
      check('password', "Please is required!").exists()
  ],
    async(req, res) => {
      const errors = validationResult(req);
      if(!errors.isEmpty()){
          return res.status(400).json({errors: errors.array() })
      }
  
      // check users exist?
      const { email, password } = req.body;
      try {
          let user = await User.findOne({email })
  
          if(!user){
              res.status(400).json({ errors: [ { msg: 'Username does not exist!'}]})
          }

          const isMatch = await bcrypt.compare(password, user.password);
          if(!isMatch){
            res.status(400).json({ errors: [ { msg: 'Password is not correct!'}]})
          }


          const payload = {
              user : {
                  id: user.id
              }
          }
          jwt.sign(
              payload,
              config.get('jwtSecret'),
              {expiresIn: 36000},
              (err,token)=> {
                  if(err) throw err;
                  res.json({token});
              })
      }catch(err){
          console.error(err.message);
          res.status(500).send('Server error!')
      }
  
    }
  );


module.exports = router