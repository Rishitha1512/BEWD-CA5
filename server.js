const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
require('dotenv').config()
const jwt= require('jsonwebtoken')
const cookieParser = require('cookie-parser')

const app = express()

app.use(express.json())
app.use(cookieParser())

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

const userSchema = new mongoose.Schema({
    username:String,
    password:String
})

const User = mongoose.model('User',userSchema)

app.post('/register',async(req,res)=>{
    const {username, password} = req.body
    const existingUser = await User.findOne({username})
    if (existingUser){
        return res.status(400).json({message:"User already exists"})
    }
    const hashedPassword = await bcrypt.hash(password,10)
    const newUser = new User({username,password:hashedPassword})
    await newUser.save();

    res.status(200).json({message:"User registered successfully"})
});

app.post('/login',async(req,res)=>{
    const {username, password} = req.body
    const user = await User.findOne({username})
    if (!user){
        return res.status(400).json({message:"User not found"})
    }
    const isMatch = await bcrypt.compare(password,user.password)
    if (!isMatch){
        return res.status(400).json({message:"Password is incorrect"})
    }

    const JWT_TOKEN = jwt.sign({username:user.username},process.env.SECRET_KEY,{expiresIn:'1h'})
    res.cookie('JWT_TOKEN',JWT_TOKEN,{
        httpOnly:true,
        secure:true
    })
    res.status(200).json({message:"Log In successful"})
});

const authenticate = (req,res,next)=>{
    const JWT_TOKEN = req.cookies.JWT_TOKEN
    if (!JWT_TOKEN){
        return res.status(404).json({message:"Not Found"})
    }
    jwt.verify(JWT_TOKEN,process.env.SECRET_KEY,(err,decoded)=>{
        if (err){
            return res.status(404).json({message:"Not Found"})
        }
        req.user = decoded;
        next();
    })
};

app.get('/protected',authenticate,(req,res)=>{
    res.status(200).json({message:"User authenticated successfully"})
});

port=3000
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});