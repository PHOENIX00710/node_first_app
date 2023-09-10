import express from 'express';
import bodyParser from 'body-parser';
import mongoose, { Schema } from 'mongoose';
import path from 'path'
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import ejs from "ejs";

const app=express();

//Middlewares
app.use(express.static(path.join(path.resolve(),"public")));
app.use(bodyParser.urlencoded({extended:true}));
app.use(cookieParser());

//set view engine for dynamic pages
app.set("view engine","ejs");

// Connect database
mongoose
.connect("mongodb://127.0.0.1:27017",{
    "dbName":"users",
})
.then(()=>console.log("Connected"))
.catch((e)=>console.error(e));

// Make Schema and Model
const userSchema=new Schema({
    name: String,
    email: String,
    password: String,
})
const users=mongoose.model("users",userSchema);
// DataBase Setup Done

// Authentication function
const authentication=async(req,res)=>{
    const {token}=req.cookies;
    if(token){
        // Extracting the original ID form the cookie, we decode using the token
        const iD=jwt.verify(token,"jsiufbdiufbuibfIU");
        const user= await users.findById(iD);
        if(user)
           return res.render("logout",{name:user.name});
    }
    return res.redirect("/login");
}

// We will make routes for all different pages to redirect to as and when required
app.get("/",authentication);

app.get("/login",(req,res)=>{
    res.render("login")
})
app.get("/logout",(req,res)=>{
    res.render("logout");
})
app.get("/register",(req,res)=>{
    res.render("register");
})

// Rendering of buttons Done Now handling post requests
app.post("/login",async(req,res)=>{
    const {email,password}=req.body;
    let user= await users.findOne({email});
    if(!user)
    return res.redirect("/register");
    // Make sure this compare function is await else it will go on the remaining procedure without actually comparing whether we have the right user or not and it will login regardless.
    const isUser=await bcrypt.compare(password,user.password);
    if(!isUser){
        // We need to do return res.render to make sure further statements do not get executed and we redirect from here itself.
       return res.render("login",{message:"Invalid Password"});
    }
    else{
        const token=jwt.sign({_id:user._id},"jsiufbdiufbuibfIU");
        res.cookie("token",token,{
            httpOnly: true,
            expires: new Date(Date.now()+60*1000),
        })
        res.redirect("/");
    }
})
app.post("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.redirect("/login");
})
app.post("/register",async(req,res)=>{
    const {name,email,password}=req.body;
    let user= await users.findOne({email});// Inside findOne u need to send an object
    if(user){
        res.redirect("/login");
    }
    console.log(name,email,password);
    const hashedPassword= await bcrypt.hash(password,10); // 10 is a salt that we need to mention
    user=await users.create({
        name,
        email,
        password: hashedPassword,
    }); // It is an async function

    // This is done to hide the exact id of the document that will be created inside the users collection everytime a new user registers. We pass an object having key of _id with value of that particular document's id and we encrypt it using jwt and an algorithn which is a string in this case.
    const token=jwt.sign({_id:user._id},"jsiufbdiufbuibfIU");
    res.cookie("token",token,{
        httpOnly: true,
        expires: new Date(Date.now()+60*1000),
    })
    res.redirect("/");
})


app.listen(2000,()=>{
    console.log("Server is listening at port 2000");
})
// Majority of mongoose operations return a promise thus we make use of async and await