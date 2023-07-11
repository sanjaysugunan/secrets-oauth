require("dotenv").config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose= require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//installed passport passport-local passport-local-mongoose express-session
//require express-session passport passport-local-mongoose

const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));
//for express-session
app.use(session({
   secret: "Our little secret.",
   resave: false,
   saveUninitialized: false
 }));
//for passport to initialize to deal with session
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/secrets-passportDB");

//for Schema to have a plugin it has to be mongoose.Schema
const  userSchema = new mongoose.Schema({
   email: String,
   password: String,
   googleId:String,
   secret: String//for saving secrets
});
//for passport.local.mongoose 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

//passport-local-mongoose configuration
passport.use(User.createStrategy());
//serialise user
passport.serializeUser(function(user, done) {
   done(null, user);
 });
 
 passport.deserializeUser(function(user, done) {
   done(null, user);
 });
//oauth2.0
passport.use(new GoogleStrategy({
   clientID: process.env.CLIENT_ID,
   clientSecret: process.env.CLIENT_SECRET,
   callbackURL: "http://localhost:3000/auth/google/secrets",
   userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
 },
 function(accessToken, refreshToken, profile, cb) {
   console.log(profile);

   User.findOrCreate({ googleId: profile.id }, function (err, user) {
     return cb(err, user);
   });
 }
));
app.get("/", function(req,res){
   res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {scope:["profile"]}));

app.get("/login", function(req,res){
   res.render("login");
});

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register", function(req,res){
   res.render("register");
});

app.get("/secrets", function(req,res){
  
  User.find({"secret":{$ne: null}}).then((foundUsers)=>{
    if(foundUsers){
         res.render("secrets",{userSecret:foundUsers})
      }
   });
});

app.get("/logout", function(req,res){
   //to end session deletes cookie
   req.logout(function(err){
      if(err){return next(err);}
   });
   res.redirect("/");
});

app.get("/submit", function(req,res){
   if(req.isAuthenticated()){
      res.render("submit");
   }else{
      res.redirect("/login");
   } 
});

app.post("/submit", function(req,res){
  
   const submitedSecret = req.body.secret;
   //req.body passes all details of user
   console.log(req.user);
   User.findById(req.user._id)
      .then((foundUser)=>{
        if(foundUser){
          foundUser.secret=submitedSecret;
          foundUser.save().then(function(){
            res.redirect("/secrets");
          })
        }else{
         res.redirect("/login");
        }
      })
      .catch((err)=>{
         if(err){
            console.log(err);
         }
      });
});

app.post("/register", function(req,res){
 
 User.register({username: req.body.username}, req.body.password, function(err,user){
   if(err){
      console.log(err);
      res.redirect("/register");
   }else{
      passport.authenticate("local")(req,res, function(){
         res.redirect("/secrets");
      })
   }
 })  
});

app.post("/login", function(req,res){

   const user = new User({
      username: req.body.username,
      password: req.body.password
   });
   //comes from passport
   req.login(user, function(err){
      if(err){
         console.log(err);
      }else{
         passport.authenticate("local")(req,res, function(){
            res.redirect("/secrets");
         });
      }
   });


});


app.listen(3000, function(req,res){
   console.log("Server started on port 3000.");
});