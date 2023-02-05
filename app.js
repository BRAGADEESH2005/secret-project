//jshint esversion:6
require('dotenv').config();
const express=require("express")
const bodyParser=require("body-parser")
const ejs=require("ejs");
const mongoose=require("mongoose");
mongoose.set("strictQuery",true)
const session=require("express-session")
const passport=require("passport")
const passportLocalMongoose=require("passport-local-mongoose")
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate=require('mongoose-findorcreate');
// const encrypt=require("mongoose-encryption")
// const md5=require("md5")
// const bcrypt=require("bcrypt")
// const saltRounds=10

const app=express();

app.set("view engine","ejs")

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static("public"))

app.use(session({
  secret:"Our little secret is here.",
  resave:false,//when is session is idle for a long time it tells that the session is still active
  saveUninitialized:false//it is used not to have empty session store in the cookie
}))

app.use(passport.initialize());//passport is authetication middleware for node taht uses cookie authentication
app.use(passport.session());//deserialize the user object



mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema=new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

      //Mongoose Encryption.............
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=new mongoose.model("user",userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, cb) {
   cb(null,  user.id);
});

passport.deserializeUser(function(id, cb) {
  User.findById(id,function(err,user) {
     cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));




app.get("/",function(req,res){
  res.render("home");
})

// app.get("/auth/google",function(req,res){
//   passport.authenticate("google",{scope:['profile']})
// })

app.get('/auth/google',
  passport.authenticate('google', { scope:
      ['profile' ] }
));

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {failureRedirect: '/login'}),
    function(req,res){
      res.redirect("/secrets");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.post("/register",function(req,res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets")
      })
    }
  })
})
app.get("/secrets",function(req,res){
  if (req.isAuthenticated()){
    User.find({"secret":{$ne:null}},function(err,foundUsers){
      if(err){
        console.log(err);
      }
      else{
          // console.log(foundUsers);
          res.render("secrets",{usersWithSecrets:foundUsers});

      }
    })
  }
  else{
    res.redirect("/login")
  }
})

app.get("/submit",function(req,res){
  if (req.isAuthenticated()){
    res.render("submit")
  }
  else{
    res.redirect("/login")
  }
})


app.post("/submit",function(req,res){
  const submittedSecret=req.body.secret;
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  })

})

app.get("/logout",function(req,res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }
    else{
      res.redirect("/")
    }
  });
});

app.post("/login",function(req,res){
  const user=new User({
    username:req.body.username,
    password:req.body.password
  })

  req.login(user,function(err){
    if(err){
      console.log(err);
      res.redirect("/login")
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets")
      })
    }
  })
})











app.listen(3000,function(){
  console.log("server started successfully started in port 3000");
})


//register bcrypt code.......................
//   bcrypt.hash(req.body.password,saltRounds,function(err,hash){
//   const newUser=new User({
//     email:req.body.username,
//     password:hash
//   })
//
//   newUser.save(function(err){
//     if(err){
//       console.log(err);
//     }
//     else{
//       res.render("secrets");
//     }
//   })
// })




//login bcrypt code.............................
// const username=req.body.username
// const password=req.body.password;
//
// User.findOne({email:username},function(err,foundUser){
//   if(err){
//     console.log(err);
//   }
//   else{
//     if(foundUser){
//       // if(foundUser.password === password){
//         bcrypt.compare(password,foundUser.password,function(err,result){
//           if (result===true){
//             res.render("secrets")
//           }
//         })
//       }
//     }
//   }
// )
