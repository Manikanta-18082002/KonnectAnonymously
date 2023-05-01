//jshint esversion:6

//We are not setting a const bcz we just need to require it and then call config 
//on it and we dont need it again it will be active and running
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const absoluteURI = 'http://localhost:5000/';

//Password + salt ===> Hash code (Both Salt and hash code stores in DB)
//const bcrypt = require("bcrypt");         //17,000 bcrypt Hashese/Second
//const saltrounds = 10; //3rd)If increase in number (10) harder to our PC to generated the hash functions
//Instead of changin the hash func every time just increase the salt rounds 


//Password + Hash Function ===> Hash        //(20 Billion) 20,00,00,00,000 MD5 Hashes/Second
//const md5 = require("md5"); //2nd)Encrypt type easy (Hash function (MD5))  but IMPOSSIBLE to decrypt (Back to Hash Function)

//const encrypt = require("mongoose-encryption"); //1st)Encrypt type: Password + Secret_Key ==> Cipher Method(Caesar/ AEs) ====> Cipher text

const app = express(); //Creating a new app instance using express

//console.log(md5("123456"));  //This will generate a Hash Code for this input password
app.use(express.static("public")); //Creating a public directory to store static files (CSS files, Images)

app.set('view engine', 'ejs'); //Tells express to use EJS as the view engine for rendering dynamic HTML pages


app.use(bodyParser.urlencoded({ //To parse incoming request bodies that are in URL encoded format
    extended: true
}));

//Should place above mongoose.connect
app.use(session({ //Use the session package from above Line 11
    secret: "My little secret.", //And we set it some some initial configuration
    resave: false,
    saveUninitialized: false,
    //cookie: {secure: true} //when  secure is set, and you access your site over HTTP, the cookie will not be set
    // cookie: {} //sometimes removing cookie option might affect the program
}));

app.use(passport.initialize()); //We tell our passport to initialize the passport package for authentication
//Now telling our app to use passport & set up our session
app.use(passport.session());
//Finally Adding passport-local-mongoose package as a plugin to our mongoose schema just like we did for mongoose encryption package L54-59

mongoose.connect("mongodb+srv://manireddy18082002:Anonymus@anonymus.tvjt3cd.mongodb.net/test", { useNewUrlParser: true });
//mongoose.set("useCreateIndex", true); //TO disappear Deprication Warning

const userSchema = new mongoose.Schema({ //A proper mongoose schema to use plugin, but not a simple JS obj with out mongoose.Schema
    email: String,
    password: String,
    googleId: String,
    secret: String
});
//Now taping into userSchema and add plugin to it(mongoose schema)
//This we are going to use hash and salt our passwords and to save our users into our MongoDB database.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Used to check the .env file required or not
//console.log(process.env.API_KEY);

//Put this in .env file
//const secret = "Thisismysecret";  //Hacker will easily fetch into app.js FILE and access this ENCRYPTION(Secret) key & easily decrypt passwords
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); //plugin should add before we create our mongoose model. Encrypt only certain fields.    ////An encryption secure key for (caesar cipher)  //Without (encryptedFields) it will encrypt entire DB

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //We create a Passport to create a local-mongoose strategy

/*Outdated way of serial/deserializing --> from (passport-local-mongoose) --> works for only local strategies

//Serialize means it creates the cookie and stuffs the message into it. Namely our users identifications into the cookie
passport.serializeUser(User.serializeUser());  

//Deserialize means it allows passport to be able to crush/open the cookie and discover the message inside it.(to find the user).
passport.deserializeUser(User.deserializeUser());
*/

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

///////////   Configure strategy for passport google OAuth 2.0   //////
//Auth Code ===> Like ticket(Admit one),  Access token ===> Yearly Pass
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        //callbackURL: absoluteURI + "/auth/google/secrets",
        callbackURL: "http://localhost:3000/auth/google/secrets",
        proxy: true,
        userProfileURL: "https://www.googleapis.com/oauth2/v3userinfo" //Why this? //since google+ is (new)sunsetting, the routes will get adjusted through this route. This line from GitHub
    },
    function(accessToken, refreshToken, profile, cb) { //AccessToken : To access the users data for a longer period of time
        console.log(profile);
        ////(findOrCreate) is not a standard function in mongoose. So install additional package to make it work
        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function(req, res) {
    res.render("home");
});
//Inside here we initiate our authentication with google.
app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] }) //Authenticating the user with google strategy 
    //Here we are saying, use passport to authenticate our user using the google strategy. And scope means, what we want is users profile.
    //So this below line of code brings up the pop up that allows the user to sign into their gmail account 

);

//after successful authentication, google will redirect to following route
//Here we authenticate them locally and save their login session
app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect to secrets Page
        res.redirect("/secrets"); //Go to below secrets line
    });

app.get("/login", function(req, res) {
    res.render("login");
});
app.get("/register", function(req, res) {
    res.render("register");
});

/*app.get("/secrets", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.render("/login");
    }
}); */

app.get("/secrets", function(req, res) {
    /* //Now we no longer need authentication to see the secrets. Because anyone anonymously can see the secrets.
    //But instead we go through our DB at find all the secret that have been submitted on the Database
    if (req.isAuthenticated()) { //The “req. isAuthenticated()” function can be used to protect routes that can be accessed only after a user is logged in eg. dashboard.
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
    */
    //This may still have a null value.
    //User.find({"secret" : {$exists:true}});
    //This will check non null values -->having value for "secret" attribute
    User.find({ "secret": { $ne: null } })
        .then(function(foundUser) {
            if (foundUser) {
                res.render("secrets", { usersWithSecrets: foundUser });
            }
        })
        .catch(function(err) {
            console.log(err);
        });
});

//after logging in, then submit a secret.
app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});
//Updating the secrets and saving them to users DB and showing them on secrets page
app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret; //Saving the secret

    //passport catches and saves the users details, Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    console.log(req.user.id);
    User.findById(req.user.id)
        .then(function(foundUser) {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save()
                    .then(function() {
                        res.redirect("/secrets");
                    })
                    .catch(function(err) {
                        console.log(err);
                    });
            }
        })
        .catch(function(err) {
            console.log(err);
        });

});

//Here we de-Authenticate our user and end that user session
app.get("/logout", function(req, res) {
    // A predefined function in passport.js documentation - req.logout must need a callback function
    req.logout(function(err) {
        if (err)
            console.log(err);
        else
            res.redirect("/");
    });
});

//catches the request from register page through submit button and then posts something onto in
//Just registering but not LOGIN by user
app.post("/register", function(req, res) { //Here user can register but cannot LOGIN, (Getting Email, Password from register page (name) )

    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });

    /*
    //////////               If user not exists Create a new user --MD5 hashing            ///////////
    bcrypt.hash(req.body.password, saltrounds, function(err, hash) { //password + salt = hash func
        const newUser = new User({
            email: req.body.username,
            password: hash //md5(req.body.password)
        });
        //Mongoose does not support using a callback with the Model.save() method. Modify our code to use Promises instead of callbacks. 
        newUser.save() //Behind the seen the mongoose-encrypt will encrypt the password
            .then(function() {
                res.render("secrets"); //GO to Secrets page
            })
            .catch(function(err) {
                console.log(err);
            });
    });*/

});

app.post("/login", function(req, res) { //Getting Email, Password from login page

    const user = new User({
        username: req.body.username,
        password: req.body.password //If registered password == to user typed password
    });

    req.login(user, function(err) { //login() method comes from passport
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});
/*
    const username = req.body.username; 
    const password = req.body.password;
    
//Below is salt + hashing function
    //Here mongoose-encrypt will DE-CRYPT the password for find()
    User.findOne({ email: req.body.username })  //Encrypt => save(),  Decrypt => find()
        .then(foundUser => {
            if (foundUser) {         //Uses bcrypt for salting and hashing to check valid user?
                bcrypt.compare(password, foundUser.password)
                    .then(result => {
                        if (result === true)
                            res.render("secrets");
                    })
                    .catch(err => {
                        console.log(err);
                    });
            }
        })
        .catch(err => {
            console.log(err);
        });
});*/

//If user try to Login again using  Login Password we again hash that password and compare this hash with our DB hash. If that 2 hashes match then Correct user

//Uses MD5  for simple hashing  
// if(foundUser.password === md5(req.body.password)){
//     res.render("secrets");
// }


/* User.findOne({ email: username })  //Does DB Email == user typing email???
        .then(function(foundUser) {  
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render("secrets");
                } else {
                    res.send("Invalid password.");
                }
            } else {
                res.send("User not found.");
            }
        })
        .catch(function(err) {
            console.log(err);
        });
*/
// Below is Older version 4.0, Mongoose no longer supports passing a callback use Promises instead of callbacks. 
/*  User.findOne({ email: username }, function(err, foundUser) {
      if (err) {
          console.log(err);
      } else {
          if (foundUser) {
              if (foundUser.password == password) {
                  res.render("secrets");
              }
          }
      }
  });
  */
//});


app.listen(5000, function() {

    console.log("Server started on port 5000");

});