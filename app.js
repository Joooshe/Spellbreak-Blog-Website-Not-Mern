//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// we no longer us md5 because it is too fast
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Make our app use passport so we can use other ways to sign in
app.use(passport.initialize());
app.use(passport.session());

// Connect mongoose to server
const dbName = "gamingBlogUserDB";
const mongoCluster = process.env.MONGO_CLUSTER;
mongoose.connect(mongoCluster+dbName);

// Make schema
const userSchema = new mongoose.Schema({
    email: String,
    userName: String,
    password: String,
    googleId: String,
    posts: [{title: String, content: String}]
});

// Add the way that passport hashes and salts passwords into the schema (doesnt have todo with sessions)
userSchema.plugin(passportLocalMongoose);
// Add function into user schema
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// Makes the passport able to save stuff to the user?
passport.use(User.createStrategy());

// How we make the cookie serialize users
// Code that passport gives us
passport.serializeUser(function(user, done) {
    // Lets serializing users work with any authentification: local, google, facebook
    done(null, user.id);
});
// How we decode the cookie to find who the user is
passport.deserializeUser(function(id, done) {
    // Lets us deserializing users work with any authentification: local, google, facebook
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


// Lets us sign in with google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  // This call back function gets triggered every time passport 
  // creates or logs in a new user 
  function(accessToken, refreshToken, profile, cb) {
    // Either finds the user or creates the user on the data base, and then finds
    // the user. It will then redirect to auth/google/secrets using the user data 
    // - Finds the user by googleId in the schema. If we did not have googleId
    // in the schema then it would just keep creating new users even Vue.config.warnHandler = function (msg, vm, trace) {
    // signing in with the same user
    console.log(profile);
    User.findOrCreate({ googleId: profile.id}, function (err, user) {
      user.userName = profile.displayName;
      user.save();
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.redirect("/home");
});

app.get("/auth/google", 
    // parameter "google" means this is the type of strategy we will use
    // to authenticate our user. The parameter probably looks at some
    // metadata on what called this function and knows to redirect this page
    // to google's sign in page
    // scope: ["profile"] is us telling google that we want to get and use
    // the user's profile from google
    passport.authenticate("google", {scope: ["profile"] })
);

// Now that we are using google OAuth, we are able to authenticate people 
// Using google OAuth
// This path must match what we typed into google's page for using passport
// which should also match what's in the google strategy
app.get("/auth/google/secrets", 
// Authenticates the session using google, the parameter 'google'
// makes it look at the person we just signed in with so we 
// know who they are and that we can authenticate them
// - { failureRedirect: '/login' } redirects to log in on failure
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // If successful authentication, redirect home.
    res.redirect('/profile');
  });

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/login")
    }
})

app.get("/home", async function(req, res) {
    User.find({"posts": {$ne:null}}, function(err, foundUsers) {
        if (err) {
            console.log(err)
        } else {
            res.render("home", {usersWithPosts: foundUsers});
        }
    })
});

app.get("/logout", function(req, res) {
    req.logout(function(err) {
        if (err) {
            console.log(err)
        } else {
            res.redirect("/");
        }
    });
});

app.get("/profile", function(req, res) {
    if(req.isAuthenticated()) {
        const username = req.user.id;
        User.findById(username, function(err, foundUser) {
            if (err) {
             console.log(err);
            } else {
             res.render("profile", {user: foundUser})
            }
         });
    } else {
        res.redirect("/access-account")
    }
})

app.get("/access-account", function(req, res) {
    res.render("access-account");
})

app.post("/submit", function(req, res) {
    const title = req.body.title;
    const content = req.body.content;
    const username = req.user.id;
    // passport saves the users details into the request variable
    User.findById(username, function(err, foundUser) {
       if (err) {
        console.log(err);
       } else {
        foundUser.posts.push({title: title, content: content});
        foundUser.save(function() {
            res.redirect("/profile");
        });
       }
    });

})

app.post("/register", function(req, res) {
    // A passport function that registers our user (we get this function by adding passport as a plugin to our schema)
    // active: false means 
    User.register({username: req.body.username, active: false}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            // Authenticates the user (gives them a session) so they can stay signed in
            passport.authenticate("local")(req, res, function() {
                res.redirect("/profile");
            });
        }
    });
});

app.post("/login", function(req, res) {
    // Create new user schema and log them in
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    // A passport function that logs in our user 
    req.login(user, function(err) {
        if (err) {
            console.log(err);
        } else {
            // Authenticates the user (gives them a session) so they can stay signed in
            passport.authenticate("local")(req, res, function() {
                res.redirect("/profile");
            });
        }
    })
});

app.listen(3000, function() {
    console.log("Server started on port 3000")
});
