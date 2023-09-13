// jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
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

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });


const userSchema = new mongoose.Schema ({
  username: String,
  password: String,
  title: String,
  secret: [
    {
      message: String,
      timestamp: {
        type: Date,
        default: Date.now
      }
    }
  ]
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Define the middleware function to check if a user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/login");
  }
}

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/signup", function(req, res){
  res.render("signup");
});



app.get("/secrets", ensureAuthenticated, function(req, res){
  User.find({"secret": {$ne: null}})
    .then(foundUsers => {
      if (foundUsers) {
        // Precompute "time ago" for each secret
        foundUsers.forEach(user => {
          user.secret.forEach(secret => {
            const now = new Date();
            const messageTime = secret.timestamp;
            const diff = now - messageTime;

            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);

            if (days > 0) {
              secret.timeAgo = `${days} days ago`;
            } else if (hours > 0) {
              secret.timeAgo = `${hours} hours ago`;
            } else if (minutes > 0) {
              secret.timeAgo = `${minutes} minutes ago`;
              if (minutes === 1) {
                secret.timeAgo = `1 minute ago` ;
              }
            } else {
              secret.timeAgo = `${seconds} seconds ago`;
            }
          });
        });

        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    })
    .catch(err => {
      console.log(err);
      res.redirect("/error");
    });
});



app.get("/submit", ensureAuthenticated, function(req, res){
  res.render("submit");
});



app.post("/submit", ensureAuthenticated, function(req, res){
  const submittedSecret = req.body.secret;
  const timestamp = Date.now(); // Get the current timestamp

  User.findById(req.user.id)
    .then(foundUser => {
      if (foundUser) {
        foundUser.secret.push({ message: submittedSecret, timestamp: timestamp });
        return foundUser.save();
      }
    })
    .then(() => {
      res.redirect("/secrets");
    })
    .catch(err => {
      console.error(err);
      res.redirect("/error"); // Redirect to an error page or handle the error as needed
    });
});


app.get("/logout", function(req, res){
  req.logout(function(err) {
    if (err) {
      console.error(err);
    }
    res.redirect("/login");
  });
});

app.post("/signup", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.error(err);
      return res.redirect("/signup");
    }
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  });
});

// Use passport.authenticate as middleware for login route
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});