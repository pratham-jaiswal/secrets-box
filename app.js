const express = require('express');
const mongoose = require("mongoose");
const argon2 = require('argon2');
const crypto = require('node:crypto');
const { body, validationResult } = require('express-validator');
const mongoSanitize = require("express-mongo-sanitize");
const csrf = require("csurf");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const passport = require('passport');
const LocalStrategy = require('passport-local');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
var GitHubStrategy = require("passport-github2").Strategy
const session = require('express-session');
const findOrCreate = require('mongoose-findorcreate');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();
require("dotenv").config();

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'", "ka-f.fontawesome.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "kit.fontawesome.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
        },
    })
);

const csrfProtection = csrf({ cookie: true });
const rateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
});

app.use(passport.initialize());
app.use(passport.session());

app.use(csrfProtection);

mongoose.connect("mongodb://localhost:27017/secretsDB",{
    family: 4,
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: String,
    googleId: String,
    facebookId: String,
    githubId: String,
    secret: [{
        content: String,
        comments: [String]
    }]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// passport.use(User.createStrategy());

passport.use(new LocalStrategy(
    async function verify(username, password, done) {
        try {
            const user = await User.findOne({ username: username });
            if (!user || !(await argon2.verify(user.password, password))) {
                return done(null, false);
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(async function (id, done) {
    let err, user;
    try {
        user = await User.findById(id).exec();
    }
    catch (e) {
        err = e;
    }
    done(err, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_REDIRECT_URI
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
}));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_REDIRECT_URI
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: process.env.GITHUB_REDIRECT_URI
    },
    function(accessToken, refreshToken, profile, done) {
        let username;
        if (profile.emails && profile.emails.length > 0) {
            username = profile.emails[0].value
        }
        else{
            username = profile.username
        }

        User.findOne({ $or: [{ username: username }, { githubId: profile.id }] }).exec()
        .then(user => {
            if (user) {
                return done(null, user);
            } else {
                return User.create({ username: username, githubId: profile.id })
                    .then(newUser => {
                        return done(null, newUser);
                    });
            }
        })
        .catch(err => {
            return done(err);
        });
    }
));

User.register = async function(username, password, callback) {
    try {
        let salt = crypto.randomBytes(32).toString("hex");
        const hashedPassword = await argon2.hash(password, {
            type: argon2.argon2id,
            salt: Buffer.from(salt, 'hex'),
            timeCost: parseInt(process.env.TIME_COST),
            memoryCost: parseInt(process.env.MEMORY_COST),
            parallelism: parseInt(process.env.PARALLELISM),
            hashLength: parseInt(process.env.HASHLENGTH)
        });
        const user = new User({ username: username });
        user.password = hashedPassword;
        await user.save();
        callback(null, user);
    }
    catch (err) {
        callback(err);
    }
};

app.get("/", function(req, res) {
    return res.render("home");
});

app.route("/register")
.get(function(req, res) {
    if (req.isAuthenticated()) {
        return res.redirect("secrets");
    }
    return res.render("register", { err: null, csrfToken: req.csrfToken() });
})
.post([
        body("username").isEmail().normalizeEmail(),
        body("password").isLength({ min: 8 }),
    ],
    csrfProtection,
    rateLimiter,
    async function(req, res) {
        if (req.isAuthenticated()) {
            return res.redirect("/secrets");
        }
        let { username, password } = req.body;
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render("register", { err: "Error: Invalid email or password.", csrfToken: req.csrfToken() });
        }
        
        if (!username || !password){
            return res.render("register", { err: "Error: Email or Password cannot be empty.", csrfToken: req.csrfToken() });
        }

        let findUser;
        try{
            findUser = await User.findOne({ username: username })
        }
        catch(err){
            console.error(err);
            return res.render("register", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }

        if(findUser){
            return res.render("register", { err: "Error: The email you entered is already registered", csrfToken: req.csrfToken() });
        }

        try {
            User.register(username, password, async (err, user) => {
                if (err) {
                    console.error(err);
                    return res.render("register", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
                }
                passport.authenticate("local")(req, res, () => {
                    req.login(user, (err) => {
                        if (err) {
                            return next(err);
                        }
                        return res.redirect('/secrets');
                    });
                });
            });
        }
        catch (err) {
            console.error(err);
            return res.render("register", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }        
    }
);

app.route("/login")
.get(async function(req, res) {
    if (req.isAuthenticated()) {
        return res.redirect("secrets");
    }
    return res.render("login", { err: null, csrfToken: req.csrfToken() });
})
.post([
        body("username").isEmail().withMessage("Invalid email").normalizeEmail(),
        body("password").notEmpty().withMessage("Password is required"),
    ],
    csrfProtection,
    rateLimiter,
    async function(req, res) {
        if (req.isAuthenticated()) {
            return res.redirect("/secrets");
        }
        let { username, password } = req.body;
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render("register", { err: "Error: Invalid email or password.", csrfToken: req.csrfToken() });
        }
        
        if (!username || !password){
            return res.render("login", { err: "Error: Email or Password cannot be empty.", csrfToken: req.csrfToken() });
        }

        let findUser;
        try{
            findUser = await User.findOne({ username: username })
        }
        catch(err){
            console.error(err);
            return res.render("login", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }

        if(!findUser){
            return res.render("login", { err: "Error: The email or password you entered is incorrect", csrfToken: req.csrfToken() });
        }

        try {
            const user = new User({
                username: username,
                password: password
            });

            passport.authenticate('local', (err, user, info) => {
                if (err) {
                    return next(err);
                }
            
                if (!user) {
                    return res.render('login', { err: 'Error: The email or password you entered is incorrect.', csrfToken: req.csrfToken() });
                }

                req.login(user, (err) => {
                    if (err) {
                        return next(err);
                    }
                    return res.redirect('/secrets');
                });
            })(req, res);           
        } 
        catch (err) {
            console.error(err);
            return res.render("login", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }
    }
);

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => { return res.redirect("/secrets") });

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ["email"] }));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => { return res.redirect("/secrets") });

app.get('/auth/github', passport.authenticate('github', { scope: ["user"] }));

app.get("/auth/github/callback", passport.authenticate("github", { failureRedirect: "/login" }), (req, res) => { return res.redirect("/secrets") });

app.get("/secrets", async function(req, res) {
    if (req.isAuthenticated()) { 
        const users = await User.find({secret: {$ne: null}}).exec();
        return res.render("secrets", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken(), users: users });
    }
    return res.redirect("/login");
});

app.route("/submit")
.get(async function(req, res) {
    if (req.isAuthenticated()) {
        return res.render("submit", { err: null, csrfToken: req.csrfToken() });
    }
    return res.redirect("/login");
})
.post(async function(req, res) {
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
    }
    try{
        let updtUser = await User.findOneAndUpdate(
            {username: req.user.username},
            { $push: { secret: { content: req.body.secret } } },
            { new: true }
        );

        if (updtUser) {
            req.login(updtUser, function(err) {
                if (err) {
                    console.error(err);
                    return res.render("submit", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
                }
                return res.redirect("/secrets");
            });
        }
        else {
            return res.render("submit", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }
    }
    catch (err) {
        console.error(err);
        return res.render("submit", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
    }
});

app.post("/comment", async function(req, res) {
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
    }

    const secretId = req.body.secretId;
    const comment = req.body.addComment;
    const username = req.body.username;
    try{
        const user = await User.findOneAndUpdate(
            {
                username: username,
                "secret._id": secretId
            },
            {
                $push: { "secret.$.comments": comment }
            },
            { new: true }
        );
        if (user) {
            return res.redirect("/secrets");
        }
        else {
            return res.render("secrets", { error: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
        }
    }
    catch (err) {
        console.error(err);
        return res.render("/secrets", { err: "Error: Something went wrong. Please try again.", csrfToken: req.csrfToken() });
    }

})

app.get("/logout", function(req, res) {
    req.logout(err => {
        if (err) {
            return next(err)
        }
        return res.redirect("/");
    });
});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});