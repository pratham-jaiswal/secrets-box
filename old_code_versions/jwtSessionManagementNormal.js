const express = require('express');
const mongoose = require("mongoose");
const argon2 = require('argon2');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require("cookie-parser");

const app = express();
require("dotenv").config();

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

mongoose.connect("mongodb://localhost:27017/secretsDB",{
    family: 4,
});

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
});

const User = mongoose.model("User", userSchema);

const authenticateToken = (req, res, next) => {
    const token = req.cookies.jwtToken;
  
    if (token == null)
      return res.redirect("/login");
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error(err);
            return res.redirect("/login");
        }
    
        req.user = user;
        next();
    });
};

app.get("/", function(req, res) {
    return res.render("home");
});

app.route("/register")
.get(function(req, res) {
    const token = req.cookies.jwtToken;
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return res.redirect("/secrets"); 
        } catch (err) {
            return res.render("register", { err: null });
        }
    }
    return res.render("register", { err: null });
})
.post(async function(req, res) {
    let { email, password} = req.body;
    if (!email || !password){
        return res.render("register", { err: "Error: Email or Password cannot be empty." });
    }

    let findUser;
    try{
        findUser = await User.findOne({ email: email })
    }
    catch(err){
        console.error(err);
        return res.render("register", { err: "Error: Something went wrong. Please try again." });
    }

    if(findUser){
        return res.render("register", { err: "Error: The email you entered is already registered" });
    }

    let salt = crypto.randomFillSync(Buffer.alloc(32)).toString("hex");

    try {
        const hashedPassword = await argon2.hash(password, {
            type: argon2.argon2id,
            salt: Buffer.from(salt, 'hex'),
            timeCost: parseInt(process.env.TIME_COST),
            memoryCost: parseInt(process.env.MEMORY_COST),
            parallelism: parseInt(process.env.PARALLELISM),
            hashLength: parseInt(process.env.HASHLENGTH)
        });

        let newUser = new User({
            email: email,
            password: hashedPassword,
        });

        await newUser.save();

        const token = jwt.sign({ userID: newUser._id }, process.env.JWT_SECRET, { algorithm: 'HS512' })
        res.cookie("jwtToken", token, {
            httpOnly: true,
            secure: Boolean(process.env.SECURE_COOKIE),
            sameSite: "strict",
        });
        return res.redirect("/secrets"); //.set('authorization', token);
    } 
    catch (err) {
        console.error(err);
        return res.render("register", { err: "Error: Something went wrong. Please try again." });
    }
});

app.route("/login")
.get(async function(req, res) {
    const token = req.cookies.jwtToken;
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return res.redirect("/secrets"); 
        } catch (err) {
            return res.render("login", { err: null });
        }
    }
    return res.render("login", { err: null });
})
.post(async function(req, res) {
    let { email, password} = req.body;
    
    if (!email || !password){
        return res.render("login", { err: "Error: Email or Password cannot be empty." });
    }

    let findUser;
    try{
        findUser = await User.findOne({ email: email })
    }
    catch(err){
        console.error(err);
        return res.render("login", { err: "Error: Something went wrong. Please try again." });
    }

    if(!findUser){
        return res.render("login", { err: "Error: The email or password you entered is incorrect" });
    }

    try {
        const isPasswordValid = await argon2.verify(findUser.password.toString('utf8'), password);
        if (!isPasswordValid) {
            return res.render("login", { err: "Error: The email or password you entered is incorrect" });
        }

        const token = jwt.sign({ userID: findUser._id }, process.env.JWT_SECRET, { algorithm: 'HS512' })
        res.cookie("jwtToken", token, {
            httpOnly: true,
            secure: Boolean(process.env.SECURE_COOKIE), // true - https connectons only, false - http allowed, keep `false` for localhosts
            sameSite: "strict",
        });
        return res.redirect("/secrets"); //.set('authorization', token);
    } 
    catch (err) {
        console.error(err);
        return res.render("login", { err: "Error: Something went wrong. Please try again." });
    }
});

app.get("/secrets", authenticateToken, async function(req, res) {
    const users = await User.find({secret: {$ne: null}}).exec();
    return res.render("secrets", { err: "Error: Something went wrong. Please try again.", users: users });
});

app.route("/submit")
.get(authenticateToken, function(req, res) {
    return res.render("submit", { err: null });
})
.post(authenticateToken, async function(req, res) {
    try{
        let updtUser = await User.findOneAndUpdate(
            { id: req.cookies.jwtToken.userID }, 
            { $push: { secret: { content: req.body.secret } } },
            { new: true }
        );

        if (updtUser) {
            return res.redirect("/secrets");
        }
        else {
            return res.render("submit", { err: "Error: Something went wrong. Please try again." });
        }
    }
    catch (err) {
        console.error(err);
        return res.render("submit", { err: "Error: Something went wrong. Please try again." });
    }
});

app.post(authenticateToken, "/comment", async function(req, res) {
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
            return res.render("secrets", { error: "Error: Something went wrong. Please try again." });
        }
    }
    catch (err) {
        console.error(err);
        return res.render("/secrets", { err: "Error: Something went wrong. Please try again." });
    }

})

app.get("/logout", function(req, res) {
    res.clearCookie("jwtToken");
    return res.redirect("/");
});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});