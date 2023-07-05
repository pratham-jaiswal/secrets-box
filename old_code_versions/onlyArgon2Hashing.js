const express = require('express');
const mongoose = require("mongoose");
const argon2 = require('argon2');
const crypto = require('node:crypto');
const app = express();
require("dotenv").config();

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

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

app.get("/", function(req, res) {
    return res.render("home");
});

app.route("/register")
.get(function(req, res) {
    return res.render("register", { err: null });
})
.post(async function(req, res) {
    let { email, password} = req.body;
    if (!email || !password){
        return res.render("register", { err: "Error: Email or Password cannot be empty." });
    }

    let findEmail;
    try{
        findEmail = await User.findOne({ email: email })
    }
    catch(err){
        console.error(err);
        return res.render("register", { err: "Error: Something went wrong. Please try again." });
    }

    if(findEmail){
        return res.render("register", { err: "Error: The email you entered is already registered" });
    }

    let salt = crypto.randomBytes(32).toString("hex");

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
        return res.redirect("/secrets");
    } catch (err) {
        console.error(err);
        return res.render("register", { err: "Error: Something went wrong. Please try again." });
    }
});

app.route("/login")
.get(async function(req, res) {
    return res.render("login", { err: null });
})
.post(async function(req, res) {
    let { email, password} = req.body;
    if (!email || !password){
        return res.render("login", { err: "Error: Email or Password cannot be empty." });
    }

    let findEmail;
    try{
        findEmail = await User.findOne({ email: email })
    }
    catch(err){
        console.error(err);
        return res.render("login", { err: "Error: Something went wrong. Please try again." });
    }

    if(!findEmail){
        return res.render("login", { err: "Error: The email or password you entered is incorrect" });
    }

    try {
        const isPasswordValid = await argon2.verify(findEmail.password.toString('utf8'), password);
        if (!isPasswordValid) {
            return res.render("login", { err: "Error: The email or password you entered is incorrect" });
        }

        return res.redirect("/secrets");
    } catch (err) {
        console.error(err);
        return res.render("login", { err: "Error: Something went wrong. Please try again." });
    }
});

app.get("/secrets", async function(req, res) {
    const users = await User.find({secret: {$ne: null}}).exec();
    return res.render("secrets", { err: "Error: Something went wrong. Please try again.", users: users });
});

app.route("/submit")
.get(async function(req, res) {
    return res.render("submit", { err: null });
})
.post(async function(req, res) { // won't work without sessions
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
    }
    try{
        let updtUser = await User.findOneAndUpdate(
            { username: "anonymous" }, 
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

app.post("/comment", async function(req, res) {
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

app.get("/logout", function(req, res) { // won't work without sessions
    return res.redirect("/");
});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});