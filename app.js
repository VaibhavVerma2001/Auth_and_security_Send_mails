const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const flash = require("connect-flash");
const session = require("express-session"); //used in both autentication and flash msg
require('dotenv').config();
// to handle forgot password
const nodemailer = require("nodemailer");
const async = require("async");
const crypto = require("crypto");
const { doesNotMatch } = require("assert");


const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

//middleware for session
app.use(session({
    secret: "Our liitle secret", //add long string from .env
    resave: false,
    saveUninitialized: false
}));

//  initialise passport just below session
app.use(passport.initialize());
app.use(passport.session());


const url = process.env.DB_CONNECT;
mongoose.connect(url);

mongoose.connection
    .once('open', function () {
        console.log('Successfully connected to Database ...');
    })
    .on('error', function (err) {
        console.log(err);
    });

const userSchema = new mongoose.Schema({
    name: String,
    username: String, //email
    password: {
        type: String,
        select: false  // htis will not show password in select (no one can log this)
    },
    // to handle forgot password
    resetPasswordToken: String,
    // to expire that reset link after some time, example after 30 minutes
    resetPasswordExpires: Date
});


userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());




//middleware for connect flash
app.use(flash());

//setting middlware globally
app.use((req, res, next) => {
    res.locals.success_msg = req.flash(('success_msg'));
    res.locals.error_msg = req.flash(('error_msg'));
    // If password and username do not match
    res.locals.error = req.flash(('error'));
    res.locals.currentUser = req.user;
    next();
});

// Checks if user is authenticated
function isAuthenticatedUser(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    else {
        req.flash('error_msg', 'Please Login first to access this page.')
        res.redirect('/login');
    }
}


// GET ROUTES
app.get("/", (req, res) => {
    res.render("login");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get('/dashboard', isAuthenticatedUser, (req, res) => {
    res.render("dashboard");
});

app.get('/forgot', (req, res) => {
    res.render("forgot");
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        else {
            req.session.destroy(); //to destroy current session
            res.redirect('/');
        }
    });
});

app.get('/password/change', isAuthenticatedUser, (req, res) => {
    res.render('changepassword');
});



//POST ROUTES
app.post("/signup", (req, res) => {
    User.register({ username: req.body.username, name: req.body.name }, req.body.password, function (err, user) {
        if (err) {
            console.log(err); //will give error if username already registered
            req.flash("error_msg", "Error" + err);
            res.redirect("/signup");
        }
        else {
            passport.authenticate("local")(req, res, function () {
                req.flash("success_msg", "Account created successfuly");
                res.redirect("/login");
            });
        }
    });
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: 'Invalid email or password. Try Again!!!'
}));


// To handle forgot password
app.post("/forgot", (req, res) => {
    let recoveryPassword = "";
    // we have to pass array of functions, so use async waterfall
    async.waterfall([
        //1st method
        (done) => {
            // 1st generate token that will handle user requests
            crypto.randomBytes(20, (err, buffer) => {
                let token = buffer.toString('hex');
                done(err, token);
            }); //1st arg is no. of  bytes
        },
        //2nd method
        (token, done) => {
            User.findOne({ username: req.body.username }, function (err, user) {
                if (err) {
                    console.log(err);
                }
                else {
                    if (!user) {
                        console.log("User does not exist with this email");
                        req.flash("error_msg", "User does not exist with this email");
                        res.redirect("/forgot");
                    }
                    else {
                        // change userSchema
                        user.resetPasswordToken = token;
                        user.resetPasswordExpires = Date.now() + 1800000; //1.5 hrs after link will expire(in ms)

                        user.save(function (err) {
                            if (err) {
                                console.log(err);
                                req.flash("error_msg", "Error" + err);
                                res.redirect("/forget");
                            }
                            else {
                                done(err, token, user);
                            }
                        });
                    }
                }
            });
        },
        //  3rd method
        (token, user) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });

            let mailOptions = {
                to: user.username,
                from: 'Vaibhav Verma abc@gmail.com',
                subject: 'Recovery Email from Auth Project',
                text: 'Please click the following link to recover your passoword: \n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email.'
            };
            smtpTransport.sendMail(mailOptions, err => {
                req.flash('success_msg', 'Email send with further instructions. Please check that.');
                res.redirect('/forgot');
            });
        }

    ], function (err) {
        if (err) {
            console.log(err);
            res.redirect("/forgot");
        }
    });
});


// after we click on reset password link sent in email
app.get("/reset/:token", (req, res) => {
    // verify user has same token with whom reset link is send
    //ensure link is not expired
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
        if (err) {
            console.log(err);
            req.flash("error_msg", "Error : " + err);
            res.redirect("/forgot");
        }
        else {
            if (!user) {
                req.flash("error_msg", "Password reset token is invalid or expired!");
                res.redirect("/forgot");
            }
            else {
                res.render('resetpassword', { token: req.params.token });
            }
        }
    });
});


//handle reset password form which will open after user clicks on reset password link, reset password and send email that password reset
app.post('/reset/:token', (req, res) => {
    if (req.body.password !== req.body.cpassword) {
        req.flash('error_msg', "Password don't match.");
        res.redirect('/forgot');
    }
    else {
        //waterfall function
        async.waterfall([
            (done) => {
                //check that token exist and not expired 
                User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } })
                    .then(user => {
                        if (!user) {
                            req.flash('error_msg', 'Password reset token in invalid or has been expired.');
                            res.redirect('/forgot');
                        }

                        // to set password
                        user.setPassword(req.body.password, err => {
                            //clear out these 2 fields bec now user resets password
                            user.resetPasswordToken = undefined;
                            user.resetPasswordExpires = undefined;

                            user.save(err => {
                                req.logIn(user, err => {
                                    done(err, user);
                                })
                            });
                        });
                    })
                    .catch(err => {
                        req.flash('error_msg', 'ERROR: ' + err);
                        res.redirect('/forgot');
                    });
            },
            //send mail that password reset successfull
            (user) => {
                let smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: process.env.GMAIL_EMAIL,
                        pass: process.env.GMAIL_PASSWORD
                    }
                });

                let mailOptions = {
                    to: user.username,
                    from: 'Vaibhav Verma vv081515@gmail.com',
                    subject: 'Your password is changed',
                    text: 'Hello, ' + user.name + '\n\n' +
                        'This is the confirmation that the password for your account ' + user.username + ' has been changed.'
                };

                smtpTransport.sendMail(mailOptions, err => {
                    req.flash('success_msg', 'Your password has been changed successfully.');
                    res.redirect('/login');
                });
            }

        ], err => {
            console.log(err);
            res.redirect('/login');
        });
    }
});

//to change password if user want to change after login
app.post('/password/change', (req, res) => {
    if (req.body.password !== req.body.cpassword) {
        req.flash('error_msg', "Password don't match. Type again!");
        res.redirect('/password/change');
    }

    else {
        User.findOne({ username: req.user.username })
            .then(user => {
                user.setPassword(req.body.password, err => {
                    user.save()
                        .then(user => {
                            req.flash('success_msg', 'Password changed successfully.');
                            res.redirect('/dashboard');
                        })
                        .catch(err => {
                            req.flash('error_msg', 'ERROR: ' + err);
                            res.redirect('/password/change');
                        });
                });
            });
    }
});



const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log("Server connected successfully...");
});
