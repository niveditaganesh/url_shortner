require("dotenv").config();
const express = require("express");
const mongodb = require("mongodb");
const nodemailer = require("nodemailer");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cryptoRandomString = require("crypto-random-string");
const jwt = require('jsonwebtoken');

const hashHelper = require("./helpers/hashing");
const mailHelper = require("./helpers/mailer");
const registered = require("./middleware/registeredUser");
const activated = require("./middleware/activatedUser");
const checkUser = require("./middleware/checkUser");
const checkPassword = require("./middleware/passwordCheck");

const mongoClient = mongodb.MongoClient;
const objectID = mongodb.ObjectID;
const app = express();
const dbUrl = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const dbName = process.env.DB_NAME;
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

app.post("/register", [registered, checkPassword], async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        req.body.password = await hashHelper.generateHash(req.body.password);
        req.body.isActivated = false;
        delete req.body.confirm_password;
        let message = 'Click the below link to activate your account.';
        let apiLink = 'http://localhost:3000/activate?activation_string';
        req.body.activationString = await mailHelper(message, req.body.email, apiLink);
        await db.collection("users").insertOne(req.body);
        res.status(200).json({
            status: "success",
            message: "Account created. Please check your email for the link to activate your account."
        });
        clientInfo.close();
    } catch (error) {
        console.log(error)
        res.status(500).json({
            error
        });
    }
});

app.post("/login", [checkUser, activated], async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let data = await db.collection('users').findOne({
            email: req.body.email
        });
        let passwordMatch = await hashHelper.compareHash(req.body.password, data.password);
        if (passwordMatch) {
            let token = jwt.sign({
                userId: data._id,
                iat: Date.now()
            }, process.env.JWT_KEY);
            res.json({
                status: "success",
                message: "Login successful",
                userId: data._id,
                token
            });
        } else {
            res.json({
                status: "failed",
                message: "Please check your password and try again."
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});

app.get("/verify/:id", async (req, res) => {
    try {
        let decodedData = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
        if (decodedData.userId == req.params.id) {
            let clientInfo = await mongoClient.connect(dbUrl);
            let db = clientInfo.db(dbName);
            let data = await db.collection('users').findOne({
                _id: objectID(req.params.id)
            });
            if (data) {
                res.status(200).json({
                    status: "success",
                    is_loggedIn: true
                });
            } else {
                res.status(400).json({
                    status: "failed",
                    is_loggedIn: false
                });
            }
        } else {
            res.status(400).json({
                status: "failed",
                is_loggedIn: false
            });
        }
    } catch (error) {
        // console.log(error);
        res.status(400).json({
            status: "failed",
            error
        });
    }
});

app.get("/activate", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let data = await db.collection('users').findOne({
            activationString: req.query.activation_string
        });
        if (data) {
            await db.collection('users').updateOne({
                _id: objectID(data._id)
            }, {
                $set: {
                    activationString: '',
                    isActivated: true
                }
            });
            res.send(`<p>Account activated. Click
                <a href="https://ui-short-url.netlify.app/login.html">here</a> to login.</p>`);
        } else {
            res.send('<p>link expired</p>')
        }
    } catch (error) {
        console.log(error);
        res.status(400).json({
            error
        });
    }
});

app.post("/password/forgot", [checkUser], async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let result = await db.collection("users").findOne({
            email: req.body.email
        });

        if (result) {
            let message = 'Click the below link to reset your password. It is one-time link, once you changed your password using the link, it will be expired.';
            let apiLink = 'http://localhost:3000/password/check/token?reset_string';
            req.body.resetString = await mailHelper(message, req.body.email, apiLink, result._id);
            await db.collection("users").updateOne({
                _id: result._id
            }, {
                $set: {
                    reset_string: req.body.resetString
                }
            });

            res.status(200).json({
                status: "success",
                message: "Reset password link is sent to your email account."
            });
        } else {
            res.status(400).json({
                status: "failed",
                message: "No user with this email found. Please provide the registered email. "
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});

app.get("/password/check/token", async (req, res) => {
    try {
        let str = req.query.reset_string.split('_._');
        let resetString = str[0];
        let uid = str[1];
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let result = await db.collection("users").findOne({
            $and: [{
                _id: objectID(uid)
            }, {
                reset_string: resetString
            }]
        });

        if (result) {
            res.redirect(`https://ui-short-url.netlify.app/reset_password.html?uid=${uid}`);
        } else {
            res.send('link expired');
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
    }
});

app.post("/password/reset/:uid", [checkPassword], async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let result = await db.collection("users").findOne({
            _id: objectID(req.params.uid)
        });
        if (result) {
            req.body.password = await hashHelper.generateHash(req.body.password);
            await db.collection("users").updateOne({
                _id: objectID(req.params.uid)
            }, {
                $set: {
                    reset_string: '',
                    password: req.body.password
                }
            })
            res.status(200).json({
                status: 'success',
                message: 'password changed successfully'
            });
        } else {
            res.status(410).json({
                status: 'failed',
                message: "User not found"
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
    }
});

app.post("/short-url", async (req, res) => {
    try {
        let decodedData = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
        let str = cryptoRandomString({
            length: 8,
            type: 'url-safe'
        });
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let data = await db.collection('urls').insertOne({
            uid: objectID(decodedData.userId),
            long_url: req.body.long_url,
            short_url_code: str
        });
        res.json({
            status: "success",
            message: "short url generated"
        })
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});

app.get("/:code", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let data = await db.collection('urls').findOne({
            short_url_code: req.params.code
        });
        if (data) {
            res.redirect(data.long_url);
        } else {
            res.status(400).json({
                status: "failed",
                message: "wrong short-url"
            })
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});

app.get("/users/url-data", async (req, res) => {
    try {
        let decodedData = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db(dbName);
        let data = await db.collection('users').aggregate([{
            '$lookup': {
                'from': 'urls',
                'localField': '_id',
                'foreignField': 'uid',
                'as': 'results'
            }
        }, {
            '$match': {
                '_id': objectID(decodedData.userId)
            }
        }]).toArray();
        res.status(200).json({
            status: "success",
            data,
            items: data.length
        });
        clientInfo.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});


app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});