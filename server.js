const express = require("express");
const bodyParser = require("body-parser");
const svgCaptcha = require("svg-captcha");
const session = require("express-session");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const bcrypt = require('bcrypt');

const app = express();

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({ secret: "123", resave: true, saveUninitialized: true }));

app.listen(8000, () => {
  console.log("Server started on http://localhost:8000");
});

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "auth_node",
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL database:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

app.post("/register", registerUser);
app.post("/verify", verifyCaptcha); //udah
app.post("/login", loginUser); //udah
app.post("/activate_tfa", activate2FA); 
app.post("/auth_tfa", auth2FA); //udah
app.post("/login_tfa", login2FA); //udah
app.get("/", generateLogin); //udah
app.get("/register", generateRegister); //udah
app.get("/captcha", generateCaptcha); //udah
app.get("/login", generateLogin); //udah
app.get("/login_tfa", generateLogin2FA); //udah
app.get("/activate_tfa", renderActivate2FA); //udah
app.get("/auth_tfa", generateAuthTfa); //udah
app.get("/home", generateIndex); //udah
app.get("/logout", logoutUser);
// app.post("/disable_2fa", disable2FA);

// register
function registerUser(req, res) {
  const { name, username, email, password } = req.body;
  connection.query("SELECT * FROM users WHERE name = ? OR username = ? OR email = ?", [name, username, email], (err, results) => {
      if (err) {
          console.error("Error querying user from MySQL database:", err);
          return res.status(500).send("Internal Server Error");
      }
      if (results.length > 0) {
          return res.json({ success: false, msg: "Username or email already exists" });
      } else {
          connection.query("INSERT INTO users (name, username, email, password) VALUES (?, ?, ?, ?)", [name, username, email, password], (err, result) => {
              if (err) {
                  console.error("Error inserting user into MySQL database:", err);
                  return res.status(500).send("Internal Server Error");
              }
              res.json({ success: true, msg: "User registered successfully" });
          });
      }
  });
}

function generateRegister(req, res) {
  res.sendFile(__dirname + "/views/register.html");
}

// login
function loginUser(req, res) {
  const { username, password, captcha } = req.body;
  req.session.failedLoginAttempts = req.session.failedLoginAttempts || 0;
  if (req.session.failedLoginAttempts >= 3) {
      if (!captcha || captcha !== req.session.captcha) {
          return res.json({ success: false, msg: "Failed captcha verification" });
      }
  }
  connection.query("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, results) => {
      if (err) {
          console.error("Error querying user from MySQL database:", err);
          return res.status(500).send("Internal Server Error");
      }
      if (results.length > 0) {
          req.session.email = results[0].email;
          req.session.userId = results[0].id;
          if (results[0].is_tfa) {
              return res.json({ success: true, msg: "Success", redirectUrl: "/login_tfa" });
          } else {
              return res.json({ success: true, msg: "Success", redirectUrl: "/activate_tfa" });
          }
      } else {
          res.status(401);
          req.session.failedLoginAttempts++;
          res.json({
              success: false,
              msg: "Invalid username or password",
              failedLoginAttempts: req.session.failedLoginAttempts,
          });
      }
  });
}

function generateLogin(req, res) {
  res.sendFile(__dirname + "/views/login.html");
}

function login2FA(req, res) {
  if (!req.session.email) {
      return res.redirect("/");
  }
  const email = req.session.email;
  const code = req.body.code;
  return verifyLogin(email, code, req, res, "/views/login_tfa.html");
}

function generateLogin2FA(req, res) {
  if (!req.session.userId) {
      return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/login_tfa.html");
}

function verifyLogin(email, code, req, res, failUrl) {
  connection.query("SELECT tfa_secret, is_tfa FROM users WHERE email = ?", [email], (err, result) => {
      if (err) {
          throw err;
      }

      const row = result[0];
      if (!row) {
          return res.redirect("/");
      }

      if (!authenticator.check(code, row.tfa_secret)) {
          return res.redirect(failUrl);
      }

      req.session.qr = null;
      req.session.email = null;
      req.session.token = jwt.sign(email, "supersecret");

      return res.redirect("/home");
  });
}

// captcha
function verifyCaptcha(req, res) {
  const { captcha } = req.body;
  const sessionCaptcha = req.session.captcha;
  if (!sessionCaptcha || captcha !== sessionCaptcha) {
      return res.json({ success: false, msg: "Failed captcha verification" });
  }
  res.json({ success: true, msg: "Captcha passed" });
}

function generateCaptcha(req, res) {
  const captcha = svgCaptcha.create();
  req.session.captcha = captcha.text;
  res.setHeader("Content-Type", "image/svg+xml");
  res.send(captcha.data);
}

function activate2FA(req, res) {
  const email = req.session.email;
  if (!email) {
      return res.status(400).send("Email not found in session");
  }
  const secret = authenticator.generateSecret();
  connection.query("UPDATE `users` SET `tfa_secret` = ?, `is_tfa` = TRUE WHERE `email` = ?", [secret, email], (err, result) => {
      if (err) {
          throw err;
      }
      const qrCodeUrl = authenticator.keyuri(email, "Coba TFA", secret);
      QRCode.toDataURL(qrCodeUrl, (err, url) => {
          if (err) {
              throw err;
          }
          req.session.qr = url;
          res.redirect("/auth_tfa");
      });
  });
}

// 2FA
function auth2FA(req, res) {
  if (!req.session.email) {
      return res.redirect("/");
  }
  const email = req.session.email;
  const code = req.body.code;
  return verifyLogin(email, code, req, res, "/auth_tfa");
}

function renderActivate2FA(req, res) {
  if (!req.session.userId) {
      return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/activate_tfa.html");
}

function generateAuthTfa(req, res) {
  if (!req.session.qr) {
      return res.redirect("/");
  }
  return res.render("auth_tfa.ejs", { qr: req.session.qr });
}

function disable2FA(req, res) {
  const { email } = req.body; // Mengambil email dari body request
  if (!email) {
      return res.status(400).send("Email not provided");
  }
  connection.query("UPDATE `users` SET `tfa_secret` = NULL, `is_tfa` = FALSE WHERE `email` = ?", [email], (err, result) => {
      if (err) {
          console.error("Error disabling 2FA:", err);
          return res.status(500).send("Internal Server Error");
      }
      res.json({ success: true, msg: "2FA disabled successfully" });
  });
}

// lainnya
function generateIndex(req, res) {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/index.html");
}

function logoutUser(req, res) {
  req.session.destroy();
  return res.redirect("/");
}

function closeConnection() {
  connection.end();
}