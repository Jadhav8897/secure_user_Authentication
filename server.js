const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "secret-key-123",
  resave: false,
  saveUninitialized: false
}));

let users = []; // demo storage

/* REGISTER */
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  const hash = await bcrypt.hash(password, 10);

  users.push({
    username,
    password: hash,
    role: role || "user"
  });

  res.redirect("/login.html");
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.send("User not found");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.send("Wrong password");

  req.session.user = user;
  res.redirect("/dashboard.html");
});

/* PROTECTED ROUTE */
app.get("/profile", (req, res) => {
  if (!req.session.user) {
    return res.status(401).send("Unauthorized");
  }
  res.json(req.session.user);
});

/* ROLE BASED ROUTE */
app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.send("Access denied");
  }
  res.send("Welcome Admin Panel");
});

/* LOGOUT */
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login.html");
});

app.listen(3000, () => console.log("Auth server running on 3000"));