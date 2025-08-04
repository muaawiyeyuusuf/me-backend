require("dotenv").config()
const express = require("express")
const jwt = require("jsonwebtoken")
const marked = require("marked")
const sanitizeHTML = require("sanitize-html")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const db = require("better-sqlite3")("ourAppp.db")
db.pragma("journal_mode = WAL")

const app = express()

// 👉 CORS si loo oggolaado frontend-kaaga localhost
app.use(cors({
  origin: "http://127.0.0.1:5500/login.html", // frontend URL
  credentials: true
}))

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(express.static("public"))
app.use(cookieParser())

const createTables = db.transaction(() => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `).run()

  db.prepare(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdDate TEXT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      authorid INTEGER,
      FOREIGN KEY (authorid) REFERENCES users(id)
    )
  `).run()
})

createTables()

app.use(function (req, res, next) {
  res.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: ["p", "br", "ul", "ol", "li", "strong", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
      allowedAttributes: {}
    })
  }

  res.locals.errors = []

  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user = decoded
  } catch (err) {
    req.user = false
  }

  res.locals.user = req.user
  next()
})

app.get("/", (req, res) => {
  if (req.user) {
    const posts = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC").all(req.user.userid)
    return res.render("dashboard", { posts })
  }
  res.render("homepage")
})

app.get("/login", (req, res) => {
  res.render("login")
})

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp")
  res.redirect("/")
})

app.post("/login", (req, res) => {
  let errors = []
  const { username = "", password = "" } = req.body

  if (username.trim() === "" || password === "") {
    errors.push("Invalid username/password.")
    return res.render("login", { errors })
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username)

  if (!user || !bcrypt.compareSync(password, user.password)) {
    errors.push("Invalid username/password.")
    return res.render("login", { errors })
  }

  const token = jwt.sign(
    { userid: user.id, username: user.username },
    process.env.JWTSECRET,
    { expiresIn: "1d" }
  )

  res.cookie("ourSimpleApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  res.redirect("/")
})

function mustBeLoggedIn(req, res, next) {
  if (req.user) return next()
  res.redirect("/")
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  res.render("create-post")
})

function sharedPostValidation(req) {
  const errors = []
  let { title = "", body = "" } = req.body
  title = sanitizeHTML(title.trim(), { allowedTags: [], allowedAttributes: {} })
  body = sanitizeHTML(body.trim(), { allowedTags: [], allowedAttributes: {} })

  if (!title) errors.push("You must provide a title.")
  if (!body) errors.push("You must provide content.")

  req.body.title = title
  req.body.body = body

  return errors
}

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = sharedPostValidation(req)
  if (errors.length) return res.render("create-post", { errors })

  const stmt = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
  const result = stmt.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(result.lastInsertRowid)
  res.redirect(`/post/${post.id}`)
})

app.get("/post/:id", (req, res) => {
  const stmt = db.prepare(`
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.authorid = users.id
    WHERE posts.id = ?
  `)
  const post = stmt.get(req.params.id)
  if (!post) return res.redirect("/")
  const isAuthor = post.authorid === req.user?.userid
  res.render("singel-post", { post, isAuthor })
})

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(req.params.id)
  if (!post || post.authorid !== req.user.userid) return res.redirect("/")
  res.render("edit-post", { post })
})

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(req.params.id)
  if (!post || post.authorid !== req.user.userid) return res.redirect("/")

  const errors = sharedPostValidation(req)
  if (errors.length) return res.render("edit-post", { post, errors })

  db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?").run(req.body.title, req.body.body, req.params.id)
  res.redirect(`/post/${req.params.id}`)
})

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(req.params.id)
  if (!post || post.authorid !== req.user.userid) return res.redirect("/")
  db.prepare("DELETE FROM posts WHERE id = ?").run(req.params.id)
  res.redirect("/")
})

app.post("/register", (req, res) => {
  const errors = []
  let { username = "", password = "" } = req.body
  username = username.trim()

  if (!username) errors.push("Username is required.")
  else if (username.length < 3) errors.push("Username must be at least 3 characters.")
  else if (username.length > 10) errors.push("Username must be under 10 characters.")
  else if (!username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username must be alphanumeric.")

  if (!password) errors.push("Password is required.")
  else if (password.length < 8) errors.push("Password must be at least 8 characters.")
  else if (password.length > 50) errors.push("Password must be under 50 characters.")

  if (db.prepare("SELECT * FROM users WHERE username = ?").get(username)) {
    errors.push("Username already taken.")
  }

  if (errors.length) return res.render("homepage", { errors })

  const hashed = bcrypt.hashSync(password, 10)
  const result = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashed)
  const user = db.prepare("SELECT * FROM users WHERE ROWID = ?").get(result.lastInsertRowid)

  const token = jwt.sign({ userid: user.id, username: user.username }, process.env.JWTSECRET, { expiresIn: "1d" })

  res.cookie("ourSimpleApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  res.redirect("/")
})

app.listen(3000)
