require("dotenv").config()
const jwt = require("jsonwebtoken")
const marked = require("marked")
const sanitizeHTML = require('sanitize-html')
const express = require("express")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')
const db = require("better-sqlite3") ("ourAppp.db")
db.pragma("journal_mode = WAL")

//database setup here
const createTables = db.transaction(() => {
    db.prepare(
        `
         CREATE TABLE IF NOT EXISTS users (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         username STRING NOT NULL UNIQUE,
         password STRING NOT NULL
         )
         `
    ).run()

db.prepare(`
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
    )
`).run();
})

createTables()

//databas setup end here

const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
    //make our markdon function avalible
    res.locals.filterUserHTML = function(content){
        return sanitizeHTML(marked.parse(content), {
            allowedTags: ["p", "br","li","li", "ul", "ol", "strong","bold","i", "em", "h1", "h2","h3","h4","h5","h6" ],
            allowedAttributes: {}
        })
    }

    res.locals.errors = []

    //try to decode incoming cookie 
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (err){
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)
        next()
    })

app.get("/", (req, res) => {
    if (req.user) {
        const postsStatement = db.prepare("SELECT *FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
        const posts =postsStatement.all(req.user.userid)
       return res.render("dashboard", {posts})
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

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors = ["invild username / password"]
    if (req.body.password == "") errors = ["invild username / password"]

    if (errors.length) {
        return res.render("login", {errors})
    } 

    const userInQuestionStatement = db.prepare(" SELECT *FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if (!userInQuestion){
        errors= ["Invalid username / password."]
        return res.render("login", {errors})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot){
         errors= ["Invalid username / password."]
        return res.render("login", {errors})
    }

    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username}, process.env.JWTSECRET)
  
  res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 *60 *60 * 24
    })

    res.redirect("/")
})


function mustBeloggedIn(req, res, next){
    if (req.user){
        return next()
    }
    return res.redirect("/")
}

app.get("/create-post",mustBeloggedIn, (req, res) => {
    res.render("create-post")
})

function sharedPostValidation(req){
    const errors = []
if (typeof req.body.title !== "string") req.body.title =""
if (typeof req.body.body !== "string") req.body.body =""
    //trim - sanitize or strip out html
req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.body = sanitizeHTML(req.body.body.trim(),{allowedTags: [], allowedAttributes:{}})

    if (!req.body.title) errors.push("You must provide a title")
    if (!req.body.body) errors.push("You must provide a Contant")

    return errors
}


app.get("/edit-post/:id", mustBeloggedIn,(req, res) => {
//post in quation
const statement= db.prepare("SELECT * FROM posts WHERE id = ?")
const post = statement.get(req.params.id)

if(!post) {
    return res.redirect("/")
}
//not the author rediract to home oage
if (post.authorid !== req.user.userid){
    return res.redirect("/")
}

const isAuthor = post.authorid === req.user.userid

// render the edit post tamlet
res.render("edit-post",{post})
})

app.post("/edit-post/:id",mustBeloggedIn, (req, res) => {
    const statement= db.prepare("SELECT * FROM posts WHERE id = ?")
const post = statement.get(req.params.id)


if(!post) {
    return res.redirect("/")
}
//not the author rediract to home oage
if (post.authorid !== req.user.userid){
    return res.redirect("/")
}

const errors = sharedPostValidation(req)

if (errors.length){
    return res.redirect("edit-post", {errors})
}

const updateStatement =db.prepare("UPDATE posts SET title = ?, body = ? WHERE ID = ?")
updateStatement.run(req.body.title, req.body.body, req.params.id)

res.redirect(`/post/${req.params.id}`)

})

app.post("/delete-post/:id",mustBeloggedIn, (req , res) => {
 const statement= db.prepare("SELECT * FROM posts WHERE id = ?")
const post = statement.get(req.params.id)


if(!post) {
    return res.redirect("/")
}
//not the author rediract to home oage
if (post.authorid !== req.user.userid){
    return res.redirect("/")
}

const deleteSatatement = db.prepare("DELETE FROM posts WHERE id = ?")
deleteSatatement.run(req.params.id)

res.redirect("/")

})

app.get("/post/:id", (req, res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)

    if(!post){
        return res.redirect("/")
    }
    const isAuthor = post.authorid === req.user.userid

    res.render("singel-post", {post, isAuthor})
})

app.post("/create-post",mustBeloggedIn, (req, res) => {
    const errors = sharedPostValidation(req)

    if (errors.length) {
        return res.render("create-post", {errors})
    }

    // save into datebase
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())
    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realpost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realpost.id}`)
})

app.post("/register", (req, res) => {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("you must provide a username")
    if (req.body.username && req.body.username.length < 3) errors.push("username must be 3.")
    if (req.body.username && req.body.username.length > 10) errors.push("username can't be 10.")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("username can only be a-0")

   //chek if username exist already 
   const usernameStatement =  db.prepare("SELECT * FROM users WHERE username = ?") 
   const usernameCheck = usernameStatement.get(req.body.username)
   if ( usernameCheck) errors.push(" That username alredy taken")

    if (!req.body.password) errors.push("you must provide a password")
    if (req.body.password && req.body.password.length < 8) errors.push("password must be 8 character.")
    if (req.body.password && req.body.password.length > 50) errors.push("Password can't be 71.")   

    if (errors.length) {
        return res.render("homepage", {errors})
    }  

  //save new user into a database
  const salt = bcrypt.genSaltSync(10)
  req.body.password = bcrypt.hashSync(req.body.password, salt)

 const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
const result = ourStatement.run(req.body.username, req.body.password)

const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
const ourUser = lookupStatement.get(result.lastInsertRowid)

  //log in the user in by giving them a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)
  
  res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 *60 *60 * 24
    })

    res.redirect("/")
})

app.listen(4000)