require("dotenv").config()
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const express = require('express')
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")

//  dtabase starts

const createTables = db.transaction(()=>{
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
    `).run()
})

createTables()
//  database ends


const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))

app.use(function(req, res, next){
    res.locals.errors =[]
    next()
})
app.get("/", (req, res) =>{
    res.render("home")
})



app.get("/login", (req, res) =>{
    res.render("login")
})

app.post("/register", (req, res) =>{
    console.log(req.body)

    const errors = []
    if (typeof req.body.username !== "string") req.body.username =""
    if (typeof req.body.password !== "string") req.body.password =""


    req.body.username =  req.body.username.trim()
    
    if(!req.body.username) errors.push("You must provide a username")
    if(req.body.username && req.body.username.length < 3) errors.push("username must be atleast 3 characters")
    if(req.body.username && req.body.username.length >10) errors.push("username mustnot exceed 10 characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("username can not contain special character")

    if(!req.body.password) errors.push("You must provide a password")
    if(req.body.password && req.body.password.length < 4) errors.push("password must be atleast 4 characters")
    if(req.body.password && req.body.password.length >10) errors.push("password mustnot exceed 10 characters")
        if(errors.length){
            return res.render("home", {errors})
        }
        //STORING USER IN THE DATABASE
        const salt = bcrypt.genSaltSync(10)
        req.body.password = bcrypt.hashSync(req.body.password , salt)


        const ourStatement = db.prepare("INSERT INTO users ( username, password) VALUES (?,?)")
        const result = ourStatement.run(req.body.username, req.body.password)

        const lookup = db.prepare("SELECT * FROM users WHERE ROWID = ?")
        const ourUser = lookup.get(result.lastInsertRowid)

    //  log the user in by giving the the cookie
    const ourTokenValue =jwt.sign({exp: Math.floor(Date.now()/ 1000) +60 * 60 * 24 , skyColor: "blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.send("thanks for filling the form")

})

app.listen(3000, (req,res) => {
    console.log("app is running in the browser")
})