const express = require('express')
const app = express()

app.set("view engine", "ejs")

app.get("/", (req, res) =>{
    res.render("home")
})

app.listen(3000, (req,res) => {
    console.log("app is running in the browser")
})