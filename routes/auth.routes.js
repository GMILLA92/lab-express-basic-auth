const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs")
const saltRounds = 10

const {isLoggedIn, isLoggedOut} = require("../middleware/route-guard.js")

const User = require("../models/User.model");
const { default: mongoose } = require('mongoose');

router.get("/signup", isLoggedOut, (req, res) => {
    res.render("auth/signup")
  })

router.post("/signup", async (req,res) => {
   const {username, password} = req.body

    if ( !username || !password) {
      res.render("auth/signup", { error: "All fields must be completed."})
      return
    }
  
    try {
      const salt = bcrypt.genSaltSync(saltRounds)
      const hash = bcrypt.hashSync(password, salt)
  
      const userDb = await User.create({
        username: username,
        password: hash
      })
      
    req.session.currentUser = userDb
    res.redirect("/profile")

    }catch (err){
        console.log(err)
        if (err.code === 11000){
            res.status(500).render("auth/signup", { error: "The username should be unique" })
        }

    //   if (err instanceof mongoose.Error.ValidationError) {
    //     res.status(500).render("auth/signup", { error: err.message })
    //   } else if (err.code === 11000) {
    //     res.status(500).render("auth/signup", { error: "The  should be unique" })
    //   }
    }
  })

  router.get("/profile", isLoggedIn, (req, res) => {
    res.render("users/user-profile", req.session.currentUser)
  })

  router.get("/login", isLoggedOut, (req, res) => {
    res.render("auth/login")
  })
  
  router.post("/login", async(req, res) => {
    console.log(req.session)
    const { username, password } = req.body
  
    if ( !username || !password) {
      res.render("auth/login", { errorMessage: "All the fields should be flled"})
      return
    }
  
    try {
      const userDb = await User.findOne({username})
      if (!userDb) {
        res.render("auth/login", { errorMessage: "This username is not registered, Try again" })
      } else if (bcrypt.compareSync(password, userDb.password)){
        req.session.currentUser = userDb
        
        res.render("users/user-profile", userDb)
      } else {
        res.render("auth/login", { errorMessage: "Incorrect password, Try again" })
      }
    }catch (err) {
      console.log(err)
    }
  
  })
  router.post("/logout", (req, res) => {
    req.session.destroy(err => {
      if (err) {
        console.log(err)
      } else {
        res.redirect("/")
      }
    })
  })

  router.get("/private", isLoggedIn , (req, res) => {
    res.render("private")
  })

  router.get("/main", isLoggedIn , (req, res) => {
    res.render("main")
  })

  

  module.exports = router;
