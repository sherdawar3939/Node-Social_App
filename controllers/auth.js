const { validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

exports.signup = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error("Validation error");
    error.statusCode = 422;
    error.data = errors.array();
    throw error;
  }
  const email = req.body.email;
  const password = req.body.password;
  const name = req.body.name;
  bcrypt
    .hash(password, 12)
    .then((hashpassword) => {
      const newUser = new User({
        email: email,
        password: hashpassword,
        name: name,
      });
      return newUser.save();
    })
    .then((result) => {
      res.status(201).json({
        message: "User created successfully",
        userId: result._id,
      });
    })

    .catch((err) => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next();
    });
};

exports.login = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  let loadedUser;
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        const error = new Error("No user found with this email");
        error.statusCode = 401;
        throw error;
      }
      loadedUser = user;
      return bcrypt.compare(password, user.password).then((isEqual) => {
        if (!isEqual) {
          const error = new Error("Wrong Password");
          error.statusCode = 401;
          throw error;
        }
        const token = jwt.sign(
          {
            email: loadedUser.email,
            userId: loadedUser._id.toString(),
          },
          "SecretSecret",
          {
            expiresIn: "1hr",
          }
        );
        res.status(200).json({
          token: token,
          userId: loadedUser._id.toString(),
        });
      });
    })
    .catch((err) => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next();
    });
};
