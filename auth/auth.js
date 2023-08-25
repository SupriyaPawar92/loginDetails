const User = require("../model/user")
const bcrypt = require("bcryptjs")
const multer = require("multer");
const path = require("path");
const jwt = require('jsonwebtoken')
const jwtSecret = '4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd'

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, ".uploads"), // cb -> callback
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(
      Math.random() * 1e9
    )}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  },
});
const handleMultipartData = multer({
    storage,
    limits: { fileSize: 1000000 * 5 },
  }).single("image");

  exports.register = async (req, res, next) => {
    const { username, password } = req.body;
  
    bcrypt.hash(password, 10).then(async (hash) => {
      await User.create({
        username,
        password: hash,
      })
        .then((user) => {
            handleMultipartData(req, res, async (err) => {
          const maxAge = 3 * 60 * 60;
          const token = jwt.sign(
            { id: user._id, username, role: user.role},
            jwtSecret,
            {
              expiresIn: maxAge, 
            }
          );
        
          res.cookie("jwt", token, {
            httpOnly: true,
            maxAge: maxAge * 1000,
          });
          res.status(201).json({
            message: "User successfully created",
            user: user._id,
            file: req.file,
          });
        })
        .catch((error) =>
          res.status(400).json({
            message: "User not successful created",
            error: error.message,
          })
        );
    });
});
  };

exports.login = async (req, res, next) => {
    const { username, password } = req.body
    // Check if username and password is provided
    if (!username || !password) {
        return res.status(400).json({
            message: "Username or Password not present",
        })
    }
    try {
        const user = await User.findOne({ username })
        if (!user) {
            res.status(400).json({
                message: "Login not successful",
                error: "User not found",
            })
        } else {
            // comparing given password with hashed password
            bcrypt.compare(password, user.password).then(function (result) {
                result
                    ? res.status(200).json({
                        message: "Login successful",
                        user,
                    })
                    : res.status(400).json({ message: "Login not succesful" })
            })
        }
    } catch (error) {
        res.status(400).json({
            message: "An error occurred",
            error: error.message,
        })
    }
}
exports.update = async (req, res, next) => {
    const { role, id } = req.body
    // Verifying if role and id is presnt
    if (role && id) {
        // Verifying if the value of role is admin
        if (role === "admin") {
            await User.findById(id)
        } else {
            res.status(400).json({
                message: "Role is not admin",
            })
        }
    } else {
        res.status(400).json({ message: "Role or Id not present" })
    }
}

exports.update = async (req, res, next) => {
    const { role, id } = req.body
    // Verifying if role and id is presnt
    if (role && id) {
        // Verifying if the value of role is admin
        if (role === "admin") {
            await User.findById(id)
        } else {
            res.status(400).json({
                message: "Role is not admin",
            })
        }
    } else {
        res.status(400).json({ message: "Role or Id not present" })
    }
}

exports.route("/user").post(async (req, res) => {
    handleMultipartData(req, res, async (err) => {
      if (err) {
        res.json({ msgs: err.message });
      }
  
      res.json({
        body: req.body,
        file: req.file,
      });
    });
  });
  
  exports.route("/user").get(async (req, res) => {
    res.send("--- Get All User ---");
  });