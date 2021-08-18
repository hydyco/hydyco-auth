import { Router, Request } from "express";
import passport from "passport";
import { HydycoModel } from "@hydyco/mongoose-plugin";
import { HydycoFile } from "@hydyco/core";
import { Strategy as JwtStrategy, StrategyOptions } from "passport-jwt";
import JWT from "jsonwebtoken";
import fs from "fs";
import path from "path";
import bcrypt from "bcrypt";

import * as data from "./user.json";

const router = Router();
const SALT_WORK_FACTOR = 10;
const file = new HydycoFile();

if (!fs.existsSync(path.join(file.hydycoMappingDir, "user.json")))
  file.writeMappingFile("user", data); // init data

const user = new HydycoModel("user");
const userSchema = user.mongooseSchema();

/**
 * Function - Generate auth token using user object and secret
 * @param {Object} user - User info object
 * @param {string} secretKey - secret key
 * @return {string} token
 */
const generateAuthToken = (user: Object, secretOrKey: string): string => {
  const options: JWT.SignOptions = {
    expiresIn: "1y",
    audience: JSON.stringify(user),
  };
  return JWT.sign({}, secretOrKey, options);
};

/**
 * Function - Handle Password hash and compare
 * @param {String} - password
 */
const authMongoosePlugin = function (schema) {
  schema.pre("save", function (next) {
    var u: any = this;

    // only hash the password if it has been modified (or is new)
    if (!u.isModified("password")) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
      if (err) return next(err);

      // hash the password using our new salt
      bcrypt.hash(u.password, salt, function (err, hash) {
        if (err) return next(err);
        // override the cleartext password with the hashed one
        u.password = hash;
        next();
      });
    });
  });

  schema.methods.comparePassword = function (candidatePassword, cb) {
    const u: any = this;
    bcrypt.compare(candidatePassword, u.password, function (err, isMatch) {
      if (err) return cb(err);
      cb(null, isMatch);
    });
  };
};

userSchema.plugin(authMongoosePlugin);

user.setMongooseSchema(userSchema);

const User = user.mongooseModel();

router.use(passport.initialize());

const makeAuth = passport.authenticate("jwt", { session: false });

const useAuth = ({ secretOrKey }) => {
  const jwtOptions: StrategyOptions = {
    jwtFromRequest: (req: Request) => {
      let token = null;
      if (req && req.headers && req.headers["authorization"]) {
        token = req.headers["authorization"];
      }
      return token;
    },
    secretOrKey: secretOrKey,
  };
  //JWT strategy options for passport (jwt middleware to verify & sign user)
  passport.use(
    new JwtStrategy(jwtOptions, async (token, done) => {
      if (!token) return done(null, true);
      try {
        const user: Object = JSON.parse(token.aud);
        return done(null, user);
      } catch (e) {
        return done(null, false);
      }
    })
  );

  /**
   * User Login Method
   */

  router.post("/auth/login", async (request, response) => {
    const { email, password } = request.body;

    try {
      const user: any = await User.findOne({ email: email });
      if (!user)
        return response
          .send({ status: false, message: "User not found" })
          .status(404);

      user.comparePassword(password, function (err, isMatch) {
        if (err || !isMatch) {
          return response
            .send({ status: false, message: "Password does not match" })
            .status(404);
        } else {
          const token = generateAuthToken(user, secretOrKey);

          return response.send({
            status: true,
            message: "User authorized",
            token,
          });
        }
      });
    } catch (error) {
      return response
        .send({ status: false, message: error.message })
        .status(500);
    }
  });

  /**
   * Register admin user
   */

  router.post("/auth/admin/register", async (request, response) => {
    const { email, password } = request.body;

    try {
      const count = await User.find().countDocuments();
      if (count > 0) {
        return response.send({
          status: false,
          message: "Admin user is already present",
        });
      }
      const user: any = new User();
      user.email = email;
      user.password = password;
      user.role = "admin";
      await user.save();

      const token = generateAuthToken(user, "random");
      return response.send({
        status: true,
        message: "Register Successful",
        token,
      });
    } catch (error) {
      return response.status(500).send({
        status: false,
        message: error.message,
      });
    }
  });

  return router;
};

export { useAuth, makeAuth, generateAuthToken, authMongoosePlugin };
