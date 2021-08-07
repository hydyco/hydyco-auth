import { Router, Request } from "express";
import passport from "passport";
import { HydycoModel } from "@hydyco/mongoose-plugin";
import { HydycoFile } from "@hydyco/core";
import { Strategy as JwtStrategy, StrategyOptions } from "passport-jwt";
import JWT from "jsonwebtoken";
import fs from "fs";
import path from "path";

import * as data from "./user.json";

const router = Router();

const file = new HydycoFile();

if (!fs.existsSync(path.join(file.hydycoMappingDir, "user.json")))
  file.writeMappingFile("user", data); // init data

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
        const userId: string = token.aud;
        return done(null, userId);
      } catch (e) {
        return done(null, false);
      }
    })
  );

  function generateAccessToken(userId: number): string {
    const options: JWT.SignOptions = {
      expiresIn: "1y",
      audience: userId.toString(),
    };
    return JWT.sign({}, secretOrKey, options);
  }

  router.post("/auth/login", async (request, response) => {
    const { email } = request.body;
    const User = new HydycoModel("user").mongooseModel();

    try {
      const user = await User.findOne({ email: email });
      if (!user)
        return response.send({ status: false, message: "User not found" });

      const token = generateAccessToken(user._id);

      return response.send({ status: true, message: "User authorized", token });
    } catch (error) {
      return response
        .send({ status: false, message: error.message })
        .status(500);
    }
  });

  return router;
};

export { useAuth, makeAuth };
