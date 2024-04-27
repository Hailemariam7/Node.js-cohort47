import express from "express";
import { v4 } from "uuid";
import {
  validDetail,
  userData,
  hashPassword,
  comparePassword,
  generateJWT,
  verifyJWT,
} from "./users.js";

let app = express();

app.use(express.json());

app.post("/register", async (req, res) => {
  const newUser = {
    id: v4(),
    username: req.body.username,
    password: req.body.password,
  };
  if (!validDetail(newUser)) {
    return res.status(400).send("Username or password is missing.").end();
  }
  newUser.password = await hashPassword(req.body.password);
  userData.push(newUser);

  res
    .status(201)
    .send({
      message: "user created",
      id: newUser.id,
      username: newUser.username,
    })
    .end();
});

app.post("/login", async (req, res) => {
  if (
    !validDetail({ username: req.body.username, password: req.body.password })
  ) {
    return res.status(400).send("Username or password is missing.").end();
  }
  const user = userData.find((user) => user.username === req.body.username);

  if (!user) {
    return res.status(404).send("No such user, sorry!").end();
  }
  const correctPassword = await comparePassword(
    req.body.password,
    user.password
  );

  if (!correctPassword) {
    return res.status(401).send("password incorrect").end();
  }
  const userJWT = generateJWT(user);

  res.set("Authorization", userJWT);
  return res.status(200).send("login successful").end();
});

app.get("/profile", (req, res) => {
  const token = req.headers.authorization;
  try {
    const user = userData.find((user) => user.id === verifyJWT(token).id);
    if (user) {
      return res
        .status(200)
        .send(`authentication is successful, ${user.username}`)
        .end();
    }
  } catch (err) {
    return res.status(401).send("authentication failed").end();
  }
});

app.post("/logout", (req, res) => {
  //localStorage.removeItem("jwtToken"); //if token is saved in localStorage
  //sessionStorage.removeItem("jwtToken");//if stored in sessionStorage.

  return res.status(204).send("successfully logged out").end();
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
