import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jsonwebtocken from "jsonwebtoken";
import { request } from "https";
import { response } from "express";

dotenv.config();

// ? BODY PARSER

const app = express();

const authorisation = async (request, response, next) => {
  const token = request.header("token");

  const verifyToken = jsonwebtocken.verify(token, process.env.privateKey);

  const checkUserExisting = await client
    .db("auth")
    .collection("register")
    .findOne({ email: verifyToken.email });

  if (verifyToken && checkUserExisting) {
    next();
  } else {
    response.status(401).send("Un Authorised");
  }
};

app.use(express.json());
app.use(cors());

const PORT = 7000;

const MONGO_URL = process.env.MONGO_URL;

const client = await createConnection();

// ! LOGIN VERIFICATION

app.post("/login", async (request, response) => {
  const { phone, password } = request.body;
  console.log(password);
  const signIn = await client
    .db("auth")
    .collection("register")
    .findOne({ contact: phone });
  if (!signIn) {
    response.status(401).send("Invalid Credentials");
  } else {
    const storedPassword = signIn.hashPassword;
    const isPasswordMatch = await bcrypt.compare(password, storedPassword);
    console.log(isPasswordMatch);
    if (!isPasswordMatch) {
      response.status(401).send("Invalid credentials");
    } else {
      console.log(signIn.email);
      const token = await tokenGenerator(signIn.email);
      console.log(isPasswordMatch);
      response.send({
        message: `Login Successful`,
        token: token,
        status: "successful",
      });
    }
  }
});

// ? SIGN UP USER
app.post("/create/user", async (req, res) => {
  const { name, contact, dob, email, password, conformPassword } = req.body;

  console.log({ password, conformPassword });
  const hashPassword = await createPassword(password);

  const hashConformPassword = await createPassword(conformPassword);

  const signUpData = {
    name,
    contact,
    dob,
    email,
    hashPassword,
    hashConformPassword,
  };
  console.log(signUpData);

  if (password !== conformPassword) {
    res.status("401").send("Password not Matching");
  } else {
    const registerUser = await client
      .db("auth")
      .collection("register")
      .insertOne(signUpData);
    console.log(signUpData);
  }

  res.send("Registration Successful");
});

// ? CREATE USER BY ADMIN

app.post("/createUser/byAdmin", async (req, res) => {
  const { name, contact, dob, email } = req.body;

  const password = "123456789";
  const conformPassword = "123456789";

  const hashPassword = await createPassword("12345678");

  const hashConformPassword = await createPassword("12345678");

  try {
    const signUpData = {
      name,
      contact,
      dob,
      email,
      hashPassword,
      hashConformPassword,
    };

    if (password !== conformPassword) {
      res.status("401").send("Password not Matching");
    } else {
      const registerUser = await client
        .db("auth")
        .collection("register")
        .insertOne(signUpData);
      console.log(registerUser);
    }
  } catch (error) {
    console.log(error.message);
  }

  res.send("Registration Successful");
});

// ? GET ALL USERS
app.get("/users", authorisation, async (request, response) => {
  const getDatas = request.headers;

  const { token } = getDatas;

  console.log(token);

  const crackData = await jsonwebtocken.verify(token, process.env.privateKey);
  const { email } = crackData;
  console.log(email);
  const checkUserExists = await client
    .db("auth")
    .collection("register")
    .findOne({ email: email });

  if (!checkUserExists) {
    response.status(401).send("Unauthorized user");
  } else {
    const getAllUserData = await client
      .db("auth")
      .collection("register")
      .find()
      .toArray();
    response.send(getAllUserData);
  }
});

// ? EDIT TABLES DATA

app.put("/editUsers/:id", async (request, response) => {
  const { id } = request.params;
  const { name, contact, dob, email } = request.body;

  const hashPassword = await createPassword("12345678");

  const hashConformPassword = await createPassword("12345678");

  const updatedData = await {
    name: name,
    contact: contact,
    dob: dob,
    email: email,
    hashPassword: hashPassword,
    hashConformPassword: hashConformPassword,
  };
  console.log(id);
  const documentId = await new ObjectId(id);
  const updateDatas = await client
    .db("auth")
    .collection("register")
    .replaceOne({ _id: documentId }, updatedData);
  console.log(updateDatas);
  response.send(updateDatas);
}),
  // ? DELETE TABLES DATA BY ID

  app.delete("/deleteUsers/:id", async (request, response) => {
    const { id } = request.params;
    console.log(id);
    const hashPassword = await createPassword("12345678");

    const hashConformPassword = await createPassword("12345678");

    console.log(id);
    const documentId = await new ObjectId(id);
    const updateDatas = await client
      .db("auth")
      .collection("register")
      .deleteOne({ _id: documentId });
    console.log(updateDatas);
    response.send(updateDatas);
  }),
  app.listen(PORT, () => console.log(`server started on port ${PORT} `));

//? DataBase Connection

async function createConnection() {
  const client = new MongoClient(MONGO_URL);

  await client.connect();

  console.log("MongoDb is connected to server 👍🏽");

  return client;
}

//? TOKEN GENERATOR

const tokenGenerator = async (email) => {
  const token = jsonwebtocken.sign({ email }, process.env.privateKey, {
    expiresIn: "9hours",
  });
  return token;
};

// ?  Hashing and salting process before storing a password in DB

async function createPassword(password) {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  return hash;
}
