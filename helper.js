import { client } from "./index.js";

//! QUERY FUNCTIONS
//? GETTING ALL USERS FROM THE COLLECTION
export async function getAllUsers() {
  return await client.db("auth").collection("register").find().toArray();
}

//? MODIFING THE SINGLE USER DATA (MODIFY DATA)
export async function modifyData(documentId, updatedData) {
  return await client
    .db("auth")
    .collection("register")
    .replaceOne({ _id: documentId }, updatedData);
}

//? DELETING A SINGLE USER DATA BY ID
export async function deleteSingleUserData(deleteDocId) {
  return await client.db("auth").collection("register").deleteOne(deleteDocId);
}

//? CREATING A SINGLE USER DATA INTO THE COLLECTION (METHOD : POST)
export async function userRegistration(signUpData) {
  return await client.db("auth").collection("register").insertOne(signUpData);
}

//? GETTING THE SINGLE USER DATA FROM MONGODB (METHOD : GET)

export async function findOneData(input) {
  return await client.db("auth").collection("register").findOne(input);
}