import bcrypt from "bcrypt";
//import { hash, compare } from "bcrypt";
import { v4 } from "uuid";
import jwt from "jsonwebtoken";
export const userData = [];
const saltRounds = 12;
const secretKey = "your-secret-key";

export function validDetail(newUser) {
  if (!newUser.username || !newUser.password) {
    return false;
  }
  return true;
}

export async function hashPassword(password) {
  return await bcrypt.hash(password, saltRounds);
}

export async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

export function generateJWT(user) {
  return jwt.sign({ id: user.id }, secretKey);
}

export function verifyJWT(token) {
  return jwt.verify(token, secretKey);
}
