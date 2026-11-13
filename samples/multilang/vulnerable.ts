import { exec } from "child_process";
import { db } from "./db";

export function findUser(id: string) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

export function run(dir: string) {
  exec(`ls ${dir}`);
}

const API_TOKEN: string = "example-github-token";
