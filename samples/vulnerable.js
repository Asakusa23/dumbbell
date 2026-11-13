const { exec } = require("child_process");
const db = require("./db");

function findUser(id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function runCommand(dir) {
  exec(`ls ${dir}`, (error, stdout) => console.log(stdout));
}

function render(element, value) {
  element.innerHTML = value;
  document.write(value);
}

function Dangerous({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

const token = "example-github-token";
const apiKey = "example-stripe-key";

module.exports = { findUser, runCommand, render, Dangerous };
