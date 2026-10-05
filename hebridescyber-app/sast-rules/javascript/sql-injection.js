// Annotated test cases for sql-injection.yaml (run: opengrep test sast-rules/).
const express = require("express");
const mysql = require("mysql2");
const { PrismaClient } = require("@prisma/client");
const knex = require("knex")({ client: "pg" });

const app = express();
const db = mysql.createPool({});
const prisma = new PrismaClient();

app.get("/user", (req, res) => {
  // ruleid: js-sql-injection
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});

app.get("/search", async (req, res) => {
  const term = req.query.term;
  const sql = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
  // ruleid: js-sql-injection
  const [rows] = await db.execute(sql);
  res.json(rows);
});

app.post("/login", async (req, res) => {
  const { email } = req.body;
  // ruleid: js-sql-injection
  await this.pool.query(`SELECT * FROM accounts WHERE email = '${email}'`);
});

app.get("/safe-param", (req, res) => {
  // ok: js-sql-injection
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (err, rows) => res.json(rows));
});

app.get("/safe-pg-object", async (req, res) => {
  // ok: js-sql-injection
  await client.query({ text: "SELECT * FROM users WHERE id = $1", values: [req.params.id] });
});

app.get("/safe-int", (req, res) => {
  const id = parseInt(req.query.id, 10);
  // ok: js-sql-injection
  db.query("SELECT * FROM users WHERE id = " + id);
});

app.get("/safe-escape", (req, res) => {
  // ok: js-sql-injection
  db.query("SELECT * FROM users WHERE name = " + db.escape(req.query.name));
});

app.get("/not-a-db", (req, res) => {
  // A search index's query() is not SQL.
  // ok: js-sql-injection
  searchIndex.query("title:" + req.query.q);
});

app.get("/constant", (req, res) => {
  // ok: js-sql-injection
  db.query("SELECT COUNT(*) FROM users");
});

app.get("/prisma", async (req, res) => {
  // ruleid: js-sql-injection-raw-query
  await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${req.query.email}'`);
  // ok: js-sql-injection-raw-query
  await prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE email = $1', req.query.email);
  // ok: js-sql-injection-raw-query
  await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${req.query.email}`;
});

app.get("/knex", async (req, res) => {
  // ruleid: js-sql-injection-raw-query
  await knex("users").whereRaw("name = '" + req.query.name + "'");
  // ruleid: js-sql-injection-raw-query
  await knex.raw(`select * from users where id = ${req.params.id}`);
  // ok: js-sql-injection-raw-query
  await knex("users").whereRaw("name = ?", [req.query.name]);
  // ok: js-sql-injection-raw-query
  await knex.raw("select * from users where id = ?", [req.params.id]);
});

app.get("/sequelize", async (req, res) => {
  // ruleid: js-sql-injection-raw-query
  await sequelize.query("SELECT * FROM orders WHERE ref = '" + req.query.ref + "'");
  // ok: js-sql-injection-raw-query
  await sequelize.query("SELECT * FROM orders WHERE ref = :ref", { replacements: { ref: req.query.ref } });
});
