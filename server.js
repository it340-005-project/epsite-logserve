require("dotenv").config();
const fs = require("fs");
const path = require("path");
const express = require("express");

const required = ["HOST", "PORT", "LOG_TOKEN", "LOG_DIR"];
for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing " + key);
    process.exit(1);
  }
}

const logDir = path.resolve(process.env.LOG_DIR);
fs.mkdirSync(logDir, { recursive: true });
const logFile = path.join(logDir, "audit.log");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "4kb" }));

app.post("/logs", (req, res) => {
  if (req.get("X-Log-Token") !== process.env.LOG_TOKEN) {
    res.status(401).json({ success: false, message: "Unauthorized." });
    return;
  }
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  const keys = Object.keys(body);
  const allowed = ["who", "access", "action", "time"];
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key))) {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  const who = body.who;
  const access = body.access;
  const action = body.action;
  const time = body.time;
  if (typeof who !== "string" || who.length < 1 || who.length > 64) {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  if (access !== "read" && access !== "write") {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  if (typeof action !== "string" || !/^[A-Za-z0-9_]{1,64}$/.test(action)) {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  if (typeof time !== "string" || Number.isNaN(Date.parse(time))) {
    res.status(400).json({ success: false, message: "Invalid log." });
    return;
  }
  fs.appendFile(logFile, JSON.stringify({ who, access, action, time }) + "\n", (err) => {
    if (err) {
      console.error("Could not write audit log", err.message);
      res.status(500).json({ success: false, message: "Could not store log." });
      return;
    }
    res.status(204).end();
  });
});

app.use((_req, res) => {
  res.status(404).json({ success: false, message: "Not found." });
});

app.listen(Number(process.env.PORT), process.env.HOST, () => {
  console.log("Log server listening on " + process.env.HOST + ":" + process.env.PORT);
});
