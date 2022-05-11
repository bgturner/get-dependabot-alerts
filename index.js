#!/usr/bin/env node

import dotenv from "dotenv";
dotenv.config();

const repos = process.argv.slice(2);

repos.forEach((item) => {
  const [org, repo] = item.split("/");
  console.log("org: ", org);
  console.log("repo: ", repo);
});
