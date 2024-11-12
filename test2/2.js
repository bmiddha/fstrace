const { execSync } = require("child_process");

console.log("Running 3.sh");
execSync(`bash ${__dirname}/3.sh`, { stdio: "inherit" });
