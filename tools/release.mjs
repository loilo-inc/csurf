import fs from "node:fs";
import cp from "node:child_process";

function praseRef(ref) {
  const m = ref.match(/^refs\/tags\/(.+?)$/);
  if (!m) throw new Error("no tags in ref: " + ref);
  return m[1];
}

async function main() {
  let ref = process.env["GITHUB_REF"];
  let token = process.env["GITHUB_TOKEN"];
  if (!ref) throw new Error("no github ref");
  if (!token) throw new Error("no github token");
  const tag = praseRef(ref);
  const packageJson = JSON.parse(await fs.promises.readFile("package.json"));
  packageJson["version"] = tag;
  await fs.promises.writeFile("package.json", JSON.stringify(packageJson));
  const npmRc = "//npm.pkg.github.com/:_authToken=" + token;
  await fs.promises.writeFile(".npmrc", npmRc);
  const p = cp.spawn("npm", ["publish"]);
  await new Promise((resolve, reject) => {
    p.stderr.pipe(process.stderr);
    p.stdout.pipe(process.stdout);
    p.on("close", (code) => {
      code === 0 ? resolve() : reject(code);
    });
  });
  console.log(`📦 package ${tag} released!`);
}

main();
