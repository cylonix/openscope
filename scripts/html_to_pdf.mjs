#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";
import puppeteer from "/opt/homebrew/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js";

const [, , inputPath, outputPath] = process.argv;

if (!inputPath || !outputPath) {
  console.error("usage: node html_to_pdf.mjs <input.html> <output.pdf>");
  process.exit(2);
}

const browser = await puppeteer.launch({
  headless: true,
  args: ["--no-sandbox"],
});

try {
  const page = await browser.newPage();
  await page.goto(pathToFileURL(path.resolve(inputPath)).href, {
    waitUntil: "networkidle0",
  });
  await page.pdf({
    path: path.resolve(outputPath),
    format: "Letter",
    printBackground: true,
    preferCSSPageSize: true,
    margin: {
      top: "0.5in",
      right: "0.5in",
      bottom: "0.5in",
      left: "0.5in",
    },
  });
} finally {
  await browser.close();
}
