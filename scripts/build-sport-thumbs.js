// scripts/build-sport-thumbs.js
// Generates JPG + WebP thumbnails from existing SVGs in img/sports/thumb.
// If a sport SVG is missing, uses a built-in generic SVG fallback.
// Output: img/sports/thumb/<slug>.webp and <slug>.jpg (160x160, dark bg).
//
// Usage:
//   npm i sharp
//   node scripts/build-sport-thumbs.js

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

// Canonical sport slugs to cover (extend if needed)
const SLUGS = [
  "kabaddi",
  "cricket",
  "volleyball",
  "badminton",
  "football",
  "hockey",
  "basketball",
  "athletics",
  "table-tennis",
  "tennis",
  "chess",
  "boxing",
  "wrestling",
  "judo",
  "taekwondo",
  "weightlifting",
  "archery",
  "shooting",
  "swimming",
];

const BG = "#0f1323"; // dark app background
const SIZE = 160; // square canvas for list thumbs
const QUALITY_WEBP = 80;
const QUALITY_JPG = 82;

const ROOT = process.cwd();
const DIR = path.join(ROOT, "img", "sports", "thumb");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function genericSvg() {
  // Simple, original “trophy”-like mark on dark bg (public-domain by author)
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="512" height="512" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect x="0" y="0" width="512" height="512" rx="40" fill="${BG}"/>
  <g fill="#ffffff" transform="translate(64,80)">
    <rect x="168" y="272" width="48" height="64" rx="8"/>
    <rect x="128" y="336" width="128" height="32" rx="16"/>
    <path d="M96 48h192a8 8 0 0 1 8 8v96a104 104 0 0 1-208 0V56a8 8 0 0 1 8-8z"/>
    <path d="M16 80h64v32a80 80 0 0 1-64-80v48z"/>
    <path d="M400 80h-64v32a80 80 0 0 0 64-80v48z"/>
  </g>
</svg>`;
}

async function rasterizeSvg(bufferOrPath, outBase) {
  const base = sharp(bufferOrPath, { density: 256 })
    .resize(SIZE, SIZE, { fit: "contain", background: BG })
    .flatten({ background: BG }); // ensures JPG background

  await base.clone().webp({ quality: QUALITY_WEBP }).toFile(`${outBase}.webp`);
  await base
    .clone()
    .jpeg({ quality: QUALITY_JPG, progressive: true })
    .toFile(`${outBase}.jpg`);
}

async function ensureThumbFor(slug) {
  const svgPath = path.join(DIR, `${slug}.svg`);
  const outBase = path.join(DIR, slug);

  if (fs.existsSync(svgPath)) {
    await rasterizeSvg(svgPath, outBase);
    return { slug, source: "svg" };
  }

  // Fallback: generic mark
  const gen = Buffer.from(genericSvg(), "utf8");
  await rasterizeSvg(gen, outBase);
  return { slug, source: "generic" };
}

async function main() {
  ensureDir(DIR);

  // Also ensure a generic.jpg/webp pair exists explicitly
  const genericBase = path.join(DIR, "generic");
  await rasterizeSvg(Buffer.from(genericSvg(), "utf8"), genericBase);

  const results = [];
  for (const slug of SLUGS) {
    // Sequential to keep console tidy; switch to Promise.all for speed if desired
    // eslint-disable-next-line no-await-in-loop
    results.push(await ensureThumbFor(slug));
  }

  // Summary
  const viaSvg = results.filter((r) => r.source === "svg").length;
  const viaGen = results.length - viaSvg;
  console.log(
    `Done. Created ${results.length * 2 + 2} files: ${results.length} slugs (webp+jpg each) + generic (webp+jpg).`
  );
  console.log(`- From existing sport SVGs: ${viaSvg}`);
  console.log(`- From generic fallback: ${viaGen}`);
}

main().catch((err) => {
  console.error("Thumbnail build failed:", err);
  process.exit(1);
});