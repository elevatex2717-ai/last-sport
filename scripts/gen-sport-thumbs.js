// scripts/gen-sport-thumbs.js
// Generates per-sport SVGs (original) + JPG/WebP thumbs into img/sports/thumb.
// 100% free to use: these shapes are authored here (public domain / CC0).
//
// Usage:
//   npm i sharp
//   node scripts/gen-sport-thumbs.js

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

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

const OUT_DIR = path.join(process.cwd(), "img", "sports", "thumb");
const BG = "#0f1323"; // app dark
const STROKE = "#ffffff";
const SW = 22; // stroke width
const SIZE = 160;
const DENSITY = 256;

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function wrapSvg(content, fillGroup = false) {
  // fillGroup set true for icons that need filled shapes
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="512" height="512" viewBox="0 0 512 512"
     xmlns="http://www.w3.org/2000/svg">
  <rect x="0" y="0" width="512" height="512" rx="40" fill="${BG}"/>
  <g ${fillGroup ? `fill="${STROKE}"` : `fill="none"`} stroke="${STROKE}" stroke-width="${SW}" stroke-linecap="round" stroke-linejoin="round">
    ${content}
  </g>
</svg>`;
}

// Icon primitives per sport (simple, original shapes)
const ICONS = {
  generic: () =>
    wrapSvg(
      `
      <rect x="232" y="316" width="48" height="70" rx="8" fill="${STROKE}" stroke="none"/>
      <rect x="192" y="386" width="128" height="32" rx="16" fill="${STROKE}" stroke="none"/>
      <path d="M156 122h200a8 8 0 0 1 8 8v92a108 108 0 0 1-216 0v-92a8 8 0 0 1 8-8z" />
      <path d="M92 118v24a64 64 0 0 0 64 64" />
      <path d="M420 118v24a64 64 0 0 1-64 64" />
      `
    , true),

  cricket: () =>
    wrapSvg(
      `
      <rect x="316" y="160" width="28" height="210" rx="8" transform="rotate(-35 330 265)" fill="${STROKE}" stroke="none"/>
      <circle cx="392" cy="176" r="18" fill="${STROKE}" stroke="none"/>
      `
    , true),

  football: () =>
    wrapSvg(
      `
      <circle cx="256" cy="256" r="140"/>
      <line x1="256" y1="116" x2="256" y2="396"/>
      <line x1="116" y1="256" x2="396" y2="256"/>
      `
    ),

  volleyball: () =>
    wrapSvg(
      `
      <circle cx="256" cy="256" r="140"/>
      <path d="M150 200c60-30 130-30 200 0"/>
      <path d="M150 312c60 30 130 30 200 0"/>
      <path d="M196 140c20 60 20 120 0 180"/>
      <path d="M316 140c20 60 20 120 0 180"/>
      `
    ),

  badminton: () =>
    wrapSvg(
      `
      <polygon points="256,140 300,220 256,300 212,220" fill="${STROKE}" stroke="none"/>
      <rect x="244" y="300" width="24" height="40" rx="6" fill="${STROKE}" stroke="none"/>
      `
    , true),

  basketball: () =>
    wrapSvg(
      `
      <circle cx="256" cy="256" r="140"/>
      <line x1="256" y1="116" x2="256" y2="396"/>
      <line x1="116" y1="256" x2="396" y2="256"/>
      <path d="M156 156c80 40 120 160 200 200"/>
      <path d="M356 156c-80 40 -120 160 -200 200"/>
      `
    ),

  hockey: () =>
    wrapSvg(
      `
      <path d="M170 140l140 220" />
      <path d="M320 360c-10 28 -36 44 -64 44" />
      <circle cx="348" cy="380" r="12" fill="${STROKE}" stroke="none"/>
      `
    , true),

  tennis: () =>
    wrapSvg(
      `
      <circle cx="256" cy="256" r="140"/>
      <path d="M156 200c40-40 160-40 200 0"/>
      <path d="M156 312c40 40 160 40 200 0"/>
      `
    ),

  "table-tennis": () =>
    wrapSvg(
      `
      <circle cx="210" cy="230" r="60" fill="${STROKE}" stroke="none"/>
      <rect x="250" y="270" width="100" height="22" rx="11" fill="${STROKE}" stroke="none"/>
      <circle cx="340" cy="190" r="14" fill="${STROKE}" stroke="none"/>
      `
    , true),

  chess: () =>
    wrapSvg(
      `
      <rect x="220" y="300" width="72" height="60" />
      <rect x="200" y="220" width="112" height="80" />
      <rect x="180" y="200" width="152" height="24" />
      <rect x="160" y="360" width="192" height="24" />
      `
    ),

  boxing: () =>
    wrapSvg(
      `
      <path d="M176 256a64 64 0 0 1 120-20" />
      <path d="M296 236h40a40 40 0 0 1 40 40v20a40 40 0 0 1-40 40h-60" />
      <rect x="176" y="276" width="120" height="80" rx="24" />
      `
    ),

  wrestling: () =>
    wrapSvg(
      `
      <circle cx="196" cy="176" r="20" />
      <circle cx="316" cy="176" r="20" />
      <path d="M180 196l40 40" />
      <path d="M332 196l-40 40" />
      <path d="M220 236l20 40" />
      <path d="M292 236l-20 40" />
      `
    ),

  judo: () =>
    wrapSvg(
      `
      <rect x="136" y="232" width="240" height="36" />
      <path d="M196 232v80" />
      <path d="M316 232v80" />
      <path d="M208 312l48-32 48 32" />
      `
    ),

  taekwondo: () =>
    wrapSvg(
      `
      <rect x="136" y="232" width="240" height="36" />
      <path d="M220 232l36 64" />
      <path d="M292 232l-36 64" />
      <path d="M256 296v48" />
      `
    ),

  weightlifting: () =>
    wrapSvg(
      `
      <rect x="120" y="240" width="272" height="16" rx="8" />
      <rect x="96" y="208" width="32" height="80" />
      <rect x="384" y="208" width="32" height="80" />
      <path d="M256 256v96" />
      <circle cx="256" cy="368" r="12" />
      `
    ),

  archery: () =>
    wrapSvg(
      `
      <circle cx="216" cy="256" r="100" />
      <circle cx="216" cy="256" r="60" />
      <circle cx="216" cy="256" r="24" />
      <line x1="216" y1="256" x2="376" y2="256" />
      <path d="M356 256l-24 -12v24z" fill="${STROKE}" stroke="none"/>
      `
    , true),

  shooting: () =>
    wrapSvg(
      `
      <circle cx="256" cy="256" r="120" />
      <line x1="256" y1="156" x2="256" y2="356" />
      <line x1="156" y1="256" x2="356" y2="256" />
      `
    ),

  swimming: () =>
    wrapSvg(
      `
      <circle cx="176" cy="176" r="18" fill="${STROKE}" stroke="none"/>
      <path d="M160 208l48 24 40-16 48 24" />
      <path d="M128 320c32-24 64-24 96 0c32-24 64-24 96 0" />
      `
    ),

  athletics: () =>
    wrapSvg(
      `
      <circle cx="196" cy="176" r="18" />
      <path d="M188 196l40 36" />
      <path d="M228 232l-36 56" />
      <path d="M228 232l60 8" />
      <path d="M288 240l32 48" />
      `
    ),
};

function svgFor(slug) {
  const fn = ICONS[slug] || ICONS.generic;
  return fn();
}

async function writeSvg(slug) {
  const p = path.join(OUT_DIR, `${slug}.svg`);
  const svg = svgFor(slug);
  fs.writeFileSync(p, svg, "utf8");
  return p;
}

async function rasterize(svgPath, outBase) {
  const base = sharp(svgPath, { density: DENSITY })
    .resize(SIZE, SIZE, { fit: "contain", background: BG })
    .flatten({ background: BG });

  await base.clone().webp({ quality: 80 }).toFile(`${outBase}.webp`);
  await base.clone().jpeg({ quality: 82, progressive: true }).toFile(`${outBase}.jpg`);
}

async function main() {
  ensureDir(OUT_DIR);

  // Generic first
  const genSvgPath = path.join(OUT_DIR, "generic.svg");
  fs.writeFileSync(genSvgPath, ICONS.generic(), "utf8");
  await rasterize(genSvgPath, path.join(OUT_DIR, "generic"));

  // Each sport
  for (const slug of SLUGS) {
    const svgPath = await writeSvg(slug);
    await rasterize(svgPath, path.join(OUT_DIR, slug));
  }

  console.log(`✅ Generated SVG + JPG/WebP for ${SLUGS.length} sports + generic in ${OUT_DIR}`);
  console.log(`   Size: ${SIZE}x${SIZE}. Formats: .svg, .webp, .jpg`);
  console.log(`   Background: ${BG}`);
}

main().catch((err) => {
  console.error("❌ Generation failed:", err);
  process.exit(1);
});