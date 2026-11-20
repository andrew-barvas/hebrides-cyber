// Renders the social media images (marketing/19-advertising-plan.md §3) from
// the brand mark and palette in public/brand/ (README.md there): each image is
// HTML screenshotted at its exact size with Playwright, so changing a line of
// copy and re-running regenerates them all.
//
// Run with: npx tsx src/scripts/render-social-images.ts
// Output: public/brand/social/*.png
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const BG = "#070B14";
const NEON = "#39FFC0";
const TEXT = "#FFFFFF";
const MUTED = "#979A9C";
const MONO = "Consolas, 'Liberation Mono', 'SFMono-Regular', ui-monospace, monospace";
const SANS = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const URL_TEXT = "hebridescyber.co.uk";

/** The `>` mark in its rounded tile, as in public/brand/hebrides-icon.svg. */
function mark(size: number): string {
  return `<svg width="${size}" height="${size}" viewBox="0 0 240 240" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5BFFD0"/><stop offset="1" stop-color="#20C88E"/></linearGradient>
      <filter id="glow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    </defs>
    <rect width="240" height="240" rx="52" fill="${BG}"/>
    <rect x="7" y="7" width="226" height="226" rx="46" fill="none" stroke="${NEON}" stroke-opacity="0.18" stroke-width="2.5"/>
    <path d="M72 50 L176 120 L72 190" fill="none" stroke="url(#g)" stroke-width="26" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)"/>
  </svg>`;
}

function wordmark(fontPx: number): string {
  return `<div style="font-family:${MONO};font-weight:700;letter-spacing:${fontPx * 0.05}px;line-height:1.05;font-size:${fontPx}px">
    <div style="color:${TEXT}">HEBRIDES</div><div style="color:${NEON}">CYBER</div></div>`;
}

/** Faint grid and glow, the site's "bg-grid" look. */
function backdrop(): string {
  return `background:${BG};background-image:
    radial-gradient(ellipse at 75% 40%, rgba(57,255,192,0.10), transparent 55%),
    linear-gradient(rgba(57,255,192,0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(57,255,192,0.05) 1px, transparent 1px);
    background-size: 100% 100%, 32px 32px, 32px 32px;`;
}

function page(width: number, height: number, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{width:${width}px;height:${height}px;overflow:hidden;${backdrop()}font-family:${SANS};color:${TEXT}}
  </style></head><body>${body}</body></html>`;
}

const prompt = (text: string, px: number) =>
  `<div style="font-family:${MONO};font-size:${px}px;color:${NEON}">&gt; <span style="color:${TEXT}">${text}</span></div>`;

type Image = { file: string; width: number; height: number; html: string };

const IMAGES: Image[] = [
  {
    // Profile picture everywhere (LinkedIn, X, YouTube, Google Business, Facebook).
    // The tile fits inside the circle X, Google and YouTube crop avatars to.
    file: "profile-400x400.png",
    width: 400,
    height: 400,
    html: page(400, 400, `<div style="display:flex;align-items:center;justify-content:center;width:400px;height:400px;background:${BG}">${mark(270)}</div>`),
  },
  {
    // LinkedIn company page cover. The logo overlaps the bottom-left on the page, so content sits right.
    file: "linkedin-company-1128x191.png",
    width: 1128,
    height: 191,
    html: page(
      1128,
      191,
      `<div style="position:absolute;left:330px;right:48px;top:0;bottom:0;display:flex;flex-direction:column;justify-content:center;gap:10px">
        <div style="font-size:30px;font-weight:700">Website and email security for UK small businesses</div>
        ${prompt(`Free check, no sign-up · ${URL_TEXT}`, 20)}
      </div>`
    ),
  },
  {
    // Your personal LinkedIn profile banner. The photo overlaps the bottom-left.
    file: "linkedin-personal-1584x396.png",
    width: 1584,
    height: 396,
    html: page(
      1584,
      396,
      `<div style="position:absolute;left:520px;right:80px;top:0;bottom:0;display:flex;align-items:center;gap:48px">
        ${mark(170)}
        <div style="display:flex;flex-direction:column;gap:16px">
          <div style="font-size:44px;font-weight:700;line-height:1.15">Practical security for<br>UK small businesses</div>
          ${prompt(URL_TEXT, 26)}
        </div>
      </div>`
    ),
  },
  {
    // X header. The avatar overlaps the bottom-left, so content sits centre-right.
    file: "x-header-1500x500.png",
    width: 1500,
    height: 500,
    html: page(
      1500,
      500,
      `<div style="position:absolute;left:470px;right:90px;top:0;bottom:40px;display:flex;flex-direction:column;justify-content:center;gap:22px">
        <div style="font-size:54px;font-weight:700;line-height:1.12">Find out how secure your<br>website is in 30 seconds</div>
        <div style="font-size:26px;color:${MUTED}">Plain-English fixes, mapped to Cyber Essentials.</div>
        ${prompt(`Free check · ${URL_TEXT}`, 28)}
      </div>`
    ),
  },
  {
    // YouTube banner: only the centre 1546x423 shows on every device, so everything sits there.
    file: "youtube-banner-2560x1440.png",
    width: 2560,
    height: 1440,
    html: page(
      2560,
      1440,
      `<div style="position:absolute;left:507px;top:508px;width:1546px;height:423px;display:flex;align-items:center;justify-content:center;gap:64px">
        ${mark(260)}
        <div style="display:flex;flex-direction:column;gap:22px">
          ${wordmark(84)}
          <div style="font-size:34px;color:${MUTED}">Security checks for UK small businesses</div>
        </div>
      </div>`
    ),
  },
  {
    // Link preview when the site is shared (Open Graph / X card); also wired into layout.tsx.
    file: "share-1200x630.png",
    width: 1200,
    height: 630,
    html: page(
      1200,
      630,
      `<div style="position:absolute;inset:0;padding:72px 80px;display:flex;flex-direction:column;justify-content:space-between">
        <div style="display:flex;align-items:center;gap:28px">${mark(110)}${wordmark(44)}</div>
        <div style="display:flex;flex-direction:column;gap:20px">
          <div style="font-size:62px;font-weight:700;line-height:1.1">Find out how secure your<br>website is in 30 seconds</div>
          <div style="font-size:30px;color:${MUTED}">Free check, no sign-up. Plain-English fixes, mapped to Cyber Essentials.</div>
        </div>
        ${prompt(URL_TEXT, 30)}
      </div>`
    ),
  },
];

async function main() {
  const outDir = path.join(process.cwd(), "public", "brand", "social");
  await mkdir(outDir, { recursive: true });
  const browser = await chromium.launch();
  try {
    for (const img of IMAGES) {
      const pageHandle = await browser.newPage({ viewport: { width: img.width, height: img.height } });
      await pageHandle.setContent(img.html, { waitUntil: "load" });
      await pageHandle.screenshot({ path: path.join(outDir, img.file), clip: { x: 0, y: 0, width: img.width, height: img.height } });
      await pageHandle.close();
      console.log(`wrote public/brand/social/${img.file}`);
    }
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error("render-social-images failed:", err);
  process.exit(1);
});
