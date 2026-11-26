'use strict';
// Generates icon.png (128x128) and images/screenshot.png (1400x900) for Terraform State & Plan Viewer.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const crcT = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc = (b) => { let c = -1; for (const v of b) c = crcT[(c ^ v) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
const chunk = (t, d) => {
  const l = Buffer.alloc(4); l.writeUInt32BE(d.length);
  const td = Buffer.concat([Buffer.from(t), d]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
  return Buffer.concat([l, td, c]);
};
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));

function writePng(filePath, W, H, px) {
  const raw = Buffer.alloc((W * 4 + 1) * H);
  for (let y = 0; y < H; y++) {
    raw[y * (W * 4 + 1)] = 0;
    px.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4); ihdr[8] = 8; ihdr[9] = 6;
  fs.writeFileSync(filePath, Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

function makeCanvas(W, H) {
  const px = Buffer.alloc(W * H * 4);
  const set = (x, y, [r, g, b], a = 255) => {
    x = Math.round(x); y = Math.round(y);
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const i = (y * W + x) * 4;
    const k = a / 255;
    px[i] = Math.round(px[i] * (1 - k) + r * k);
    px[i + 1] = Math.round(px[i + 1] * (1 - k) + g * k);
    px[i + 2] = Math.round(px[i + 2] * (1 - k) + b * k);
    px[i + 3] = Math.max(px[i + 3], a);
  };
  const rect = (x0, y0, w, h, col, r = 3, a = 255) => {
    for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) {
      const dx = Math.max(x0 + r - x, 0, x - (x0 + w - 1 - r));
      const dy = Math.max(y0 + r - y, 0, y - (y0 + h - 1 - r));
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d <= r) set(x, y, col, d > r - 1 ? Math.round(a * (r - d)) : a);
    }
  };
  return { px, set, rect };
}

// 1. Icon (128x128): Deep violet-indigo Terraform state & dependency graph badge
{
  const W = 128, H = 128, R = 22;
  const { px, set, rect } = makeCanvas(W, H);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const dx = Math.max(R - x, 0, x - (W - 1 - R)), dy = Math.max(R - y, 0, y - (H - 1 - R));
    const d = Math.sqrt(dx * dx + dy * dy);
    if (d <= R) set(x, y, mix(hex('#2E1065'), hex('#111827'), y / H), d > R - 1 ? Math.round(255 * (R - d)) : 255);
  }
  // Top state header bar
  rect(14, 15, 100, 16, hex('#7C3AED'), 4);
  rect(20, 20, 44, 6, hex('#EDE9FE'), 2);
  rect(86, 20, 22, 6, hex('#34D399'), 2);

  // Resource nodes + dependency connector lines
  rect(14, 40, 44, 22, hex('#1F2937'), 4);
  rect(20, 46, 30, 5, hex('#A78BFA'), 2);
  rect(20, 54, 20, 4, hex('#9CA3AF'), 2);

  rect(58, 49, 12, 4, hex('#60A5FA'), 1);

  rect(70, 40, 44, 22, hex('#1F2937'), 4);
  rect(76, 46, 30, 5, hex('#38BDF8'), 2);
  rect(76, 54, 22, 4, hex('#34D399'), 2);

  // Second row: DB node (masked secret shield) + S3 node
  rect(34, 62, 4, 10, hex('#60A5FA'), 1);
  rect(90, 62, 4, 10, hex('#60A5FA'), 1);

  rect(14, 72, 44, 24, hex('#1F2937'), 4);
  rect(20, 78, 28, 5, hex('#F59E0B'), 2);
  rect(20, 86, 32, 4, hex('#F87171'), 2);

  rect(70, 72, 44, 24, hex('#1F2937'), 4);
  rect(76, 78, 30, 5, hex('#A78BFA'), 2);
  rect(76, 86, 26, 4, hex('#CBD5E1'), 2);

  // Bottom offline shield bar
  rect(14, 104, 100, 10, hex('#5B21B6'), 3);
  rect(22, 107, 52, 4, hex('#DDD6FE'), 2);
  rect(90, 107, 18, 4, hex('#10B981'), 2);
  writePng(path.join(__dirname, '..', 'icon.png'), W, H, px);
}

// 2. Screenshot preview (1400x900)
{
  const W = 1400, H = 900;
  const { px, rect } = makeCanvas(W, H);
  rect(0, 0, W, H, hex('#1E1E1E'), 0);
  rect(0, 0, W, 44, hex('#252526'), 0);
  rect(16, 12, 280, 20, hex('#7C3AED'), 4);
  rect(310, 14, 280, 16, hex('#475569'), 3);
  // Summary chips
  for (let i = 0; i < 5; i++) rect(16 + i * 160, 58, 145, 24, i === 4 ? hex('#B45309') : hex('#334155'), 10);
  // Toolbar
  rect(16, 94, 300, 28, hex('#2D2D30'), 3);
  rect(328, 94, 130, 28, hex('#2D2D30'), 3);
  rect(470, 94, 130, 28, hex('#2D2D30'), 3);
  rect(612, 94, 90, 28, hex('#0E639C'), 3);
  rect(714, 94, 135, 28, hex('#5B21B6'), 3);
  rect(868, 94, 165, 28, hex('#2563EB'), 3);
  rect(1045, 94, 165, 28, hex('#2563EB'), 3);
  // Left resource inventory table pane
  rect(16, 140, 860, 720, hex('#151B28'), 4);
  rect(16, 140, 860, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 14; r++) {
    const y = 184 + r * 46;
    rect(24, y, 844, 38, r === 2 ? hex('#2E1065') : (r % 2 === 0 ? hex('#1A2233') : hex('#151B28')), 2);
    rect(34, y + 13, 28, 12, hex('#94A3B8'), 2);
    rect(74, y + 13, 210, 12, hex('#A78BFA'), 2);
    rect(300, y + 13, 62, 12, r % 4 === 0 ? hex('#F59E0B') : hex('#10B981'), 2);
    rect(378, y + 13, 72, 12, hex('#38BDF8'), 2);
    rect(466, y + 13, 150, 12, hex('#CBD5E1'), 2);
    rect(632, y + 13, 130, 12, hex('#E2E8F0'), 2);
    rect(778, y + 13, 72, 12, hex('#94A3B8'), 2);
  }
  // Right attribute detail inspector pane
  rect(892, 140, 492, 720, hex('#151B28'), 4);
  rect(892, 140, 492, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 9; r++) {
    const y = 188 + r * 36;
    rect(908, y, 120, 14, hex('#A78BFA'), 2);
    rect(1042, y, 320, 14, r === 8 ? hex('#F59E0B') : hex('#E2E8F0'), 2);
  }
  // Attributes JSON block
  rect(908, 530, 460, 310, hex('#0F172A'), 4);
  for (let r = 0; r < 9; r++) {
    const y = 550 + r * 30;
    rect(924, y, 110, 12, hex('#38BDF8'), 2);
    rect(1048, y, 220, 12, r === 4 ? hex('#F87171') : hex('#94A3B8'), 2);
  }
  fs.mkdirSync(path.join(__dirname, '..', 'images'), { recursive: true });
  writePng(path.join(__dirname, '..', 'images', 'screenshot.png'), W, H, px);
}
console.log('Generated icon.png and images/screenshot.png');
