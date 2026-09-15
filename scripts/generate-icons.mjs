#!/usr/bin/env node
/**
 * generate-icons - draws Sentinel's toolbar icons with no image dependency.
 *
 * The mark is a shield with a check inside it: "this page has been looked at", not "you are
 * safe", which is the distinction the whole project is built on. The icons are generated
 * from geometry instead of being checked in as opaque binaries, so every pixel is auditable
 * and the build stays dependency-free (no sharp, no canvas, no ImageMagick).
 *
 * Output: `public/icon/{16,32,48,96,128}.png`. WXT discovers those automatically - see
 * `discoverIcons` in wxt, which maps `public/icon/<size>.png` (and `icon-<size>.png`)
 * onto `manifest.icons`.
 *
 * Usage:
 *   node scripts/generate-icons.mjs           # write the icons
 *   node scripts/generate-icons.mjs --check   # validate the PNGs already on disk
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync, deflateSync } from 'node:zlib';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ICON_DIR = join(ROOT, 'public', 'icon');

/** Sizes Chrome and Firefox ask for; 16/32 are the toolbar, the rest are store listings. */
const SIZES = [16, 32, 48, 96, 128];

/** Palette. Dark shield so it reads on a light toolbar, bright check so it reads on a dark one. */
const RIM = [56, 189, 248]; // sky-400, the outline
const FILL_TOP = [30, 41, 59]; // slate-800
const FILL_BOTTOM = [11, 18, 32]; // near-black
const CHECK = [125, 211, 252]; // sky-300, a shade brighter than the rim

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

/** Encodes 8-bit RGBA pixels as a PNG: filter type 0 on every scanline, one IDAT chunk. */
function encodePng(size, rgba) {
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y += 1) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: truecolour with alpha
  header[10] = 0; // deflate
  header[11] = 0; // adaptive filtering
  header[12] = 0; // no interlace

  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

/**
 * Shield geometry, in a unit box. `PAD` keeps a margin so the mark never touches the icon
 * edge; the shape is a rounded rectangle whose sides taper to a point below `SHOULDER`.
 */
const PAD = 0.055;
const HALF_WIDTH = 0.4;
const SHOULDER = 0.6;
const CORNER = 0.16;
const RIM_SCALE = 0.84; // the inner shield is this much smaller, which is what draws the outline
const V_CENTER = 0.51;

function halfWidthAt(v) {
  if (v < 0) return 0;
  if (v <= SHOULDER) {
    if (v < CORNER) {
      const rise = CORNER - v;
      return HALF_WIDTH - (CORNER - Math.sqrt(Math.max(0, CORNER * CORNER - rise * rise)));
    }
    return HALF_WIDTH;
  }
  const t = Math.min(1, (v - SHOULDER) / (1 - SHOULDER));
  return HALF_WIDTH * Math.pow(1 - Math.pow(t, 1.6), 0.62);
}

function insideShield(u, v) {
  if (v < 0 || v > 1) return false;
  return Math.abs(u - 0.5) <= halfWidthAt(v);
}

/** The check mark: two capsules sharing a vertex, so the joint cannot show a seam. */
const CHECK_THICKNESS = 0.088;
const CHECK_STROKE = [
  [0.315, 0.5],
  [0.44, 0.638],
  [0.7, 0.335],
];

function distanceToSegment(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax;
  const dy = by - ay;
  const lengthSquared = dx * dx + dy * dy;
  const t = lengthSquared === 0 ? 0 : Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lengthSquared));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function insideCheck(u, v) {
  let distance = Number.POSITIVE_INFINITY;
  for (let index = 1; index < CHECK_STROKE.length; index += 1) {
    distance = Math.min(distance, distanceToSegment(u, v, CHECK_STROKE[index - 1], CHECK_STROKE[index]));
  }
  return distance <= CHECK_THICKNESS / 2;
}

function mix(top, bottom, t) {
  const clamped = Math.max(0, Math.min(1, t));
  return top.map((value, index) => value + (bottom[index] - value) * clamped);
}

/** Colour at one point, or null where the mark is transparent. Layers composite back to front. */
function sampleIcon(x, y) {
  const u = (x - PAD) / (1 - 2 * PAD);
  const v = (y - PAD) / (1 - 2 * PAD);
  if (!insideShield(u, v)) return null;

  const innerU = (u - 0.5) / RIM_SCALE + 0.5;
  const innerV = (v - V_CENTER) / RIM_SCALE + V_CENTER;
  if (!insideShield(innerU, innerV)) return RIM;
  if (insideCheck(u, v)) return CHECK;

  return mix(FILL_TOP, FILL_BOTTOM, v);
}

/** Rasterises one icon size with supersampling, so the curves survive a 16px toolbar. */
function render(size) {
  const perAxis = size >= 48 ? 4 : 8;
  const total = perAxis * perAxis;
  const rgba = Buffer.alloc(size * size * 4);

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let red = 0;
      let green = 0;
      let blue = 0;
      let hits = 0;

      for (let sy = 0; sy < perAxis; sy += 1) {
        for (let sx = 0; sx < perAxis; sx += 1) {
          const colour = sampleIcon((x + (sx + 0.5) / perAxis) / size, (y + (sy + 0.5) / perAxis) / size);
          if (colour === null) continue;
          red += colour[0];
          green += colour[1];
          blue += colour[2];
          hits += 1;
        }
      }

      const offset = (y * size + x) * 4;
      // Average only the covered samples, so partially covered edge pixels keep the right hue
      // and simply become translucent instead of darkening towards black.
      rgba[offset] = hits === 0 ? 0 : Math.round(red / hits);
      rgba[offset + 1] = hits === 0 ? 0 : Math.round(green / hits);
      rgba[offset + 2] = hits === 0 ? 0 : Math.round(blue / hits);
      rgba[offset + 3] = Math.round((hits / total) * 255);
    }
  }

  return rgba;
}

/**
 * Reads a PNG back and proves it is well formed: signature, chunk CRCs, dimensions, filter
 * bytes and decompressed length. Returns the decoded header and pixels for the checks below.
 */
function decodePng(buffer) {
  if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error('is missing the PNG signature');

  let offset = 8;
  let header = null;
  const data = [];

  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const body = buffer.subarray(offset + 4, offset + 8 + length);
    if (buffer.readUInt32BE(offset + 8 + length) !== crc32(body)) throw new Error(`has a ${type} chunk with a bad CRC`);
    if (type === 'IHDR') {
      header = {
        width: buffer.readUInt32BE(offset + 8),
        height: buffer.readUInt32BE(offset + 12),
        bitDepth: buffer[offset + 16],
        colourType: buffer[offset + 17],
      };
    }
    if (type === 'IDAT') data.push(buffer.subarray(offset + 8, offset + 8 + length));
    offset += length + 12;
    if (type === 'IEND') break;
  }

  if (header === null) throw new Error('has no IHDR chunk');
  return { ...header, pixels: inflateSync(Buffer.concat(data)) };
}

/** Structural and sanity checks: the file must be a real PNG, and it must not be blank. */
function checkIcon(size) {
  const decoded = decodePng(readFileSync(join(ICON_DIR, `${size}.png`)));

  if (decoded.width !== size || decoded.height !== size) {
    throw new Error(`is ${decoded.width}x${decoded.height}, expected ${size}x${size}`);
  }
  if (decoded.bitDepth !== 8 || decoded.colourType !== 6) throw new Error('is not 8-bit RGBA');

  const stride = size * 4;
  const expected = (stride + 1) * size;
  if (decoded.pixels.length !== expected) {
    throw new Error(`decodes to ${decoded.pixels.length} bytes, expected ${expected}`);
  }

  const alphaAt = (x, y) => decoded.pixels[y * (stride + 1) + 1 + x * 4 + 3];
  let opaque = 0;
  for (let y = 0; y < size; y += 1) {
    const rowStart = y * (stride + 1);
    if (decoded.pixels[rowStart] !== 0) throw new Error(`row ${y} uses an unexpected filter type`);
    for (let x = 0; x < size; x += 1) if (alphaAt(x, y) === 255) opaque += 1;
  }

  const coverage = opaque / (size * size);
  // The mark has to be inset (empty corners), solid in the middle, and actually present.
  if (alphaAt(0, 0) !== 0 || alphaAt(size - 1, size - 1) !== 0) {
    throw new Error('has an opaque corner, so the mark is bleeding to the edge');
  }
  if (alphaAt(size >> 1, size >> 1) !== 255) throw new Error('is not solid at its centre');
  if (coverage < 0.2 || coverage > 0.8) {
    throw new Error(`is ${(coverage * 100).toFixed(1)}% opaque, which is not a shield shape`);
  }

  return { coverage, bytes: readFileSync(join(ICON_DIR, `${size}.png`)).length };
}

function main() {
  if (process.argv.includes('--check')) {
    console.log('generate-icons --check - validating public/icon/*.png.');
    let failed = false;
    for (const size of SIZES) {
      try {
        const { coverage, bytes } = checkIcon(size);
        console.log(`  ok    ${size}x${size}  ${bytes} bytes, ${(coverage * 100).toFixed(1)}% opaque`);
      } catch (error) {
        failed = true;
        console.log(`  FAIL  ${size}x${size}  public/icon/${size}.png ${error.message}`);
      }
    }
    if (failed) {
      console.log('\nFAIL  Regenerate the icons with `npm run icons`.');
      process.exitCode = 1;
      return;
    }
    console.log('\nOK  Every icon is a valid, non-blank 8-bit RGBA PNG.');
    return;
  }

  mkdirSync(ICON_DIR, { recursive: true });
  for (const size of SIZES) {
    const file = join(ICON_DIR, `${size}.png`);
    writeFileSync(file, encodePng(size, render(size)));
    // Check what was just written, so a broken encoder cannot pass silently.
    const { bytes, coverage } = checkIcon(size);
    console.log(`  wrote  public/icon/${size}.png  ${bytes} bytes, ${(coverage * 100).toFixed(1)}% opaque`);
  }
  console.log(`\nOK  ${SIZES.length} icon(s) written. WXT adds them to manifest.icons on the next build.`);
  console.log('    Add `node scripts/generate-icons.mjs --check` to CI if you edit the geometry.');
}

main();

