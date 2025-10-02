#!/usr/bin/env node
/**
 * Extract selected icons from tech-stack-icons package into static SVG files.
 * Usage:
 *   node scripts/extract_stack_icons.mjs [variant]
 * variant: light | dark | grayscale (default: dark)
 */
import fs from 'fs';
import path from 'path';
import url from 'url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const variantArg = (process.argv[2] || 'dark').toLowerCase();
const staticDir = path.join(root, 'app', 'static', 'icons', 'stack', variantArg);

// Ensure target dir exists
fs.mkdirSync(staticDir, { recursive: true });

// Dynamic import of esm bundle
const pkgPath = path.join(root, 'node_modules', 'tech-stack-icons', 'dist', 'index.js');
let mod;
try {
  mod = await import(url.pathToFileURL(pkgPath));
} catch (e) {
  console.error('Failed to import tech-stack-icons dist/index.js', e);
  process.exit(1);
}

// The bundle exports default React component and typed data internally; we need raw source.
// Since dist/index.js in this package appears empty in this environment snapshot, this script anticipates
// future versions where icon data is accessible (e.g., mod.iconsData or similar). If not present,
// we fallback to reading source TypeScript if available.

const variant = variantArg;
if(!['light','dark','grayscale'].includes(variant)){
  console.error('Invalid variant. Use light | dark | grayscale');
  process.exit(1);
}

// List of icons we want to extract / keep local
const ICONS = [
  'wordpress','react','laravel','vue','angular','tailwindcss','php','mysql','redis','nginx','apache',
  'cloudflare','express','drupal','joomla','woocommerce','jquery','nextjs','nuxtjs',
  // Additional plugins / libs we added custom placeholders for (may not exist in upstream package):
  'yoastseo','wpml','litespeed','ga','jqueryui','jquerymigrate'
];

// Attempt strategy: the published dist/index.js may embed a JSON-like structure or we rely on site copy.
// Placeholder extraction logic (user can customize once structure known).

if(!mod || Object.keys(mod).length === 0){
  console.warn('tech-stack-icons module appears empty; please update script once package exposes raw SVG map.');
  process.exit(0);
}

let dataGuess = null;
for(const k of Object.keys(mod)){
  const v = mod[k];
  if(v && typeof v === 'object'){
    // Heuristic: look for an object whose values have svg variants
    const values = Object.values(v);
    if(values.length && values[0] && typeof values[0] === 'object' && values[0].svg){
      dataGuess = v; break;
    }
  }
}

if(!dataGuess){
  console.warn('Could not locate icons data structure automatically. Adjust script to match package internals.');
  process.exit(0);
}

let written = 0;
for(const name of ICONS){
  const def = dataGuess[name];
  if(!def){
    console.warn('Missing icon in data map:', name);
    continue;
  }
  const svgRaw = def.svg?.[variant];
  if(!svgRaw){
    console.warn('Variant not found for', name);
    continue;
  }
  const filePath = path.join(staticDir, `${name}.svg`);
  fs.writeFileSync(filePath, svgRaw.trim() + '\n', 'utf8');
  written++;
}
console.log(`Extracted ${written} icons to ${path.relative(root, staticDir)} (variant=${variant})`);
