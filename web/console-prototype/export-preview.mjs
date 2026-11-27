// Package the real Angular production output as a portable, offline demo document.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
const output = resolve(root, 'dist/agp-console/browser');
const imageAssets = new Map();
for (const name of ['nlgate-logo.png', 'nlgate-icon.png']) {
  const bytes = await readFile(resolve(output, name));
  if (bytes.length > 1024 * 1024 || !bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    throw new Error(`Unexpected PNG asset: ${name}`);
  }
  imageAssets.set(name, `data:image/png;base64,${bytes.toString('base64')}`);
}
let html = await readFile(resolve(output, 'index.html'), 'utf8');
const scriptRefs = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"[^>]*><\/script>/g)];
const styleRefs = [...html.matchAll(/<link\b[^>]*\brel="stylesheet"[^>]*>/g)];
for (const [tag, source] of scriptRefs) {
  if (!/^[\w.-]+\.js$/.test(source)) throw new Error(`Unexpected script reference: ${source}`);
  let script = await readFile(resolve(output, source), 'utf8');
  if (/\b(?:from\s*|import\s*\()["']\.\//.test(script)) throw new Error('Split bundles need an explicit offline packager.');
  for (const [name, dataURL] of imageAssets) script = script.replaceAll(name, dataURL);
  html = html.replace(tag, `<script type="module">${script.replace(/<\/script/gi, '<\\/script')}</script>`);
}
for (const [tag] of styleRefs) {
  const source = tag.match(/\bhref="([^"]+)"/)?.[1];
  if (!source || !/^[\w.-]+\.css$/.test(source)) throw new Error('Unexpected stylesheet reference');
  const css = await readFile(resolve(output, source), 'utf8');
  html = html.replace(tag, `<style>${css.replace(/<\/style/gi, '<\\/style')}</style>`);
}
html = html.replace(/<base href="[^"]*"\s*\/?\s*>/, '<base href="./">');
html = html.replace(/<link\b[^>]*\brel="modulepreload"[^>]*>/g, '');
for (const [name, dataURL] of imageAssets) html = html.replaceAll(name, dataURL);
await writeFile(resolve(root, 'preview.html'), html);
console.log(`Portable Angular demo: preview.html (${Math.round(Buffer.byteLength(html) / 1024)} KiB)`);
