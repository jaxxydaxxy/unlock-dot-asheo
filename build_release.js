#!/usr/bin/env node
/*
 * Build the release archives of both extensions.
 *
 *   node build_release.js [outdir]
 *
 * For every extension it takes the *official* source tree from
 * extensions/, patches it, and writes a zip that can be loaded with
 * chrome://extensions -> Load unpacked:
 *
 *   extensions/dot-bypasser/  ->  unlock_dot.js + tools/fix_guards.js
 *   extensions/asheo/         ->  tools/asheo_unlock.js
 *
 * The result:
 *
 *   <outdir>/dot-bypasser-4.6.6-unlocked.zip
 *   <outdir>/asheo-1.6.2-unlocked.zip
 *
 * The sources are the official releases. They are patched here rather than
 * committed in patched form, so every release is reproducible from the same
 * input and the build fails loudly if a release changes the patch sites.
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname);
const OUT = path.resolve(process.argv[2] || path.join(ROOT, 'dist'));
const EXTENSIONS = path.join(ROOT, 'extensions');

/** the extensions that are built, in the order they are released */
const TARGETS = [
  {
    id: 'dot-bypasser',
    name: 'Dot Bypasser',
    source: 'dot-bypasser',
    /* the patcher, then the guard repair (the guards hash the source text,
     * so they have to be recomputed after the edits) */
    steps: [
      { file: 'unlock_dot.js', args: [] },
      { file: 'tools/fix_guards.js', args: ['--experimental-vm-modules'] },
    ],
  },
  {
    id: 'asheo',
    name: 'Asheo',
    source: 'asheo',
    steps: [
      { file: 'tools/asheo_unlock.js', args: [] },
    ],
  },
];

function fail(msg) {
  console.error('build_release: ' + msg);
  process.exit(1);
}

/** the version of an extension, from its manifest */
function versionOf(dir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  return manifest.version || 'unknown';
}

/** the name of the extension, from its manifest */
function nameOf(dir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  return manifest.name || 'extension';
}

function run(script, args, tree) {
  /* the patchers take the tree to patch as their first argument */
  const nodeArgs = script.endsWith('.mjs')
    ? args.slice()
    : args.slice();
  if (!script.endsWith('.mjs')) nodeArgs.push(path.join(ROOT, script));
  nodeArgs.push(tree);
  console.log('  $ node ' + nodeArgs.map((a) => a.replace(ROOT, '.')).join(' '));
  execFileSync(process.execPath, nodeArgs, {
    cwd: ROOT,
    stdio: 'inherit',
    env: { ...process.env, NODE_OPTIONS: '' },
  });
}

/** zip a directory into <out>/<name>.zip, with the tree at the top level */
function zipDir(dir, outFile, folder) {
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'rel-'));
  try {
    fs.cpSync(dir, path.join(stage, folder), { recursive: true });
    fs.rmSync(outFile, { force: true });
    execFileSync('zip', ['-r', '-q', '-9', outFile, folder], { cwd: stage });
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}

console.log('build_release');
console.log('  sources : ' + EXTENSIONS);
console.log('  output  : ' + OUT);

fs.mkdirSync(OUT, { recursive: true });

const built = [];

for (const target of TARGETS) {
  const src = path.join(EXTENSIONS, target.source);
  if (!fs.existsSync(path.join(src, 'manifest.json'))) {
    fail('no source tree for ' + target.name + ' (expected ' + src + '/manifest.json)');
  }

  console.log('');
  console.log('[' + target.name + ']');

  /* patch a copy, so the sources stay untouched */
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'rel-'));
  const tree = path.join(work, 'ext');
  fs.cpSync(src, tree, { recursive: true });

  try {
    for (const step of target.steps) {
      run(step.file, step.args, tree);
    }

    const version = versionOf(tree);
    const zip = path.join(OUT, target.id + '-' + version + '-unlocked.zip');
    zipDir(tree, zip, target.id);
    const size = fs.statSync(zip).size;
    built.push({ id: target.id, version, name: nameOf(tree), file: path.basename(zip), size });

    console.log('  built   : ' + path.basename(zip) + ' (' + Math.round(size / 1024) + ' KB)');
  } catch (e) {
    fail('building ' + target.name + ' failed: ' + (e && e.message ? e.message : e));
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

console.log('');
console.log('done:');
for (const b of built) {
  console.log('  ' + b.file + '  (' + b.name + ' ' + b.version + ')');
}
