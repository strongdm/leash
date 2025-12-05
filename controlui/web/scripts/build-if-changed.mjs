#!/usr/bin/env node
import { createHash } from 'crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'fs'
import { dirname, join, relative, resolve } from 'path'
import { spawnSync } from 'child_process'

const projectRoot = resolve(new URL('..', import.meta.url).pathname)

const IGNORES = new Set(['node_modules', 'dist', 'out', 'build', 'coverage', '.git', '.next', '.vite', '.tmp'])

function gatherFiles(base, rel = '.') {
  const dir = join(base, rel)
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return []
  }
  const files = []
  for (const entry of entries) {
    if (IGNORES.has(entry.name)) continue
    const relPath = rel === '.' ? entry.name : join(rel, entry.name)
    const absPath = join(base, relPath)
    if (entry.isDirectory()) {
      files.push(...gatherFiles(base, relPath))
    } else if (entry.isFile()) {
      files.push(absPath)
    }
  }
  return files
}

function addIfExists(list, candidate) {
  if (existsSync(candidate)) list.push(candidate)
}

function computeHash(root) {
  const inputs = []
  addIfExists(inputs, join(root, 'index.html'))
  addIfExists(inputs, join(root, 'package.json'))
  addIfExists(inputs, join(root, 'pnpm-lock.yaml'))
  addIfExists(inputs, join(root, 'package-lock.json'))
  addIfExists(inputs, join(root, 'yarn.lock'))
  addIfExists(inputs, join(root, '.npmrc'))
  for (const cfg of ['tsconfig.json', 'tsconfig.app.json', 'tsconfig.node.json']) {
    addIfExists(inputs, join(root, cfg))
  }
  addIfExists(inputs, join(root, 'vite.config.ts'))
  if (existsSync(join(root, 'src'))) inputs.push(...gatherFiles(join(root, 'src')))
  if (existsSync(join(root, 'public'))) inputs.push(...gatherFiles(join(root, 'public')))

  inputs.sort()
  const hash = createHash('sha256')
  for (const absPath of inputs) {
    const relPath = relative(root, absPath)
    hash.update(relPath)
    try {
      const contents = readFileSync(absPath)
      hash.update(contents)
      const stats = statSync(absPath)
      hash.update(String(stats.size))
      hash.update(String(stats.mtimeMs))
    } catch {
      // Skip transient files
    }
  }
  return hash.digest('hex')
}

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { stdio: 'inherit', shell: false, ...opts })
  if (result.status !== 0) {
    process.exit(result.status ?? 1)
  }
}

function parseArgs(argv) {
  let outDir = null
  let hashPath = null
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--out' && i + 1 < argv.length) {
      outDir = resolve(argv[i + 1])
      i += 1
    } else if (arg === '--hash' && i + 1 < argv.length) {
      hashPath = resolve(argv[i + 1])
      i += 1
    }
  }
  return { outDir, hashPath }
}

const { outDir, hashPath } = parseArgs(process.argv)
const force = process.argv.includes('--force')
if (!outDir) {
  console.error('Usage: build-if-changed.mjs --out <path>')
  process.exit(1)
}

const hashFile = hashPath ?? join(projectRoot, '.buildhash')
const previousHash = existsSync(hashFile) ? readFileSync(hashFile, 'utf8').trim() : ''
const nextHash = computeHash(projectRoot)

const distIndex = join(outDir, 'index.html')
const needsBuild = force || !existsSync(distIndex) || previousHash !== nextHash

if (!needsBuild) {
  console.log('[ui] No relevant changes detected; skipping build.')
  process.exit(0)
}

console.log('[ui] Changes detected; running build...')
run('pnpm', ['lint'], { cwd: projectRoot })
run('pnpm', ['build'], { cwd: projectRoot })

// Next.js 16 creates _not-found/ with only .txt metadata files that Go's embed
// directive cannot embed. Add a placeholder file so the directory is embeddable.
// Note: Go embed ignores files starting with "." so we use "keep" not ".keep".
const notFoundDir = join(projectRoot, 'out', '_not-found')
if (existsSync(notFoundDir)) {
  writeFileSync(join(notFoundDir, 'keep'), '')
}

try {
  mkdirSync(outDir, { recursive: true })
} catch {}

run('bash', ['-lc', `set -euo pipefail; rm -rf /tmp/ui-out && mkdir -p /tmp/ui-out && cp -R out/. /tmp/ui-out/ && mkdir -p "${outDir}" && rm -rf "${outDir}"/* && cp -R /tmp/ui-out/. "${outDir}/"`], {
  cwd: projectRoot,
})

try {
  mkdirSync(dirname(hashFile), { recursive: true })
} catch {}
writeFileSync(hashFile, `${nextHash}\n`)
console.log('[ui] Build complete; hash updated.')
