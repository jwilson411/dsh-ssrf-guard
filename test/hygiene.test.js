/**
 * Repository hygiene, asserted rather than promised.
 *
 * Two claims are made about this package in the README, and both are cheap
 * enough to check on every run: the tree carries no private hostnames, machine
 * names, or credentials from wherever it was written, and the shipped source
 * opens nothing — no resolver, no socket, no fetch. A guard that quietly
 * resolved a hostname would falsify the whole design, so the check is a test
 * and not a comment.
 *
 * The forbidden literals are assembled from fragments so that this file does
 * not itself trip the scan it performs.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

/** The package root, walked below. */
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Directories never worth scanning: not ours, or not text. */
const SKIP_DIRS = new Set(['node_modules', '.git'])

/** Extensions with no text worth scanning. */
const BINARY_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2'])

/**
 * Every checked-in text file, repo-relative.
 * @returns Paths relative to the package root, in directory order.
 */
function repoFiles() {
  return readdirSync(ROOT, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(ROOT, join(entry.parentPath ?? entry.path, entry.name)))
    .filter((path) => !path.split(sep).some((segment) => SKIP_DIRS.has(segment)))
    .filter((path) => !BINARY_EXTENSIONS.has(extname(path)))
}

/**
 * Read a repo file as text.
 * @param path - A repo-relative path.
 * @returns Its contents.
 */
function readRepoFile(path) {
  return readFileSync(join(ROOT, path), 'utf8')
}

/**
 * The literals and shapes that must not appear anywhere in the tree, each
 * built from fragments so this file is not its own counterexample.
 */
const FORBIDDEN = [
  { what: 'a private machine name', pattern: new RegExp(['def', 'iant'].join(''), 'i') },
  { what: 'a host-local mount path', pattern: /\/mnt\/[a-z]/i },
  { what: 'a CI token variable', pattern: new RegExp(['GITHUB', 'TOKEN'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['ANTHROPIC', 'API', 'KEY'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['OPENAI', 'API', 'KEY'].join('_')) },
  { what: 'an API key literal', pattern: /\bsk-[a-z0-9]{2,10}-[A-Za-z0-9_-]{16,}/ },
  { what: 'a private key block', pattern: new RegExp(['BEGIN', 'PRIVATE', 'KEY'].join(' ')) },
  { what: 'an AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { what: 'a bearer token literal', pattern: /\bBearer [A-Za-z0-9._-]{20,}/ },
]

test('the tree carries no machine names, mount paths, or credentials', () => {
  const offences = []

  for (const path of repoFiles()) {
    const text = readRepoFile(path)
    for (const { what, pattern } of FORBIDDEN) {
      const hit = pattern.exec(text)
      if (hit !== null) offences.push(`${path}: ${what} (${hit[0].slice(0, 24)})`)
    }
  }

  assert.deepEqual(offences, [])
})

test('the scan actually covers the files it claims to', () => {
  const files = repoFiles()

  for (const expected of [
    'package.json',
    'cordis.patch.yml',
    'README.md',
    'LICENSE',
    join('src', 'index.js'),
    join('src', 'ssrf.js'),
  ]) {
    assert.ok(files.includes(expected), `hygiene scan missed ${expected}`)
  }
  assert.equal(
    files.some((path) => path.startsWith('node_modules')),
    false,
  )
})

test('the shipped source opens nothing: no resolver, no socket, no fetch', () => {
  // The production claim is parse-only. These are the ways a guard could
  // accidentally acquire an egress path of its own.
  const banned = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    new RegExp(`\\b${['dns', 'lookup'].join('\\.')}\\b`),
    new RegExp(`\\b${['dns', 'resolve'].join('\\.')}`),
    /\bnode:(dns|net|tls|http|https|dgram|child_process)\b/,
    /\brequire\s*\(/,
    /\bimport\s*\(/,
  ]

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, `${path} matches ${pattern}`)
    }
  }
})

test('the shipped source imports only the pinned tools package and its own files', () => {
  const specifiers = []

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const match of text.matchAll(/^\s*(?:import|export)[^'"\n]*from\s*'([^']+)'/gm)) {
      specifiers.push(match[1])
    }
  }

  assert.ok(specifiers.length > 0)
  for (const specifier of specifiers) {
    assert.ok(
      specifier === '@deepseek-ai/dsh-tools' || specifier.startsWith('./'),
      `unexpected import ${specifier}`,
    )
  }
})

test('CI needs no credentials', () => {
  const workflow = readRepoFile(join('.github', 'workflows', 'ci.yml'))

  assert.match(workflow, /contents: read/)
  assert.match(workflow, /npm ci/)
  assert.match(workflow, /npm test/)
  assert.match(workflow, /'22\.x', '24\.x'/)
  assert.equal(/secrets\./.test(workflow), false)
})
