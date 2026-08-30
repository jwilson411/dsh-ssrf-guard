/**
 * The allowlist itself: what `assertUrlAllowed` admits and what it denies.
 *
 * Every case here is a URL **parse**. No resolver is consulted, no socket is
 * opened, and no fixture reaches a network — the whole point of checking the
 * hostname as written is that the decision is a pure function of the string.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  DEFAULT_ALLOW_SCHEMES,
  PLUGIN_NAME,
  REASONS,
  SSRF_DENIED,
  SsrfDeniedError,
  assertUrlAllowed,
  checkUrl,
  classifyHost,
  hostIsAllowed,
  hostMatchesEntry,
  normalizeHost,
  normalizeScheme,
} from '../src/ssrf.js'

import { assertDenied } from './helpers.js'

/** A config allowing one exact host over https. */
const EXACT = { allowHosts: ['example.com'], allowSchemes: ['https'] }

/** A config allowing a domain and its subdomains over https. */
const SUFFIX = { allowHosts: ['.example.com'], allowSchemes: ['https'] }

test('an allowed URL comes back as the structured allow record', () => {
  const value = assertUrlAllowed('https://example.com/a', EXACT)

  assert.deepEqual(value, {
    ok: true,
    url: 'https://example.com/a',
    host: 'example.com',
    scheme: 'https',
    plugin: PLUGIN_NAME,
  })
  assert.deepEqual(assertUrlAllowed('https://example.com/a', SUFFIX), value)
})

test('the scheme allowlist defaults to https only, so http is denied', () => {
  assert.deepEqual(DEFAULT_ALLOW_SCHEMES, ['https'])
  assert.equal(assertUrlAllowed('https://example.com/', { allowHosts: ['example.com'] }).ok, true)

  const error = assertDenied(
    () => assertUrlAllowed('http://example.com', EXACT),
    'SCHEME_DENIED',
    'http://example.com',
  )
  assert.equal(error.scheme, 'http')
  assert.equal(error.host, 'example.com')
})

test('http is allowed only when the config asks for it explicitly', () => {
  const value = assertUrlAllowed('http://example.com/x', {
    allowHosts: ['example.com'],
    allowSchemes: ['http', 'https'],
  })

  assert.equal(value.ok, true)
  assert.equal(value.scheme, 'http')
})

test('file: is denied even with a permissive host list', () => {
  const error = assertDenied(
    () => assertUrlAllowed('file:///etc/passwd', { allowHosts: ['.example.com', ''] }),
    'SCHEME_DENIED',
    'file:///etc/passwd',
  )
  assert.equal(error.scheme, 'file')
  assert.equal(error.host, null)
})

test('the cloud metadata address is denied', () => {
  for (const url of ['https://169.254.169.254/', 'https://169.254.169.254/latest/meta-data/']) {
    const error = assertDenied(() => assertUrlAllowed(url, EXACT), 'LINK_LOCAL_DENIED', url)
    assert.equal(error.host, '169.254.169.254')
    assert.match(error.message, /169\.254\.169\.254/)
  }
})

test('a suffix rule does not unlock the metadata address; an exact entry does', () => {
  assertDenied(
    () => assertUrlAllowed('https://169.254.169.254/', { allowHosts: ['.254'] }),
    'LINK_LOCAL_DENIED',
    'https://169.254.169.254/',
  )

  assert.equal(
    assertUrlAllowed('https://169.254.169.254/', { allowHosts: ['169.254.169.254'] }).ok,
    true,
  )
})

test('an unlisted host is denied', () => {
  const error = assertDenied(
    () => assertUrlAllowed('https://evil.test/x', EXACT),
    'HOST_DENIED',
    'https://evil.test/x',
  )
  assert.equal(error.host, 'evil.test')
  assert.equal(error.scheme, 'https')
})

test('an empty allowlist allows nothing — that is the fail-closed default', () => {
  for (const config of [{}, { allowHosts: [] }, { allowHosts: ['', '  '] }, undefined]) {
    assertDenied(
      () => assertUrlAllowed('https://example.com/', config),
      'HOST_DENIED',
      'https://example.com/',
    )
  }
  assert.match(
    checkUrl('https://example.com/', {}).message,
    /the allowlist is empty/,
  )
})

test('loopback is denied unless it is named exactly', () => {
  for (const url of [
    'https://127.0.0.1/',
    'https://127.0.0.1:8080/admin',
    'https://localhost/',
    'https://[::1]/',
    'https://0.0.0.0/',
  ]) {
    assertDenied(() => assertUrlAllowed(url, SUFFIX), 'LOOPBACK_DENIED', url)
  }

  assert.equal(assertUrlAllowed('https://127.0.0.1/', { allowHosts: ['127.0.0.1'] }).ok, true)
  assert.equal(assertUrlAllowed('https://localhost/', { allowHosts: ['localhost'] }).ok, true)
  assert.equal(assertUrlAllowed('https://[::1]/', { allowHosts: ['::1'] }).host, '::1')
  // The config may write the address either way; the brackets normalize away.
  assert.equal(assertUrlAllowed('https://[::1]/', { allowHosts: ['[::1]'] }).host, '::1')
})

test('a suffix rule never unlocks loopback', () => {
  assertDenied(
    () => assertUrlAllowed('https://localhost/', { allowHosts: ['.localhost'] }),
    'LOOPBACK_DENIED',
    'https://localhost/',
  )
  assertDenied(
    () => assertUrlAllowed('https://app.localhost/', { allowHosts: ['.localhost'] }),
    'LOOPBACK_DENIED',
    'https://app.localhost/',
  )
})

test('a suffix rule covers subdomains and the bare domain, and nothing that merely ends in it', () => {
  assert.equal(assertUrlAllowed('https://foo.example.com/x', SUFFIX).host, 'foo.example.com')
  assert.equal(assertUrlAllowed('https://a.b.example.com/x', SUFFIX).host, 'a.b.example.com')
  assert.equal(assertUrlAllowed('https://example.com/x', SUFFIX).host, 'example.com')

  for (const url of ['https://notexample.com', 'https://example.com.evil.test/']) {
    assertDenied(() => assertUrlAllowed(url, SUFFIX), 'HOST_DENIED', url)
  }
})

test('an exact rule covers only itself, never a subdomain', () => {
  assertDenied(
    () => assertUrlAllowed('https://evil.example.com', EXACT),
    'HOST_DENIED',
    'https://evil.example.com',
  )
  assertDenied(
    () => assertUrlAllowed('https://example.com.evil.test/', EXACT),
    'HOST_DENIED',
    'https://example.com.evil.test/',
  )
})

test('host comparison is case-insensitive, and a trailing root dot cannot slip past', () => {
  assert.equal(assertUrlAllowed('https://EXAMPLE.COM/a', EXACT).host, 'example.com')
  assert.equal(assertUrlAllowed('https://Foo.Example.COM/a', SUFFIX).host, 'foo.example.com')
  assert.equal(assertUrlAllowed('https://example.com./a', EXACT).host, 'example.com')
  assert.equal(assertUrlAllowed('https://example.com/a', { allowHosts: ['ExAmPlE.CoM'] }).ok, true)
  assert.equal(assertUrlAllowed('https://HTTPS.example.com/a', SUFFIX).ok, true)
})

test('a port is not part of the match', () => {
  assert.equal(assertUrlAllowed('https://example.com:8443/a', EXACT).host, 'example.com')
})

test('an unparseable or relative URL is denied rather than guessed at', () => {
  for (const url of ['/etc/passwd', 'example.com/a', 'not a url', '', 'https://']) {
    assertDenied(() => assertUrlAllowed(url, EXACT), 'INVALID_URL', url)
  }
})

test('a URL carrying credentials is denied', () => {
  const url = 'https://user:pass@example.com/a'
  const error = assertDenied(() => assertUrlAllowed(url, EXACT), 'CREDENTIALS_DENIED', url)
  assert.equal(error.host, 'example.com')

  // The classic confusion: the allowed name appears, but it is the userinfo.
  assertDenied(
    () => assertUrlAllowed('https://example.com@evil.test/', EXACT),
    'CREDENTIALS_DENIED',
    'https://example.com@evil.test/',
  )
})

test('a scheme with no host is denied for the scheme, or for the missing host', () => {
  assertDenied(() => assertUrlAllowed('data:text/plain,hi', EXACT), 'SCHEME_DENIED', 'data:text/plain,hi')
  // Not an empty host: the parser collapses the extra slash and reads `a` as
  // the hostname, with `/` as the path. So this is an ordinary unlisted host,
  // and the denial says so rather than blaming the syntax.
  const collapsed = assertDenied(
    () => assertUrlAllowed('https:///a', { allowHosts: ['example.com'] }),
    'HOST_DENIED',
    'https:///a',
  )
  assert.equal(collapsed.host, 'a')
  // A scheme the URL parser treats as opaque parses, allows, and still has no
  // host to check — the allowlist has nothing to match, so it denies.
  const url = 'mailto:someone@example.com'
  assertDenied(
    () => assertUrlAllowed(url, { allowHosts: ['example.com'], allowSchemes: ['mailto'] }),
    'HOST_MISSING',
    url,
  )
})

test('every denial carries the one code, and a reason from the documented set', () => {
  const cases = [
    ['not a url', EXACT],
    ['http://example.com', EXACT],
    ['file:///etc/passwd', EXACT],
    ['https://user:pass@example.com/', EXACT],
    ['https://127.0.0.1/', EXACT],
    ['https://169.254.169.254/', EXACT],
    ['https://evil.test/', EXACT],
    ['mailto:a@example.com', { allowHosts: ['example.com'], allowSchemes: ['mailto'] }],
  ]

  for (const [url, config] of cases) {
    assert.throws(
      () => assertUrlAllowed(url, config),
      (error) => {
        assert.ok(error instanceof SsrfDeniedError)
        assert.equal(error.name, 'SsrfDeniedError')
        assert.equal(error.code, SSRF_DENIED)
        assert.ok(REASONS.includes(error.reason), `undocumented reason ${error.reason}`)
        return true
      },
      `expected a denial for ${url}`,
    )
  }
})

test('checkUrl is the same decision, returned instead of thrown', () => {
  assert.deepEqual(checkUrl('https://example.com/a', EXACT), {
    ok: true,
    url: 'https://example.com/a',
    host: 'example.com',
    scheme: 'https',
    plugin: PLUGIN_NAME,
  })

  const denied = checkUrl('http://example.com/a', EXACT)
  assert.equal(denied.ok, false)
  assert.equal(denied.reason, 'SCHEME_DENIED')
  assert.equal(denied.scheme, 'http')
})

test('a malformed config shrinks towards denying rather than growing towards allowing', () => {
  for (const allowHosts of ['example.com', null, { 'example.com': true }, undefined]) {
    assertDenied(
      () => assertUrlAllowed('https://example.com/', { allowHosts }),
      'HOST_DENIED',
      'https://example.com/',
    )
  }
  // A non-list allowSchemes falls back to the default rather than to anything.
  assertDenied(
    () => assertUrlAllowed('http://example.com/', { allowHosts: ['example.com'], allowSchemes: 'http' }),
    'SCHEME_DENIED',
    'http://example.com/',
  )
})

test('the matching helpers are the whole rule, and are testable on their own', () => {
  assert.equal(hostMatchesEntry('example.com', 'example.com'), true)
  assert.equal(hostMatchesEntry('evil.example.com', 'example.com'), false)
  assert.equal(hostMatchesEntry('foo.example.com', '.example.com'), true)
  assert.equal(hostMatchesEntry('example.com', '.example.com'), true)
  assert.equal(hostMatchesEntry('notexample.com', '.example.com'), false)
  assert.equal(hostMatchesEntry('example.com', ''), false)
  assert.equal(hostMatchesEntry('example.com', '.'), false)
  assert.equal(hostMatchesEntry('', 'example.com'), false)
  assert.equal(hostMatchesEntry('example.com', 42), false)

  assert.equal(hostIsAllowed('foo.example.com', ['other.test', '.example.com']), true)
  assert.equal(hostIsAllowed('foo.example.com', []), false)

  assert.equal(normalizeHost('  EXAMPLE.com. '), 'example.com')
  assert.equal(normalizeHost('[::1]'), '::1')
  assert.equal(normalizeHost(undefined), '')
  assert.equal(normalizeScheme('HTTPS:'), 'https')
  assert.equal(normalizeScheme('https'), 'https')

  assert.equal(classifyHost('127.0.0.9'), 'LOOPBACK')
  assert.equal(classifyHost('::1'), 'LOOPBACK')
  assert.equal(classifyHost('169.254.169.254'), 'LINK_LOCAL')
  assert.equal(classifyHost('fe80::1'), 'LINK_LOCAL')
  assert.equal(classifyHost('example.com'), null)
})
