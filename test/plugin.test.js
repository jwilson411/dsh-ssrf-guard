/**
 * The plugin seam: that `apply` registers the one tool, that the tool the
 * registry would get behaves the way its declared contract says, and that the
 * package is shaped the way the profile installer expects.
 *
 * `apply` is handed a stub context that records registrations, and the tool is
 * driven through the same `execute` the registry calls. No profile boots, no
 * socket opens, no key is read, and nothing is written.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ToolArgsError, validateJsonSchemaValue } from '@deepseek-ai/dsh-tools'

import {
  ALLOW_HOSTS_ENV,
  ALLOW_SCHEMES_ENV,
  DEFAULT_ALLOW_SCHEMES,
  PLUGIN_NAME,
  SSRF_CHECK_TOOL_NAME,
  SsrfDeniedError,
  apply,
  createSsrfCheckTool,
  inject,
  name,
  resolveConfig,
} from '../src/index.js'

import { assertDenied, exec, stubContext } from './helpers.js'

/** The patch-row config used by most cases here. */
const CONFIG = { allowHosts: ['.example.com'], allowSchemes: ['https'] }

/**
 * Register the plugin and hand back its one tool.
 * @param config - The `config` block the patch row would supply.
 * @returns The registered tool and the stub's parts.
 */
function registerTool(config = CONFIG) {
  const parts = stubContext()
  apply(parts.ctx, config)
  assert.equal(parts.registered.length, 1)
  return { tool: parts.registered[0], ...parts }
}

test('apply registers exactly one tool, named ssrf_check', () => {
  const { ctx, registered } = stubContext()

  apply(ctx, CONFIG)

  assert.equal(registered.length, 1)
  assert.equal(registered[0].name, SSRF_CHECK_TOOL_NAME)
  assert.equal(SSRF_CHECK_TOOL_NAME, 'ssrf_check')
  assert.equal(name, 'ssrf-guard')
  assert.equal(PLUGIN_NAME, 'dsh-ssrf-guard')
  assert.deepEqual(inject, ['tools'])
})

test('apply with no config at all still registers, and denies everything', async () => {
  const { ctx, registered } = stubContext()

  apply(ctx)

  assert.equal(registered.length, 1)
  await assert.rejects(
    () => registered[0].execute({ url: 'https://example.com/' }, exec),
    (error) => error instanceof SsrfDeniedError && error.reason === 'HOST_DENIED',
  )
})

test('the registered tool declares an object parameter schema requiring `url`', () => {
  const { tool } = registerTool()

  assert.equal(tool.parameters.type, 'object')
  assert.deepEqual(tool.parameters.required, ['url'])
  assert.equal(tool.parameters.properties.url.type, 'string')
  assert.ok(tool.description.length > 0)
  // The description must not oversell what a parse-time allowlist can do.
  assert.match(tool.description, /never resolved/)
  assert.match(tool.description, /not DNS-rebinding protection/)
})

test('an allowed URL returns a value shaped by the declared output schema', async () => {
  const { tool } = registerTool()

  const value = await tool.execute({ url: 'https://foo.example.com/x' }, exec)

  assert.deepEqual(validateJsonSchemaValue(tool.output.schema, value, SSRF_CHECK_TOOL_NAME), [])
  assert.deepEqual(value, {
    ok: true,
    url: 'https://foo.example.com/x',
    host: 'foo.example.com',
    scheme: 'https',
    plugin: PLUGIN_NAME,
  })
  assert.deepEqual(tool.output.render({ url: value.url }, value), [
    { type: 'text', text: 'ssrf: allow https://foo.example.com' },
  ])
})

test('a denied URL throws the structured error instead of returning one', async () => {
  const { tool } = registerTool()

  const cases = [
    ['http://example.com', 'SCHEME_DENIED'],
    ['file:///etc/passwd', 'SCHEME_DENIED'],
    ['https://169.254.169.254/', 'LINK_LOCAL_DENIED'],
    ['https://127.0.0.1/', 'LOOPBACK_DENIED'],
    ['https://localhost/', 'LOOPBACK_DENIED'],
    ['https://[::1]/', 'LOOPBACK_DENIED'],
    ['https://evil.test/', 'HOST_DENIED'],
    ['https://notexample.com/', 'HOST_DENIED'],
    ['nonsense', 'INVALID_URL'],
  ]

  for (const [url, reason] of cases) {
    // `execute` returns a promise, so the denial arrives as a rejection; the
    // error itself is the same one the library throws.
    await assert.rejects(
      () => tool.execute({ url }, exec),
      (error) => {
        assertDenied(
          () => {
            throw error
          },
          reason,
          url,
        )
        return true
      },
      `expected SSRF_DENIED for ${url}`,
    )
  }
})

test('the tool honours an exact entry, including for loopback', async () => {
  const { tool } = registerTool({ allowHosts: ['example.com', '127.0.0.1'] })

  assert.equal((await tool.execute({ url: 'https://127.0.0.1:9000/' }, exec)).host, '127.0.0.1')
  assert.equal((await tool.execute({ url: 'https://example.com/' }, exec)).ok, true)
  await assert.rejects(
    () => tool.execute({ url: 'https://evil.example.com/' }, exec),
    (error) => error.reason === 'HOST_DENIED',
  )
})

test('invalid arguments fail loudly instead of executing', async () => {
  const { tool } = registerTool()

  for (const args of [{}, { url: 42 }, { url: null }, null, [], 'https://example.com']) {
    await assert.rejects(
      () => tool.execute(args, exec),
      (error) => {
        assert.ok(error instanceof ToolArgsError)
        assert.ok(error.violations.length > 0)
        return true
      },
      `expected ToolArgsError for ${JSON.stringify(args) ?? String(args)}`,
    )
  }
})

test('the factory takes resolved settings, so a host can drive it without a fiber', async () => {
  const tool = createSsrfCheckTool(resolveConfig({ allowHosts: ['api.vendor.test'] }, {}))

  assert.equal((await tool.execute({ url: 'https://api.vendor.test/v1' }, exec)).ok, true)
  await assert.rejects(
    () => tool.execute({ url: 'https://vendor.test/v1' }, exec),
    (error) => error.reason === 'HOST_DENIED',
  )
})

test('config defaults to the empty allowlist and https, then env, then the patch row wins', () => {
  assert.deepEqual(resolveConfig({}, {}), {
    allowHosts: [],
    allowSchemes: [...DEFAULT_ALLOW_SCHEMES],
  })

  const env = {
    [ALLOW_HOSTS_ENV]: '.env.test, other.test ,',
    [ALLOW_SCHEMES_ENV]: 'http,https',
  }
  assert.deepEqual(resolveConfig({}, env), {
    allowHosts: ['.env.test', 'other.test'],
    allowSchemes: ['http', 'https'],
  })
  assert.deepEqual(resolveConfig({ allowHosts: ['patch.test'] }, env), {
    allowHosts: ['patch.test'],
    allowSchemes: ['http', 'https'],
  })
  assert.deepEqual(resolveConfig({ allowHosts: [], allowSchemes: [] }, env), {
    // An explicitly empty list is a stated intent, not an absent key: it wins
    // over the environment and denies everything.
    allowHosts: [],
    allowSchemes: [],
  })
  // Non-string entries are dropped rather than coerced.
  assert.deepEqual(resolveConfig({ allowHosts: ['a.test', 7, null, '  '] }, {}).allowHosts, [
    'a.test',
  ])
})

test('the manifest declares the bundle patch the profile installer looks for', () => {
  const manifestPath = fileURLToPath(new URL('../package.json', import.meta.url))
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.equal(manifest.name, PLUGIN_NAME)
  assert.equal(manifest.type, 'module')
  assert.equal(manifest.devDependencies['@deepseek-ai/dsh-tools'], '0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/dsh-tools'], '^0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/cordis'], '^4.0.1')
  assert.equal(manifest.engines.node, '>=22.14.0')

  const patchPath = fileURLToPath(new URL('../cordis.patch.yml', import.meta.url))
  const patch = readFileSync(patchPath, 'utf8')
  assert.match(patch, /^- insert:$/m)
  assert.match(patch, /^ {4}- id: ssrf-guard$/m)
  assert.match(patch, new RegExp(`name: ${manifest.name}$`, 'm'))
  // The documented config keys are the ones resolveConfig actually reads.
  assert.match(patch, /allowHosts/)
  assert.match(patch, /allowSchemes/)
})
