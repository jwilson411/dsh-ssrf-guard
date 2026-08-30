/**
 * dsh-ssrf-guard — a DeepSeek Harness function plugin holding outbound URLs to
 * a fail-closed host and scheme allowlist, checked **before** a request is
 * opened.
 *
 * The library API is {@link assertUrlAllowed}: hand it a URL string and the
 * allowlist, and it either returns a small allow record or throws an
 * `SsrfDeniedError` carrying `code: 'SSRF_DENIED'`. A denied host never leaves
 * the box, because nothing in this package opens a socket: it performs no name
 * resolution and builds no request. `test/hygiene.test.js` asserts that.
 *
 * **This is a URL-host allowlist, not DNS-rebinding protection and not a WAF.**
 * The hostname is checked as written in the URL, never after resolution. See
 * the README for what that does and does not buy you.
 *
 * The pinned DSH release candidate, `0.1.1-rc.2`, exposes no HTTP or fetch
 * intercept seam, so the plugin does not invent one: it registers exactly one
 * model-facing tool, `ssrf_check`, against the `tools` service and exports the
 * assertion for a host to call at its own egress point. Registration happens
 * inside `apply` so the Cordis fiber owns the effect: stopping, updating, or
 * reloading the plugin unregisters the tool with no bookkeeping here. Named
 * exports preserve the loader's injection metadata.
 *
 * @module dsh-ssrf-guard
 */
import { defineTool } from '@deepseek-ai/dsh-tools'

import { DEFAULT_ALLOW_SCHEMES, PLUGIN_NAME, assertUrlAllowed } from './ssrf.js'

export {
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
} from './ssrf.js'

/** The one model-facing tool name this plugin owns. */
export const SSRF_CHECK_TOOL_NAME = 'ssrf_check'

/** Cordis plugin name, used in loader diagnostics and the runtime plugin tree. */
export const name = 'ssrf-guard'

/**
 * `tools` is a hard dependency: with no registry there is nothing for this
 * plugin to do, so it waits rather than degrading.
 */
export const inject = ['tools']

/** Environment fallback for the host allowlist: a comma-separated list. */
export const ALLOW_HOSTS_ENV = 'DSH_SSRF_ALLOW_HOSTS'

/** Environment fallback for the scheme allowlist: a comma-separated list. */
export const ALLOW_SCHEMES_ENV = 'DSH_SSRF_ALLOW_SCHEMES'

/**
 * Read a comma-separated environment list into entries, dropping blanks.
 * @param value - The raw environment value, if set.
 * @returns The entries, or null when the variable was not set at all.
 */
function parseEnvList(value) {
  if (typeof value !== 'string') return null
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
}

/**
 * Coerce a configured list into trimmed non-empty strings, or null when the
 * value is not a list at all.
 *
 * Anything unusable is dropped rather than coerced: a malformed allowlist
 * should shrink towards denying, never grow towards allowing.
 * @param value - The raw `allowHosts` or `allowSchemes` from the patch row.
 * @returns The usable entries, or null when there was no list.
 */
function normalizeList(value) {
  if (!Array.isArray(value)) return null
  return value
    .filter((entry) => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
}

/**
 * Resolve the plugin's effective allowlists.
 *
 * Precedence is patch config, then environment, then default — the patch row is
 * the deployment's stated intent, so it wins over an ambient variable. The
 * default for `allowHosts` is the **empty list, which allows nothing**: a
 * profile that installs this plugin and configures no hosts denies every
 * outbound URL, and that is the fail-closed behaviour, not a misconfiguration.
 * @param config - The `config` block of the plugin's row in the composed patch.
 * @param env - Environment to read, injectable for tests.
 * @returns `{ allowHosts, allowSchemes }`, both plain string arrays.
 */
export function resolveConfig(config = {}, env = process.env) {
  return {
    allowHosts:
      normalizeList(config.allowHosts) ?? parseEnvList(env[ALLOW_HOSTS_ENV]) ?? [],
    allowSchemes:
      normalizeList(config.allowSchemes) ??
      parseEnvList(env[ALLOW_SCHEMES_ENV]) ?? [...DEFAULT_ALLOW_SCHEMES],
  }
}

/**
 * Build the `ssrf_check` tool definition.
 *
 * Kept as a factory rather than a module-scope constant so nothing is
 * constructed at import time and each `apply` owns its own definition bound to
 * its own resolved allowlists. Exported so a host can drive the tool without
 * booting a profile.
 * @param settings - Resolved settings from {@link resolveConfig}.
 * @returns A registry-ready tool definition.
 */
export function createSsrfCheckTool(settings = {}) {
  const allowlist = {
    allowHosts: settings.allowHosts ?? [],
    allowSchemes: settings.allowSchemes ?? [...DEFAULT_ALLOW_SCHEMES],
  }

  return defineTool({
    name: SSRF_CHECK_TOOL_NAME,
    description:
      'Decide whether a URL may be fetched, against this profile\'s host and scheme allowlist, ' +
      'without opening anything. Reach for it before fetching a URL a user, a document, or ' +
      'another tool handed you. An allowed URL comes back as a structured record; a denied one ' +
      'raises SSRF_DENIED naming the reason — the scheme, an unlisted host, a loopback address, ' +
      'or a link-local metadata address. The check is a parse: the hostname is read as written ' +
      'in the URL and never resolved, so it is an allowlist, not DNS-rebinding protection, and ' +
      'an allow verdict is permission to try rather than a promise the host is safe.',
    parameters: {
      url: {
        type: 'string',
        required: true,
        description:
          'The absolute URL to check, exactly as it would be fetched. A relative or ' +
          'unparseable string is denied as INVALID_URL rather than guessed at.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: {
            type: 'boolean',
            required: true,
            const: true,
            description: 'Always true: a denial throws SSRF_DENIED instead of returning.',
          },
          url: {
            type: 'string',
            required: true,
            description: 'The `url` argument, echoed back unchanged.',
          },
          host: {
            type: 'string',
            required: true,
            description:
              'The hostname that was matched, normalized — lowercased, IPv6 brackets and any ' +
              'trailing root dot removed. No port.',
          },
          scheme: {
            type: 'string',
            required: true,
            description: 'The matched scheme, lowercased and without its colon.',
          },
          plugin: {
            type: 'string',
            required: true,
            const: PLUGIN_NAME,
            description: 'The plugin that registered the tool that answered.',
          },
        },
      },
      render: (_args, value) => [
        { type: 'text', text: `ssrf: allow ${value.scheme}://${value.host}` },
      ],
    },
    execute(args) {
      // Throws SsrfDeniedError on a denial, deliberately: the caller must not
      // be able to proceed by forgetting to read a boolean.
      return Promise.resolve(assertUrlAllowed(args.url, allowlist))
    },
  })
}

/**
 * Register the plugin's single tool for the lifetime of this plugin's fiber.
 * @param ctx - The injected Cordis context, with `tools` resolved.
 * @param config - The `config` block of this plugin's row in the composed patch.
 */
export function apply(ctx, config = {}) {
  ctx.tools.register(createSsrfCheckTool(resolveConfig(config)))
}
