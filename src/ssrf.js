/**
 * The pure half of dsh-ssrf-guard: parse a URL string and decide, against an
 * allowlist, whether a caller may open it.
 *
 * Nothing here touches Cordis, a socket, or a resolver. The only input is the
 * URL **as written**; the only outputs are a small allow record or a thrown
 * {@link SsrfDeniedError}. This module performs no name resolution and builds
 * no request — the check runs *before* a request is opened, so a denied host
 * never leaves the box. `test/hygiene.test.js` asserts that.
 *
 * **The hostname is checked as written, not as resolved.** That is the whole
 * design: it makes the check a pure function of the URL, and it means this is
 * an allowlist rather than DNS-rebinding protection. See the README.
 *
 * @module dsh-ssrf-guard/ssrf
 */

/** The plugin's own identity, echoed on every allow so a caller can confirm the source. */
export const PLUGIN_NAME = 'dsh-ssrf-guard'

/** The single `code` every denial carries, so a caller can branch without parsing prose. */
export const SSRF_DENIED = 'SSRF_DENIED'

/** The schemes allowed when neither the patch row nor the environment names any. */
export const DEFAULT_ALLOW_SCHEMES = Object.freeze(['https'])

/** Every `reason` a denial can carry. Each is a stable token, not a message. */
export const REASONS = Object.freeze([
  'INVALID_URL',
  'SCHEME_DENIED',
  'HOST_MISSING',
  'CREDENTIALS_DENIED',
  'LOOPBACK_DENIED',
  'LINK_LOCAL_DENIED',
  'HOST_DENIED',
])

/**
 * A denial, raised rather than returned so a caller cannot proceed to open the
 * URL by forgetting to read a boolean. Fail-closed means the failure path is
 * the throwing one.
 */
export class SsrfDeniedError extends Error {
  /**
   * @param reason - A stable token from {@link REASONS}.
   * @param message - Human-readable detail.
   * @param details - `{ url, host, scheme }` as far as they were parsed.
   */
  constructor(reason, message, { url = null, host = null, scheme = null } = {}) {
    super(message)
    this.name = 'SsrfDeniedError'
    /** Always `SSRF_DENIED`; the specific cause is {@link SsrfDeniedError#reason}. */
    this.code = SSRF_DENIED
    this.reason = reason
    /** The input string exactly as it was handed in, for the log line. */
    this.url = url
    /** The normalized hostname, or null when parsing never got that far. */
    this.host = host
    /** The scheme without its colon, or null when parsing never got that far. */
    this.scheme = scheme
  }
}

/**
 * Normalize a hostname for comparison.
 *
 * Lowercased because DNS is case-insensitive; the IPv6 brackets the URL parser
 * keeps on `hostname` are stripped so a config may write either `::1` or
 * `[::1]`; and one trailing root dot is dropped so `example.com.` cannot slip
 * past an `example.com` entry as a different string.
 * @param host - A hostname from a URL or from an allowlist entry.
 * @returns The normalized form, or `''` for anything that is not a string.
 */
export function normalizeHost(host) {
  if (typeof host !== 'string') return ''
  let value = host.trim().toLowerCase()
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1)
  if (value.length > 1 && value.endsWith('.')) value = value.slice(0, -1)
  return value
}

/**
 * Normalize a scheme for comparison: lowercased, with the colon the URL
 * parser's `protocol` carries trimmed off either spelling.
 * @param scheme - `https`, `https:`, or the same with any casing.
 * @returns The bare scheme, or `''` for anything that is not a string.
 */
export function normalizeScheme(scheme) {
  if (typeof scheme !== 'string') return ''
  const value = scheme.trim().toLowerCase()
  return value.endsWith(':') ? value.slice(0, -1) : value
}

/** Hosts that name the local machine, in the spellings a URL can carry. */
const LOOPBACK_PATTERNS = Object.freeze([
  /^localhost$/,
  /^.+\.localhost$/,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^0:0:0:0:0:0:0:1$/,
  /^::$/,
  /^::ffff:127\./,
])

/** Hosts on the link-local ranges, where the cloud metadata services live. */
const LINK_LOCAL_PATTERNS = Object.freeze([
  /^169\.254\.\d{1,3}\.\d{1,3}$/,
  /^fe80:/,
  /^::ffff:169\.254\./,
])

/**
 * Classify a host that is dangerous enough to require an *exact* allowlist
 * entry rather than merely matching some suffix rule.
 *
 * A suffix like `.internal` should never be what unlocks `127.0.0.1` or the
 * metadata address; naming them is the only way to reach them.
 * @param host - An already-normalized hostname.
 * @returns `'LOOPBACK'`, `'LINK_LOCAL'`, or null for an ordinary host.
 */
export function classifyHost(host) {
  if (LOOPBACK_PATTERNS.some((pattern) => pattern.test(host))) return 'LOOPBACK'
  if (LINK_LOCAL_PATTERNS.some((pattern) => pattern.test(host))) return 'LINK_LOCAL'
  return null
}

/**
 * Whether a normalized host is matched by one allowlist entry.
 *
 * An entry with a leading dot is a **suffix** rule that also covers the bare
 * domain — `.example.com` matches `foo.example.com` and `example.com`, and
 * deliberately does not match `notexample.com`, because the dot is part of what
 * has to match. Any other entry is **exact**: `example.com` matches only
 * itself, never `evil.example.com`.
 * @param host - An already-normalized hostname.
 * @param entry - One raw `allowHosts` entry.
 * @returns True when the entry admits the host.
 */
export function hostMatchesEntry(host, entry) {
  const rule = normalizeHost(entry)
  if (rule === '' || host === '') return false
  if (rule.startsWith('.')) {
    const bare = rule.slice(1)
    return bare !== '' && (host === bare || host.endsWith(rule))
  }
  return host === rule
}

/**
 * Whether any entry in the list admits the host. An empty or absent list
 * admits nothing: that is the fail-closed default, not an oversight.
 * @param host - An already-normalized hostname.
 * @param allowHosts - The configured entries.
 * @returns True when at least one entry matches.
 */
export function hostIsAllowed(host, allowHosts = []) {
  return allowHosts.some((entry) => hostMatchesEntry(host, entry))
}

/**
 * Whether the host is named exactly — no suffix rule counts. Used for the
 * loopback and link-local classes, which a wildcard must not unlock.
 * @param host - An already-normalized hostname.
 * @param allowHosts - The configured entries.
 * @returns True when an entry names this host and is not a suffix rule.
 */
function hostIsNamedExactly(host, allowHosts = []) {
  return allowHosts.some((entry) => {
    const rule = normalizeHost(entry)
    return rule !== '' && !rule.startsWith('.') && rule === host
  })
}

/** The denial message for a host held to exact-naming, by class. */
const CLASS_DETAIL = Object.freeze({
  LOOPBACK: 'loopback and unspecified addresses are denied unless named exactly in allowHosts',
  LINK_LOCAL:
    'link-local addresses — including the cloud metadata service at 169.254.169.254 — are ' +
    'denied unless named exactly in allowHosts',
})

/** The `reason` reported for each held-to-exact-naming class. */
const CLASS_REASON = Object.freeze({
  LOOPBACK: 'LOOPBACK_DENIED',
  LINK_LOCAL: 'LINK_LOCAL_DENIED',
})

/**
 * Assert that a URL may be opened, or throw.
 *
 * The checks run in the order a denial is most usefully explained: the URL has
 * to parse, then the scheme has to be allowed, then there has to be a host,
 * then the host has to be admitted. Every failure throws
 * {@link SsrfDeniedError} with `code: 'SSRF_DENIED'` and a `reason` token.
 *
 * **This function opens nothing and resolves nothing.** It is a decision about
 * the string it was given, and it is meant to be called *before* a request is
 * built.
 * @param url - The URL to check, as a string (or anything with a `toString`
 *   the `URL` parser accepts, such as a `URL`).
 * @param config - `{ allowHosts, allowSchemes }`; both default to the
 *   fail-closed empty list and to `['https']` respectively.
 * @returns `{ ok: true, url, host, scheme, plugin }` when the URL is allowed.
 * @throws {SsrfDeniedError} When it is not.
 */
export function assertUrlAllowed(url, config = {}) {
  const allowHosts = Array.isArray(config.allowHosts) ? config.allowHosts : []
  const allowSchemes = Array.isArray(config.allowSchemes)
    ? config.allowSchemes
    : DEFAULT_ALLOW_SCHEMES
  const input = typeof url === 'string' ? url : String(url ?? '')

  let parsed
  try {
    parsed = new URL(input)
  } catch {
    throw new SsrfDeniedError('INVALID_URL', `not a parseable absolute URL: ${input}`, {
      url: input,
    })
  }

  const scheme = normalizeScheme(parsed.protocol)
  if (!allowSchemes.some((allowed) => normalizeScheme(allowed) === scheme)) {
    throw new SsrfDeniedError(
      'SCHEME_DENIED',
      `scheme "${scheme}" is not allowed (allowed: ${describeList(allowSchemes)})`,
      { url: input, scheme, host: normalizeHost(parsed.hostname) || null },
    )
  }

  const host = normalizeHost(parsed.hostname)
  if (host === '') {
    throw new SsrfDeniedError('HOST_MISSING', `URL carries no host: ${input}`, {
      url: input,
      scheme,
    })
  }

  // Credentials in a URL are how a check that matched on the host alone gets
  // talked past by a parser that reads `https://allowed.example.com@evil/`
  // differently. This parser does not, but nothing needs them, so they go.
  if (parsed.username !== '' || parsed.password !== '') {
    throw new SsrfDeniedError('CREDENTIALS_DENIED', 'URLs carrying credentials are denied', {
      url: input,
      scheme,
      host,
    })
  }

  const held = classifyHost(host)
  if (held !== null && !hostIsNamedExactly(host, allowHosts)) {
    throw new SsrfDeniedError(
      CLASS_REASON[held],
      `host "${host}" is denied: ${CLASS_DETAIL[held]}`,
      { url: input, scheme, host },
    )
  }

  if (held === null && !hostIsAllowed(host, allowHosts)) {
    throw new SsrfDeniedError(
      'HOST_DENIED',
      `host "${host}" is not in allowHosts (allowed: ${describeList(allowHosts)})`,
      { url: input, scheme, host },
    )
  }

  return { ok: true, url: input, host, scheme, plugin: PLUGIN_NAME }
}

/**
 * Render a config list for a denial message, naming the empty list rather than
 * printing nothing — an empty allowlist denying everything is the intended
 * behaviour, and the message should say so.
 * @param list - The configured entries.
 * @returns A short human-readable rendering.
 */
function describeList(list) {
  const entries = list.filter((entry) => typeof entry === 'string' && entry.trim() !== '')
  return entries.length === 0 ? 'none — the allowlist is empty' : entries.join(', ')
}

/**
 * The non-throwing form, for a caller that wants to branch on a value.
 * @param url - The URL to check.
 * @param config - The same config {@link assertUrlAllowed} takes.
 * @returns The allow record, or `{ ok: false, reason, url, host, scheme, message }`.
 */
export function checkUrl(url, config = {}) {
  try {
    return assertUrlAllowed(url, config)
  } catch (error) {
    if (!(error instanceof SsrfDeniedError)) throw error
    return {
      ok: false,
      reason: error.reason,
      url: error.url,
      host: error.host,
      scheme: error.scheme,
      message: error.message,
    }
  }
}
