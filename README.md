# dsh-ssrf-guard

A **DeepSeek Harness function plugin** holding outbound URLs to a **fail-closed
host and scheme allowlist**, checked **before** a request is opened. Hosts that
are not on the list never leave the box, because nothing here opens anything:
the check is a URL parse and a string match.

The scope is one question: **may this URL be fetched?** The answer is either a
small structured record or a thrown error carrying `code: 'SSRF_DENIED'` and a
reason token. Default configuration allows **nothing** — you name the hosts you
actually need.

## What it is not

> **This is a URL-host allowlist. It is not DNS-rebinding protection, and it is
> not a WAF.**

- **Not DNS-rebinding protection.** The hostname is matched **as written in the
  URL**, never after resolution. An allowed name whose DNS answer points at
  `127.0.0.1` — or that answers differently on the second lookup than on the
  first — is allowed by this plugin, because this plugin never looks it up. If
  you need that, you need a resolver-level or connect-level control, which is a
  different thing living in a different layer.
- **Not a WAF.** Nothing inspects a request body, a response, a header, or a
  payload. There is no rule set, no signature list, and no traffic to filter.
- **Not a reverse proxy.** It sits in your process as a function you call, not
  in front of your service as a hop.
- **Not an interceptor.** The pinned release candidate `0.1.1-rc.2` exposes no
  HTTP or fetch seam, so the plugin does not invent one and does not silently
  wrap your client. It gives you an assertion to call at your own egress point,
  and a tool the model can call before it asks for a fetch.

An allow verdict is **permission to try**, not a promise that the host is safe.

## Install

```sh
dsh plugin --profile web add github:jwilson411/dsh-ssrf-guard
```

`dsh plugin` forwards to pnpm inside `$DSH_HOME/profiles/web`, then reconciles
the profile: because this package's manifest declares `dsh.bundle.patch`, it is
appended to the profile manifest's ordered `dsh.profile.bundles` list and its
`cordis.patch.yml` becomes a layer. Remove it the same way, with `remove` in
place of `add`.

## Pinned DSH release candidate

This package is written and tested against the pinned release candidate
**`0.1.1-rc.2`** — `@deepseek-ai/dsh-tools@0.1.1-rc.2` is pinned exactly in
`devDependencies` so tests run against one known API, and the peer range is
`^0.1.1-rc.2`, matching how the harness's own tool packages declare it.

Note that `@deepseek-ai/dsh-tools`'s npm `latest` tag still points at the older
`0.0.1-rc.1`; the `0.1.1-rc.2` line is published under `next`. Pin explicitly
rather than relying on the tag.

## What it registers

| | |
|---|---|
| Cordis plugin id | `ssrf-guard` (the row id in `cordis.patch.yml`) |
| Injects | `tools` — a hard dependency; the plugin waits rather than degrading |
| Tool | `ssrf_check` |
| Arguments | `url` (string, required) |

On an allow the tool returns `{ ok: true, url, host, scheme, plugin }`, shaped
by its declared output schema. On a denial it **throws** rather than returning
`ok: false` — a guard a caller can walk past by forgetting to read a boolean is
not a guard.

## The library API

The tool is a thin wrapper. The function is the product:

```js
import { assertUrlAllowed, SsrfDeniedError } from 'dsh-ssrf-guard'

const config = { allowHosts: ['.example.com'], allowSchemes: ['https'] }

try {
  const { host, scheme } = assertUrlAllowed(candidate, config)
  await fetch(candidate) // your call, at your own egress point
} catch (error) {
  if (error instanceof SsrfDeniedError) {
    log.warn({ code: error.code, reason: error.reason, host: error.host })
    return
  }
  throw error
}
```

Call it **before** you build the request. A non-throwing form, `checkUrl(url,
config)`, returns `{ ok: false, reason, url, host, scheme, message }` instead
for a caller that would rather branch on a value.

## Config

| key | type | default | |
|---|---|---|---|
| `allowHosts` | string[] | `[]` | exact hostnames and leading-dot suffix rules. Empty allows **nothing**. |
| `allowSchemes` | string[] | `["https"]` | allowed URL schemes, with or without the colon |

Set them from the profile's own `cordis.patch.yml` — note that an id-targeted
patch replaces the row's whole `config`, so restate every field you mean to
keep:

```yaml
- id: ssrf-guard
  config:
    allowHosts:
      - .example.com
      - api.vendor.test
    allowSchemes: [https]
```

Resolution order is **patch config, then environment, then default**: a patch
row is the deployment's stated intent, so it is not silently overridden by an
ambient variable. The environment fallbacks are `DSH_SSRF_ALLOW_HOSTS` and
`DSH_SSRF_ALLOW_SCHEMES`, each a comma-separated list, and each used only when
the patch row omits the key entirely. An **explicitly empty** list is a stated
intent and wins.

### How a host entry matches

| entry | matches | does not match |
|---|---|---|
| `example.com` (exact) | `example.com` | `evil.example.com`, `notexample.com` |
| `.example.com` (suffix) | `foo.example.com`, `a.b.example.com`, `example.com` | `notexample.com`, `example.com.evil.test` |

- Comparison is **case-insensitive**, since DNS is: `EXAMPLE.com` matches
  `example.com`.
- A trailing root dot is normalized away, so `https://example.com./` cannot
  slip past an `example.com` entry as a different string.
- IPv6 brackets are normalized away, so a config may write `::1` or `[::1]`.
- **Ports are not part of the match.** `https://example.com:8443/` is allowed
  by `example.com`. If you need port control, that is a different layer.
- A non-string or blank entry is dropped rather than coerced: a malformed
  allowlist shrinks towards denying, never grows towards allowing.

## What is denied by default

With no config at all, everything is. With hosts configured, the following are
still denied unless you name them:

| denied | `reason` |
|---|---|
| any host not matched by `allowHosts` | `HOST_DENIED` |
| any scheme outside `allowSchemes` — `http:` under the https-only default, and `file:`, `data:`, `gopher:`, `ftp:` always unless listed | `SCHEME_DENIED` |
| loopback and unspecified addresses: `127.0.0.0/8`, `localhost` and `*.localhost`, `::1`, `0.0.0.0`, `::` | `LOOPBACK_DENIED` |
| link-local, including the cloud metadata service at `169.254.169.254`: `169.254.0.0/16`, `fe80::/10` | `LINK_LOCAL_DENIED` |
| a URL carrying credentials, such as `https://example.com@evil.test/` | `CREDENTIALS_DENIED` |
| a relative or unparseable string | `INVALID_URL` |
| a URL that parses but carries no host, such as `mailto:` | `HOST_MISSING` |

Loopback and link-local addresses are reachable only through an **exact**
entry. A suffix rule never unlocks them: `.localhost` does not admit
`localhost`, and `.254` does not admit the metadata address. Naming
`127.0.0.1` in `allowHosts` does — that case is a local development server, and
it should have to be written down.

## The error

```js
error instanceof SsrfDeniedError
error.code    // 'SSRF_DENIED' — always, for every denial
error.reason  // 'HOST_DENIED' | 'SCHEME_DENIED' | 'LOOPBACK_DENIED' |
              // 'LINK_LOCAL_DENIED' | 'CREDENTIALS_DENIED' |
              // 'HOST_MISSING' | 'INVALID_URL'
error.url     // the input string, exactly as handed in
error.host    // the normalized host, or null if parsing never got that far
error.scheme  // the scheme without its colon, or null likewise
error.message // human-readable, naming what was allowed
```

Branch on `code` and `reason`; the message is for a human reading a log. The
full reason set is exported as `REASONS`.

## Layout

```
package.json          manifest + `dsh.bundle.patch` — what makes this a bundle
cordis.patch.yml      the bundle's patch layer: one insert, one plugin row
src/ssrf.js           the pure half: normalize, match, allow or throw
src/index.js          the plugin: `name`, `inject`, `apply(ctx, config)`, the tool
test/                 offline tests: URL parses, a stub context, a hygiene scan
package-lock.json     the pinned dependency tree `npm ci` installs in CI
```

## Tests

```sh
npm install
npm test
```

Offline by construction, and not merely by intention: every case is a URL
**parse**, `apply` is handed a stub context that records registrations, and the
tool is driven through the same `execute` the registry calls, with results
validated against the real `@deepseek-ai/dsh-tools` pinned to `0.1.1-rc.2`. No
profile boots, no name is resolved, no socket opens, and no key is read.

`test/hygiene.test.js` asserts the claim rather than restating it: it scans
`src/` for any resolver, socket, HTTP, or dynamic-import construct and fails if
one appears, checks that the only non-relative import is the pinned tools
package, and scans the whole tree for machine names, mount paths, and
credential shapes.

CI (`.github/workflows/ci.yml`) runs `npm ci` and `npm test` on Node 22 and 24
from the committed lockfile, against the public registry only. It needs no
credentials and the suite reaches no network.

## Out of scope

- **DNS-rebinding defence.** Covered above: the name is checked as written, not
  as resolved.
- **A reverse proxy or a cloud WAF.** Neither is here, and this is not a
  smaller version of one.
- **Opening sockets.** The package makes no connection of any kind, including
  to validate that an allowed host exists.
- **Scanning networks.** There is no probing, no sweeping, and no discovery.
- **IP-range policy beyond loopback and link-local.** Private ranges such as
  `10.0.0.0/8` are denied by the allowlist being an allowlist, not by a
  special case. If you want them reachable, name them.
- **Deciding for you.** The tool answers about one URL. What your code does
  with an allow is your code's business.

## License

MIT — see [LICENSE](LICENSE).
