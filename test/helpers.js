/** Shared stubs. Everything here is offline and synchronous. */
import assert from 'node:assert/strict'

import { SSRF_DENIED, SsrfDeniedError } from '../src/ssrf.js'

/**
 * A context stub exposing only what `apply` is allowed to touch.
 * @returns The stub context and the definitions it recorded.
 */
export function stubContext() {
  const registered = []
  const ctx = {
    tools: {
      register(definition) {
        registered.push(definition)
        return () => {}
      },
    },
  }
  return { ctx, registered }
}

/** The execution context the registry passes to `execute`; unused by this tool. */
export const exec = { signal: new AbortController().signal }

/**
 * Assert that a call denies with the structured error, and that the error
 * carries the fields a caller is meant to branch on.
 * @param call - A thunk performing the check.
 * @param reason - The expected `reason` token.
 * @param url - The URL that should be echoed back on the error.
 * @returns The error, for any further assertions.
 */
export function assertDenied(call, reason, url) {
  let thrown
  try {
    call()
  } catch (error) {
    thrown = error
  }
  assert.ok(thrown !== undefined, `expected a denial for ${url}`)
  assert.ok(thrown instanceof SsrfDeniedError, `expected SsrfDeniedError for ${url}`)
  assert.equal(thrown.code, SSRF_DENIED)
  assert.equal(thrown.reason, reason, `wrong reason for ${url}`)
  assert.equal(thrown.url, url)
  assert.ok(thrown.message.length > 0)
  return thrown
}
