import { buffer, Bytes }     from '@cmdcode/buff-utils'
import { KeyOperationError } from './error.js'

import { assert, math, PointData } from '@cmdcode/crypto-utils'

export function size (
  input  : Bytes,
  size  ?: number
) : boolean {
  if (typeof size === 'number') {
    const bytes = buffer(input)
    if (bytes.length !== size) {
      throw new TypeError(`Invalid byte size: ${bytes.hex} !== ${size}`)
    }
  }
  return true
}

export function nonce_total_size (
  nonce : Bytes,
  size  : number
) : void {
  const bytes = buffer(nonce)
  if (bytes.length !== size) {
    throw new KeyOperationError({
      data   : [ bytes.hex ],
      type   : 'nonce_total_size',
      reason : `Nonce size mismatch: ${bytes.length} !== ${size}`
    })
  }
}

export function nonce_key_size (
  nonce : Bytes
) : void {
  const bytes = buffer(nonce)
  if (bytes.length % 32 !== 0 && bytes.length % 33 !== 0) {
    throw new KeyOperationError({
      data   : [ bytes.hex ],
      type   : 'nonce_key_size',
      reason : `Invalid key size: ${bytes.length}`
    })
  }
}

export function valid_nonce_group (
  pub_nonces : Bytes[]
) : void {
  // Load each nonce into a buffer.
  const nonces = pub_nonces.map(e => buffer(e))
  // Check each nonce for validity.
  nonces.forEach((nonce, idx) => {
    nonce_key_size(nonce)
    if (idx > 0) {
      const prev = nonces[idx - 1]
      nonce_total_size(nonce, prev.length)
    }
  })
}

export function in_field (bytes : Bytes) : void {
  const big = buffer(bytes).big
  if (!math.in_field(big)) {
    throw new KeyOperationError({
      type   : 'assert_N',
      reason : 'Key out of range of N.',
      data   : [ buffer(big, 32).hex ]
    })
  }
}

export function valid_point (
  point : PointData | null
) : asserts point is PointData {
  assert.valid_point(point)
}
