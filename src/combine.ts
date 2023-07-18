import { Buff, Bytes } from '@cmdcode/buff-utils'
import { ecc, math }   from '@cmdcode/crypto-utils'
import { get_context } from './context.js'

import * as assert from './assert.js'

import {
  MusigContext,
  MusigOptions
} from './schema/index.js'

const { CONST } = math

export function combine_s (
  signatures : Bytes[]
) : bigint {
  // Initialize s at zero.
  let s = CONST._0n
  // Iterate through each sig:
  for (const psig of signatures) {
    // Convert key to bigint.
    const s_i = Buff.bytes(psig).big
    // Assert key is within range.
    assert.in_field(s_i)
    // Add signature value to s.
    s = math.modN(s + s_i)
  }
  return s
}

export function combine_sigs (
  context    : MusigContext,
  signatures : Bytes[]
) : Buff {
  const { challenge, key_parity, group_rx, key_tweak } = context

  const s   = combine_s(signatures)
  const e   = challenge.big
  const a   = e * key_parity * key_tweak
  const sig = math.modN(s + a)

  // Return the combined signature.
  return Buff.join([
    ecc.parse_x(group_rx),
    Buff.big(sig, 32)
  ])
}

export function get_signature (
  message    : Bytes,
  pub_keys   : Bytes[],
  pub_nonces : Bytes[],
  signatures : Bytes[],
  options   ?: MusigOptions
) : Bytes {
  const ctx = get_context(pub_keys, pub_nonces, message, options)
  return combine_sigs(ctx, signatures)
}
