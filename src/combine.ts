import { Buff, Bytes }       from '@cmdcode/buff'
import { CONST, keys, math } from '@cmdcode/crypto-tools'
import { parse_psig }        from './utils.js'
import { MusigContext }      from './types.js'

import * as assert from './assert.js'

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
    s = math.mod_n(s + s_i)
  }
  return s
}

export function combine_sigs (
  context    : MusigContext,
  signatures : Bytes[]
) : Buff {
  const { challenge, Q, group_rx } = context
  const { parity, tweak } = Q
  const sigs = signatures
    .map(e => parse_psig(e))
    .map(e => e.sig)
  const s   = combine_s(sigs)
  const e   = challenge.big
  const a   = e * parity * tweak
  const sig = math.mod_n(s + a)
  // Return the combined signature.
  return Buff.join([
    keys.convert_32b(group_rx),
    Buff.big(sig, 32)
  ])
}
