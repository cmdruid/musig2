import { Buff, Bytes }      from '@cmdcode/buff-utils'
import { ecc, math, point } from '@cmdcode/crypto-utils'
import { parse_keys }       from './utils.js'

import * as assert from './assert.js'

import { MusigSession } from './schema/index.js'

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
  context    : MusigSession,
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

export function verify_psig (
 psigs : Bytes[]
) : void {
  void psigs
  throw new Error('Not implemented')
}

export function verify_sig (
  context   : MusigSession,
  signature : Bytes
) : boolean {
  const { challenge, group_pubkey } = context
  const [ rx, s ] = parse_keys(signature, 64)
  const S  = point.mul(CONST.G, s.big)
  const R  = point.lift_x(rx, true)
  const P  = point.lift_x(group_pubkey, true)
  const c  = Buff.bytes(challenge).big
  const SP = point.add(R, point.mul(P, c))
  assert.valid_point(S)
  return point.eq(S, SP)
}

// export function verify_all (
//   group_keys   : Bytes[],
//   group_nonces : Bytes[],
//   group_sigs   : Bytes[],
//   message   : Bytes,
//   options   : Partial<MusigOptions> = {}
// ) : boolean {
//   const opt = { ...DEFAULT_OPT, ...options }
//   const [ gpk ] = combine_pubkeys(group_keys, opt)
//   const gnk     = combine_nonces(group_nonces, opt)
//   const n_c     = get_nonce_coeff(gnk, gpk, message)
//   const grk     = compute_R(gnk, n_c)
//   const sig     = combine_sigs(group_sigs, grk)
//   return verify_sig(sig, gpk, message)
// }
