import { Buff, Bytes } from '@cmdcode/buff-utils'
import { modN }        from './math.js'
import { KeyContext }  from './context.js'
import { KeyOperationError }  from './error.js'
import { buffer, parse_keys } from './utils.js'

import {
  G,
  point_add,
  point_mul,
  point_eq,
  assert_point,
  point_x,
  parse_x,
  N
} from './point.js'

const _0n = BigInt(0)

export function assert_N (bytes : Bytes) : void {
  const big = Buff.bytes(bytes).big
  if (big <= _0n || N <= big) {
    throw new KeyOperationError({
      type   : 'assert_N',
      reason : 'Key out of range.',
      data   : [ Buff.big(big).hex ]
    })
  }
}

export function combine_s (
  signatures : Bytes[]
) : bigint {
  // Initialize s at zero.
  let s = _0n
  // Iterate through each sig:
  for (const psig of signatures) {
    // Convert key to bigint.
    const s_i = buffer(psig).big
    // Assert key is within range.
    assert_N(s_i)
    // Add signature value to s.
    s = modN(s + s_i)
  }
  return s
}

export function combine_sigs (
  context    : KeyContext,
  signatures : Bytes[]
) : Buff {
  const { challenge, group_pubkey, group_R, tweak } = context
  const is_odd = group_pubkey[0] === 3

  console.log('tweak:', tweak)

  const s = combine_s(signatures)
  const e = buffer(challenge).big
  console.log('e:', e)
  const t = buffer(tweak).big
  const g = (is_odd) ? N - 1n : 1n
  console.log('combine g:', g)
  const a = modN(e * g * t)
  console.log('pre s tweak:', Buff.big(a).hex)
  const sig = modN(s + a)

  // Return the combined signature.
  return Buff.join([
    parse_x(group_R),
    Buff.big(sig, 32)
  ])
}

export function verify_sig (
  context   : KeyContext,
  signature : Bytes
) : boolean {
  const { challenge, group_pubkey } = context
  const [ rx, s ] = parse_keys(signature, 64)
  const S  = point_mul(G, s.big)
  const R  = point_x(rx, true)
  const P  = point_x(group_pubkey, true)
  const c  = buffer(challenge).big
  const SP = point_add(R, point_mul(P, c))
  assert_point(S)
  return point_eq(S, SP)
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
