import { Buff, Bytes } from '@cmdcode/buff'
import { convert_32b } from '@cmdcode/crypto-tools/keys'
import { PointState }  from './types.js'
import { hash340 }     from '@cmdcode/crypto-tools/hash'

import {
  CONST,
  PointData
} from '@cmdcode/crypto-tools'

import {
  mod_bytes,
  mod_n,
  pow_n,
  pt
} from '@cmdcode/crypto-tools/math'

const { _N, _G } = CONST

export function get_challenge (
  group_rx  : Bytes,
  group_pub : Bytes,
  message   : Bytes
) : Buff {
  const grx = convert_32b(group_rx)
  const gpx = convert_32b(group_pub)
  // Create the challenge pre image.
  const preimg = Buff.join([ grx, gpx, message ])
  // Return the challenge hash.
  return hash340('BIP0340/challenge', preimg)
}

export function get_pt_state (
  int_pt : PointData,
  tweaks : Bytes[] = []
) : PointState {
  // Convert our tweaks to integers.
  const ints = tweaks.map(e => mod_bytes(e).big)
  const pos  = BigInt(1)
  const neg  = _N - pos

  let point : PointData | null = int_pt,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!pt.is_even(point)) ? neg : pos
    // Invert point based on g, then add tweak.
    point = pt.add(pt.mul(point, parity), pt.mul(_G, t))
    // Assert that point is not null.
    pt.assert_valid(point)
    // Store our progress for the next round.
    state = mod_n(parity * state)
    tweak = mod_n(t + parity * tweak)
  }

  parity = (!pt.is_even(point)) ? neg : pos

  return {
    point,
    parity,
    state,
    tweak
  }
}

export function compute_R (
  group_nonce : Bytes,
  nonce_coeff : Bytes
) : PointData {
  // Read our data into buffer.
  const nonces = Buff.parse(group_nonce, 33, 66)
  const ncoeff = Buff.bytes(nonce_coeff)
  // Init our R value as null point.
  let R : PointData | null = null
  // For each round of nonces:
  for (let j = 0; j < nonces.length; j++) {
    // Calculate coefficient for round.
    const c  = mod_n(ncoeff.big ** BigInt(j))
    // Convert current nonce into point.
    const NC = pt.lift_x(nonces[j])
    // Assert n is not null.
    pt.assert_valid(NC)
    // Apply coefficient to n.
    const Rj = pt.mul(NC, c)
    // Add tweaked nonce to R.
    R = pt.add(R, Rj)
  }
  // Asset R is not null.
  pt.assert_valid(R)
  // Return x value of R.
  return R
}

export function compute_s (
  secret_key  : bigint,
  key_coeff   : bigint,
  challenge   : bigint,
  sec_nonces  : bigint[],
  nonce_coeff : bigint
) : Buff {
  // Similar to typical schnorr signing,
  // with an added group coefficient tweak.
  let s = mod_n(challenge * key_coeff * secret_key)

  for (let j = 0; j < sec_nonces.length; j++) {
    // Set our nonce value for the round.
    const r = sec_nonces[j]
    // Compute our nonce coeff.
    const c = pow_n(nonce_coeff, BigInt(j))
    // Apply the nonce and coeff tweak.
    s += (r * c)
    // Squash our signature back into the field.
    s = mod_n(s)
  }

  return Buff.big(s, 32)
}

export function compute_ps (
  secret_key  : bigint,
  key_coeff   : bigint,
  challenge   : bigint
) : Buff {
  // Similar to typical schnorr signing,
  // with an added group coefficient tweak.
  const ps = mod_n(challenge * key_coeff * secret_key)
  return Buff.big(ps, 32)
}

export function apply_sn (
  ps  : bigint,
  sns : bigint[],
  ncf : bigint
) : Buff {
  for (let j = 0; j < sns.length; j++) {
    // Set our nonce value for the round.
    const r = sns[j]
    // Compute our nonce coeff.
    const c = pow_n(ncf, BigInt(j))
    // Apply the nonce and coeff tweak.
    ps += (r * c)
    // Squash our signature back into the field.
    ps = mod_n(ps)
  }
  return Buff.big(ps, 32)
}
