import { Buff, Bytes } from '@cmdcode/buff-utils'
import { PointState }  from './types.js'

import * as ecc from '@cmdcode/crypto-utils'

type PointData = ecc.PointData

const { _N, _G } = ecc.CONST

export function get_challenge (
  group_rx  : Bytes,
  group_pub : Bytes,
  message   : Bytes
) : Buff {
  const grx = ecc.keys.convert_32(group_rx)
  const gpx = ecc.keys.convert_32(group_pub)
  // Create the challenge pre image.
  const preimg = Buff.join([ grx, gpx, message ])
  // Return the challenge hash.
  return ecc.hash.digest('BIP0340/challenge', preimg)
}

export function get_pt_state (
  int_pt : PointData,
  tweaks : Bytes[] = []
) : PointState {
  // Convert our tweaks to integers.
  const ints = tweaks.map(e => ecc.math.mod_bytes(e).big)
  const pos  = BigInt(1)
  const neg  = _N - pos

  let point : PointData | null = int_pt,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!ecc.pt.is_even(point)) ? neg : pos
    // Invert point based on g, then add tweak.
    point = ecc.pt.add(ecc.pt.mul(point, parity), ecc.pt.mul(_G, t))
    // Assert that point is not null.
    ecc.pt.assert_valid(point)
    // Store our progress for the next round.
    state = ecc.math.modN(parity * state)
    tweak = ecc.math.modN(t + parity * tweak)
  }

  parity = (!ecc.pt.is_even(point)) ? neg : pos

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
    const c  = ecc.math.modN(ncoeff.big ** BigInt(j))
    // Convert current nonce into point.
    const NC = ecc.pt.lift_x(nonces[j])
    // Assert n is not null.
    ecc.pt.assert_valid(NC)
    // Apply coefficient to n.
    const Rj = ecc.pt.mul(NC, c)
    // Add tweaked nonce to R.
    R = ecc.pt.add(R, Rj)
  }
  // Asset R is not null.
  ecc.pt.assert_valid(R)
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
  let s = ecc.math.modN(challenge * key_coeff * secret_key)

  for (let j = 0; j < sec_nonces.length; j++) {
    // Set our nonce value for the round.
    const r = sec_nonces[j]
    // Compute our nonce coeff.
    const c = ecc.math.powN(nonce_coeff, BigInt(j))
    // Apply the nonce and coeff tweak.
    s += (r * c)
    // Squash our signature back into the field.
    s = ecc.math.modN(s)
  }

  return Buff.big(s, 32)
}
