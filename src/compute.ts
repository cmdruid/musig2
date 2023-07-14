import { Buff, Bytes } from '@cmdcode/buff-utils'
import { parse_keys }  from './utils.js'

import {
  assert,
  digest,
  math,
  point,
  PointData,
  util
} from '@cmdcode/crypto-utils'

export function get_challenge (
  group_rx  : Bytes,
  group_pub : Bytes,
  message   : Bytes
) : Buff {
  const grx = util.parse_x(group_rx)
  const gpx = util.parse_x(group_pub)
  // Create the challenge pre image.
  const preimg = Buff.join([ grx, gpx, message ])
  // Return the challenge hash.
  return digest('BIP0340/challenge', preimg)
}

export function compute_R (
  group_nonce : Bytes,
  nonce_coeff : Bytes
) : PointData {
  // Read our data into buffer.
  const nonces = parse_keys(group_nonce)
  const ncoeff = Buff.bytes(nonce_coeff)
  // Init our R value as null point.
  let R : PointData | null = null
  // For each round of nonces:
  for (let j = 0; j < nonces.length; j++) {
    // Calculate coefficient for round.
    const c  = math.modN(ncoeff.big ** BigInt(j))
    // Convert current nonce into point.
    const NC = point.lift_x(nonces[j])
    // Assert n is not null.
    assert.valid_point(NC)
    // Apply coefficient to n.
    const Rj = point.mul(NC, c)
    // Add tweaked nonce to R.
    R = point.add(R, Rj)
  }
  // Asset R is not null.
  assert.valid_point(R)
  // Return x value of R.
  return R
}

export function compute_s (
  secret_key : bigint,
  key_vector : bigint,
  challenge  : bigint,
  sec_nonces : bigint[],
  nonce_vect : bigint
) : Buff {
  // Similar to typical schnorr signing,
  // with an added group coefficient tweak.
  let s = math.modN(challenge * key_vector * secret_key)

  for (let j = 0; j < sec_nonces.length; j++) {
    // Set our nonce value for the round.
    const r = sec_nonces[j]
    // Compute our nonce vector.
    const c = math.powN(nonce_vect, BigInt(j))
    // Apply the nonce and vector tweak.
    s += (r * c)
    // Squash our signature back into the field.
    s = math.modN(s)
  }

  return Buff.big(s, 32)
}
