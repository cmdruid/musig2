import { Buff, Bytes }   from '@cmdcode/buff-utils'
import { modN, pow }     from './math.js'
import { get_vector }    from './pubkey.js'
import { generate_keys } from './generate.js'
import { KeyContext }    from './context.js'
import { buffer, hashTag, parse_keys } from './utils.js'

import {
  N,
  Point,
  point_x,
  point_add,
  point_mul,
  assert_point,
  parse_x
} from './point.js'

export function get_challenge (
  group_R   : Bytes,
  group_pub : Bytes,
  message   : Bytes
) : Buff {
  const grx = parse_x(group_R)
  const gpx = parse_x(group_pub)
  // Create the challenge pre image.
  const preimg = Buff.join([ grx, gpx, message ])
  // Return the challenge hash.
  return hashTag('BIP0340/challenge', preimg)
}

export function compute_R (
  group_nonce : Bytes,
  nonce_coeff : Bytes
) : Point {
  // Read our data into buffer.
  const nonces = parse_keys(group_nonce)
  const ncoeff = Buff.bytes(nonce_coeff)
  // Init our R value as null point.
  let R : Point | null = null
  // For each round of nonces:
  for (let j = 0; j < nonces.length; j++) {
    // Calculate coefficient for round.
    const c  = modN(ncoeff.big ** BigInt(j))
    // Convert current nonce into point.
    const NC = point_x(nonces[j])
    // Assert n is not null.
    assert_point(NC)
    // Apply coefficient to n.
    const Rj = point_mul(NC, c)
    // Add tweaked nonce to R.
    R = point_add(R, Rj)
  }
  // Asset R is not null.
  assert_point(R)
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
  let s = modN(challenge * key_vector * secret_key)

  for (let j = 0; j < sec_nonces.length; j++) {
    // Set our nonce value for the round.
    const r = sec_nonces[j]
    // Compute our nonce vector.
    const c = pow(nonce_vect, BigInt(j), N)
    // Apply the nonce and vector tweak.
    s += (r * c)
    // Squash our signature back into the field.
    s = modN(s)
  }

  return Buff.big(s, 32)
}

export function sign (
  context   : KeyContext,
  secret    : Bytes,
  sec_nonce : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, nonce_vector, R_state, key_state, key_parity, vectors } = context
  // Load secret key into buffer.
  const [ sec, pub ] = generate_keys(secret)
  // Get the vector for our pubkey.
  const p_v = get_vector(vectors, pub).big
  const sk  = modN(key_parity * key_state * sec.big)
  const cha = buffer(challenge).big
  const n_v = buffer(nonce_vector).big
  // Parse nonce values into an array.
  const sn  = parse_keys(sec_nonce).map(e => {
    // Negate our nonce values if needed.
    return  R_state * e.big
  })
  // Return partial signature.
  return compute_s(sk, p_v, cha, sn, n_v)
  // NOTE: Add a partial sig verfiy check here.
}
