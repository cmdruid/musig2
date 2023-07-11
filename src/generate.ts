import { Buff, Bytes } from '@cmdcode/buff-utils'
import { modN }        from './math.js'
import { assert_size, parse_keys } from './utils.js'

import {
  G,
  N,
  Point,
  assert_point,
  point_mul,
  to_bytes,
  is_even,
  mod_key
} from './point.js'

export function generate_random (size = 64) : Buff {
  // Generate a random secret, mod N.
  return new Buff(Buff.random(size), size)
}

export function generate_field (
  secret : Bytes,
  even_y : boolean = false
) : bigint {
  // Load secret into buffer.
  const sec = Buff.bytes(secret)
  // Squash secret into field N.
  const sk  = modN(sec.big)
  // Check if secret is within the field N.
  if (sk <= 0n || sk >= N) {
    throw new TypeError('Secret key must be within the field N!')
  }
  if (even_y) {
    const P = point_mul(G, sk)
    assert_point(P)
    if (!is_even(P)) {
      return N - sk
    }
  }
  return sk
}

export function generate_point (
  secret : Bytes
) : Point {
  const sk = generate_field(secret)
  const P  = point_mul(G, sk)
  assert_point(P)
  return P
}

export function generate_seckey (
  secret : Bytes,
  xonly ?: boolean
) : Buff {
  return Buff.big(generate_field(secret, xonly), 32)
}

export function generate_pubkey (
  secret : Bytes,
  xonly  : boolean = true
) : Buff {
  const P = generate_point(secret)
  return to_bytes(P, xonly)
}

export function generate_keys (
  secret : Bytes,
  xonly  : boolean = true
) : [ seckey: Buff, pubkey : Buff ] {
  const P = generate_point(secret)
  let sec = generate_field(secret)
  if (xonly && !is_even(P)) {
    sec = N - sec
  }
  return [
    Buff.big(sec, 32),
    to_bytes(P, xonly)
  ]
}

export function generate_sec_nonce (
  secret ?: Bytes
) : Buff {
  const seed = (secret !== undefined)
    ? Buff.bytes(secret)
    : Buff.random(64)
  assert_size(seed, 64)
  const nonces = parse_keys(seed).map(e => mod_key(e))
  return Buff.join(nonces)
}

export function generate_pub_nonce (
  sec_nonce : Bytes
) : Buff {
  const nonces = parse_keys(sec_nonce)
  return Buff.join(nonces.map(e => generate_pubkey(e, false)))
}

export function generate_nonces (
  secret : Bytes
) : [ sec_nonce: Buff, pub_nonce : Buff ]  {
  const sec_nonce = generate_sec_nonce(secret)
  const pub_nonce = generate_pub_nonce(sec_nonce)
  return [ sec_nonce, pub_nonce ]
}
