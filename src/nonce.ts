import { Buff, Bytes }  from '@cmdcode/buff-utils'
import { get_key_data, parse_keys } from './utils.js'
import { get_keys }     from './ecc/point.js'

import * as keys   from './keys.js'
import * as assert from './assert.js'

import {
  Point,
  PointData,
  digest,
  ecc,
  ecdh,
  math,
  point
} from '@cmdcode/crypto-utils'

const buffer = Buff.bytes

export function get_nonce_coeff (
  group_nonce : Bytes,
  group_key   : Bytes,
  message     : Bytes
) : Buff {
  const gpx = keys.parse_x(group_key)
  // Combine all bytes into a message challenge.
  const preimg = buffer([ group_nonce, gpx, message ])
  // Hash the challenge.
  const bytes  = digest('MuSig/noncecoef', preimg)
  // Return bytes as a bigint mod N.
  const coeff  = math.modN(bytes.big)
  return buffer(coeff, 32)
}

export function combine_nonces (
  pub_nonces : Bytes[]
) : Buff {
  // Check that all nonces are valid.
  assert.valid_nonce_group(pub_nonces)
  // Get key data from first nonce.
  const [ size, rounds ] = get_key_data(pub_nonces[0])
  // Store our group nonces in an array.
  const nonces = []
  // Iterate through each round.
  for (let j = 0; j < rounds; j++) {
    // Start with a null point.
    let group_R : PointData | null = null
    // Iterate through each nonce_data.
    for (const data of pub_nonces) {
      // Read data into buffer.
      const bytes = buffer(data)
      // Configure our index points.
      const start = size * j,
            end   = size * (j + 1)
      // Slice the nonce value from the buffer.
      const nonce = bytes.slice(start, end)
      // Convert nonce value into a point.
      const n_pt  = point.lift_x(nonce)
      // Add point to current group R point.
      group_R = point.add(group_R, n_pt)
    }
    if (group_R === null) {
      // From spec: there is at least one dishonest signer (except with negligible probability).
      // Continue with arbitrary use of point G so the dishonest signer can be caught later
      group_R = math.CONST.G
    }
    // Store our R value for the round.
    nonces.push(group_R)
  }
  // Return our nonce points combined into a buffer.
  return get_keys(nonces)
}

export function get_shared_nonces (
  secret  : Bytes,
  altkey  : Bytes,
  message : Bytes
) : Buff[] {
  const int_sec  = ecc.get_seckey(secret)
  const twk_code = ecdh.get_shared_code(int_sec, altkey, { aux: message })
  assert.size(twk_code, 64)
  const sec_nonces : Bytes[] = [],
        pub_nonces : Bytes[] = [],
        alt_nonces : Bytes[] = []
  for (const tweak of parse_keys(twk_code, 64)) {
    const twk_secret = math.modN(int_sec.big * tweak.big)
    const sec_nonce  = ecc.get_seckey(twk_secret, true)
    const pub_nonce  = ecc.get_pubkey(sec_nonce, true)
    sec_nonces.push(sec_nonce)
    pub_nonces.push(pub_nonce)
    alt_nonces.push(Point.from_x(altkey).mul(tweak).x)
  }
  return [
    Buff.join(sec_nonces),
    Buff.join(pub_nonces),
    Buff.join(alt_nonces)
  ]
}
