import { Buff, Bytes } from '@cmdcode/buff'
import { hash340 }     from '@cmdcode/crypto-tools/hash'
import { mod_n, pt }   from '@cmdcode/crypto-tools/math'
import { convert_32b } from '@cmdcode/crypto-tools/keys'

import {
  PointData,
  CONST
} from '@cmdcode/crypto-tools'

import * as assert from './assert.js'
import * as util   from './utils.js'

// export function tweak_nonces (
//   pub_nonces : Bytes[],
//   tweaks     : Bytes[]
// ) : Buff[] {
//   if (tweaks.length === 0) {
//     return pub_nonces.map(e => Buff.bytes(e))
//   }
//   return pub_nonces.map(e => {
//     const nonces = Buff.parse(e, 32, 64).map(e =>
//       ecc.keys.tweak_pubkey(e, tweaks, true)
//     )
//     return Buff.join(nonces)
//   })
// }

export function get_nonce_coeff (
  group_nonce : Bytes,
  group_key   : Bytes,
  message     : Bytes
) : Buff {
  const gpx = convert_32b(group_key)
  // Combine all bytes into a message challenge.
  const preimg = Buff.bytes([ group_nonce, gpx, message ])
  // Hash the challenge.
  const bytes  = hash340('MuSig/noncecoef', preimg)
  // Return bytes as a bigint mod N.
  const coeff  = mod_n(bytes.big)
  return Buff.bytes(coeff, 32)
}

export function combine_nonces (
  pub_nonces : Bytes[]
) : Buff {
  // Check that all nonces are valid.
  assert.valid_nonce_group(pub_nonces)
  // We are hard-coding 2 nonce values per member.
  const rounds = 2
  // Build an array of nonces from each member.
  const members = pub_nonces.map(e => Buff.parse(e, 32, 64))
  // Store our group nonces in an array.
  const points = []
  // Iterate through each round.
  for (let j = 0; j < rounds; j++) {
    // Start with a null point.
    let group_R : PointData | null = null
    // Iterate through each nonce_data.
    for (const nonces of members) {
      // Read data into buffer.
      const nonce = nonces[j]
      // Convert nonce value into a point.
      const n_pt  = pt.lift_x(nonce)
      // Add point to current group R point.
      group_R = pt.add(group_R, n_pt)
    }
    if (group_R === null) {
      // From spec: there is at least one dishonest signer (except with negligible probability).
      // Continue with arbitrary use of point G so the dishonest signer can be caught later
      group_R = CONST._G
    }
    // Store our R value for the round.
    points.push(group_R)
  }
  // Return our nonce points combined into a buffer.
  return util.parse_points(points)
}
