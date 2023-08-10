import { Buff, Bytes }  from '@cmdcode/buff-utils'

import * as ecc    from '@cmdcode/crypto-utils'
import * as assert from './assert.js'
import * as keys   from './keys.js'
import * as util   from './utils.js'

type PointData = ecc.PointData

const buffer = Buff.bytes

const { _G } = ecc.CONST

export function get_nonce_coeff (
  group_nonce : Bytes,
  group_key   : Bytes,
  message     : Bytes
) : Buff {
  const gpx = keys.parse_x(group_key)
  // Combine all bytes into a message challenge.
  const preimg = buffer([ group_nonce, gpx, message ])
  // Hash the challenge.
  const bytes  = ecc.hash.digest('MuSig/noncecoef', preimg)
  // Return bytes as a bigint mod N.
  const coeff  = ecc.math.modN(bytes.big)
  return buffer(coeff, 32)
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
      const n_pt  = ecc.pt.lift_x(nonce)
      // Add point to current group R point.
      group_R = ecc.pt.add(group_R, n_pt)
    }
    if (group_R === null) {
      // From spec: there is at least one dishonest signer (except with negligible probability).
      // Continue with arbitrary use of point G so the dishonest signer can be caught later
      group_R = _G
    }
    // Store our R value for the round.
    points.push(group_R)
  }
  // Return our nonce points combined into a buffer.
  return util.parse_points(points)
}
