import { Buff, Bytes }       from '@cmdcode/buff-utils'
import { KeyOperationError } from './error.js'
import { modN }              from './math.js'

import {
  hashTag,
  get_keydata
} from './utils.js'

import {
  G,
  Point,
  point_x,
  point_add,
  parse_x,
  get_keys
} from './point.js'

function assert_nonce_size (
  nonce : Buff,
  size  : number
) : void {
  if (nonce.length !== size) {
    throw new KeyOperationError({
      data   : [ nonce.hex ],
      type   : 'nonce_data',
      reason : `Nonce size mismatch: ${nonce.length} !== ${size}`
    })
  }
}

function assert_round_size (
  nonce : Buff
) : void {
  if (nonce.length % 32 !== 0 && nonce.length % 33 !== 0) {
    throw new KeyOperationError({
      data   : [ nonce.hex ],
      type   : 'nonce_data',
      reason : `Invalid nonce size: ${nonce.length}`
    })
  }
}

export function check_nonces (
  pub_nonces : Bytes[]
) : void {
  // Load each nonce into a buffer.
  const nonces = pub_nonces.map(e => Buff.bytes(e))
  // Check each nonce for validity.
  nonces.forEach((nonce, idx) => {
    if (idx > 0) {
      const prev = nonces[idx - 1]
      assert_round_size(nonce)
      assert_nonce_size(nonce, prev.length)
    }
  })
}

export function get_nonce_coeff (
  group_nonce : Bytes,
  group_key   : Bytes,
  message     : Bytes
) : Buff {
  const gpx = parse_x(group_key)
  // Combine all bytes into a message challenge.
  const preimg = Buff.join([ group_nonce, gpx, message ])
  // Hash the challenge.
  const bytes  = hashTag('MuSig/noncecoef', preimg)
  // Return bytes as a bigint mod N.
  const coeff  = modN(bytes.big)
  return Buff.big(coeff, 32)
}

export function combine_nonces (
  pub_nonces : Bytes[]
) : Buff {
  // Check that all nonces are valid.
  check_nonces(pub_nonces)
  // Get key data from first nonce.
  const [ size, rounds ] = get_keydata(pub_nonces[0])
  // Store our group nonces in an array.
  const nonces = []
  // Iterate through each round.
  for (let j = 0; j < rounds; j++) {
    // Start with a null point.
    let group_R : Point | null = null
    // Iterate through each nonce_data.
    for (const data of pub_nonces) {
      // Read data into buffer.
      const bytes = Buff.bytes(data)
      // Configure our index points.
      const start = size * j,
            end   = size * (j + 1)
      // Slice the nonce value from the buffer.
      const nonce = bytes.slice(start, end)
      // Convert nonce value into a point.
      const point = point_x(nonce)
      // Add point to current group R point.
      group_R = point_add(group_R, point)
    }
    if (group_R === null) {
      // From spec: there is at least one dishonest signer (except with negligible probability).
      // Continue with arbitrary use of point G so the dishonest signer can be caught later
      group_R = G
    }
    // Store our R value for the round.
    nonces.push(group_R)
  }
  // Return our nonce points combined into a buffer.
  return get_keys(nonces)
}
