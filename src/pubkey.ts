import { Buff, Bytes }       from '@cmdcode/buff-utils'
import { sort_keys }         from './utils.js'
import { KeyOperationError } from './error.js'

import * as assert from './assert.js'

import {
  digest,
  PointData,
  math,
  point
} from '@cmdcode/crypto-utils'

import { KeyVector } from './schema/types.js'

function get_group_hash (
  pubkeys : Bytes[]
) : Buff {
  // Sort the set of keys in lexicographical order.
  const group_p = sort_keys(pubkeys)
  // Convert the set of keys into a hash.
  return digest('KeyAgg list', ...group_p)
}

function get_vector_hash (
  group_hash : Bytes,
  coeff_key  : Bytes
) : Buff {
  return digest('KeyAgg coefficient', group_hash, coeff_key)
}

export function get_key_vector (
  pubkeys  : Bytes[],
  self_key : Bytes
) : Buff {
  // Obtain the group key hash.
  const group_hash  = get_group_hash(pubkeys)
  // Return the coeff_key hash.
  const vector_hash = get_vector_hash(group_hash, self_key)
  // Return the coefficient mod N.
  return Buff.big(math.modN(vector_hash.big), 32)
}

export function combine_pubkeys (
  pubkeys  : Bytes[]
) : [ point : PointData, vectors : KeyVector[] ] {
  // Sort keys lexigraphically.
  const keys = sort_keys(pubkeys)
  // Get hash commitment of keys.
  const hash = get_group_hash(keys)
  // We are going to store the key vectors.
  const vectors : KeyVector[] = []
  // Initialize our group point.
  let group_P : PointData | null = null
  // Iterate through our list of pubkeys.
  for (const key of keys) {
    // Calculate the vector hash.
    const c = get_vector_hash(hash, key)
    // Add the key vector to the map.
    vectors.push([ key.hex, c ])
    // NOTE: Current spec forces xonly keys here.
    const P = point.lift_x(key)
    // Check if point is null.
    if (P === null) {
      // Report key for returning null.
      throw new KeyOperationError({
        pubkey : key.hex,
        type   : 'lift_x',
        reason : 'Point lifted from key is null!'
      })
    }
    // Multiply pubkey with its coefficient.
    const mP = point.mul(P, c.big)
    // Add the point to our sum.
    group_P = point.add(group_P, mP)
    // Check if group point is null.
    if (group_P === null) {
      // Report key for returning null.
      throw new KeyOperationError({
        pubkey : key.hex,
        type   : 'point_add',
        reason : 'Point nullifies the group!'
      })
    }
  }
  // Assert that final key is not null.
  assert.valid_point(group_P)
  // Return group key and vectors.
  return [ group_P, vectors ]
}

export function get_vector (
  vectors : KeyVector[],
  pubkey  : Bytes
) : Buff {
  const key = Buff.bytes(pubkey)
  const pkv = vectors.find(e => e[0] === key.hex)
  // If our key vector is not found, throw.
  if (pkv === undefined) {
    throw new KeyOperationError({
      type   : 'get_vector',
      reason : 'Pubkey is not included in vector map.',
      pubkey : key.hex
    })
  }
  return pkv[1]
}
