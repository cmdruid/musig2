import { Buff, Bytes }  from '@cmdcode/buff-utils'
import { modN }         from './math.js'
import { KeyOperationError } from './error.js'
import { buffer, hashTag, sort_keys } from './utils.js'

import {
  Point,
  point_x,
  point_add,
  point_mul,
  assert_point,
  is_even,
  N,
  mod_key,
  G
} from './point.js'

function hash_keys (
  pubkeys : Bytes[]
) : Buff {
  // Sort the set of keys in lexicographical order.
  const group_p = sort_keys(pubkeys)
  // Convert the set of keys into a hash.
  return hashTag('KeyAgg list', ...group_p)
}

function hash_key_vector (
  group_hash : Bytes,
  coeff_key  : Bytes
) : Buff {
  return hashTag('KeyAgg coefficient', group_hash, coeff_key)
}

export function get_key_vector (
  pubkeys  : Bytes[],
  self_key : Bytes
) : Buff {
  // Obtain the group key hash.
  const group_hash = hash_keys(pubkeys)
  // Return the coeff_key hash.
  const vector = hash_key_vector(group_hash, self_key)
  // Return the coefficient mod N.
  return Buff.big(modN(vector.big))
}

// function combine_tweaks (
//   tweaks : Bytes[]
// ) : Point {
//   const points = tweaks.map(e => to_point(e))
//   return add_points(points)
// }

export function combine_pubkeys (
  pubkeys  : Bytes[]
) : [ int_point : Point, vectors : Map<string, Buff> ] {
  // Sort keys lexigraphically.
  const keys = sort_keys(pubkeys)
  // We are going to store the key vectors.
  const vectors = new Map()
  // Initialize our group point.
  let group_P : Point | null = null
  // Iterate through our list of pubkeys.
  for (const key of keys) {
    // Calculate the coefficient hash.
    const c = get_key_vector(keys, key)
    // Add the key vector to the map.
    vectors.set(key.hex, c.hex)
    // NOTE: Current spec forces xonly keys here.
    const P = point_x(key)
    // Check if point is null.
    if (P === null) {
      // Report key for returning null.
      throw new KeyOperationError({
        pubkey : key.hex,
        type   : 'point_x',
        reason : 'Point lifted from key is null!'
      })
    }
    // Multiply pubkey with its coefficient.
    const mP = point_mul(P, c.big)
    // Add the point to our sum.
    group_P = point_add(group_P, mP)
    // Check if group point is null.
    if (group_P === null) {
      // Report key for returning null.
      throw new KeyOperationError({
        pubkey : key.hex,
        type   : 'point_add',
        reason : 'Tweaked point nullifies the group!'
      })
    }
  }
  // Assert that final key is not null.
  assert_point(group_P)
  return [ group_P, vectors ]
}

export function get_vector (
  vectors : Map<string, Bytes>,
  pubkey  : Bytes
) : Buff {
  const key = buffer(pubkey)
  const pkv = vectors.get(key.hex)
  // If our key vector is not found, throw.
  if (pkv === undefined) {
    throw new KeyOperationError({
      type   : 'get_vector',
      reason : 'Pubkey is not included in vector map.',
      pubkey : key.hex
    })
  }
  return Buff.bytes(pkv)
}

export function apply_tweaks (
  group_P : Point,
  tweaks  : Bytes[]
) : [ ext_P : Point, parity: bigint, tweak : bigint ] {
  // Convert our tweaks to integers.
  const ints = tweaks.map(e => mod_key(e).big)

  let Q      = group_P,
      g      = 1n, // Handles negation for current round.
      gacc   = 1n, // Stores negation from prev round.
      tacc   = 0n  // Stores the accumulated tweak.

  for (const t of ints) {
    // console.log('prev Q:', to_bytes(Q).hex)
    // If point is odd, g should be negative.
    g = (!is_even(Q)) ? N - 1n : 1n
    console.log('pubkey g:', g)
    // Invert Q based on g, then add tweak.
    Q = point_add(point_mul(Q, g), point_mul(G, t))
    // Assert that Q is not null.
    assert_point(Q)
    // Store our progress for the next round.
    gacc = modN(g * gacc)
    tacc = modN(t + (g * tacc))
    // console.log('g:', g)
    // console.log('gacc:', gacc)
    // console.log('tacc:', tacc)
    // console.log('new Q:', to_bytes(Q).hex)
  }
  return [ Q, gacc, tacc ]
}
