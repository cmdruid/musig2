import { Buff, Bytes } from '@cmdcode/buff'
import { PointData }   from '@cmdcode/crypto-tools'
import { hash340 }     from '@cmdcode/crypto-tools/hash'
import { mod_n, pt }   from '@cmdcode/crypto-tools/math'
import { sort_keys }   from './util.js'
import { KeyCoeff }    from './types.js'

import { KeyOperationError } from './error.js'

import * as assert from './assert.js'

function compute_group_hash (
  pubkeys : Bytes[]
) : Buff {
  // Sort the set of keys in lexicographical order.
  const group_p = sort_keys(pubkeys)
  // Convert the set of keys into a hash.
  return hash340('KeyAgg list', ...group_p)
}

function compute_coeff_hash (
  group_hash : Bytes,
  coeff_key  : Bytes
) : Buff {
  return hash340('KeyAgg coefficient', group_hash, coeff_key)
}

export function compute_key_coeff (
  pubkeys  : Bytes[],
  self_key : Bytes
) : Buff {
  // Obtain the group key hash.
  const group_hash  = compute_group_hash(pubkeys)
  // Return the coeff_key hash.
  const coeff_hash = compute_coeff_hash(group_hash, self_key)
  // Return the coefficient mod N.
  return Buff.big(mod_n(coeff_hash.big), 32)
}

export function combine_pubkeys (
  pubkeys  : Bytes[]
) : [ point : PointData, coeffs : KeyCoeff[] ] {
  // Sort keys lexigraphically.
  const keys = sort_keys(pubkeys)
  // Get hash commitment of keys.
  const hash = compute_group_hash(keys)
  // Store the coeff value for each pubkey.
  const coeffs : KeyCoeff[] = []
  // Initialize our group point.
  let group_P : PointData | null = null
  // Iterate through our list of pubkeys.
  for (const key of keys) {
    // Calculate the coeff hash.
    const c = compute_coeff_hash(hash, key)
    // Add the key coeff to the map.
    coeffs.push([ key.hex, c ])
    // NOTE: Current spec forces xonly keys here.
    const P = pt.lift_x(key)
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
    const mP = pt.mul(P, c.big)
    // Add the point to our sum.
    group_P = pt.add(group_P, mP)
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
  // Return group key and coeffs.
  return [ group_P, coeffs ]
}

export function get_key_coeff (
  pubkey : Bytes,
  coeffs : KeyCoeff[]
) : Buff {
  const key = Buff.bytes(pubkey)
  const pkv = coeffs.find(e => e[0] === key.hex)
  // If our key coeff is not found, throw.
  if (pkv === undefined) {
    throw new KeyOperationError({
      type   : 'get_key_coeff',
      reason : 'Pubkey is not included in coeff map.',
      pubkey : key.hex
    })
  }
  return pkv[1]
}
