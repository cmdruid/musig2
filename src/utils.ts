import { Buff, Bytes } from '@cmdcode/buff-utils'
import { PartialSig }  from './schema/types.js'

import * as ecc from '@cmdcode/crypto-utils'

type PointData = ecc.PointData

export const buffer = Buff.bytes
export const random = Buff.random

export function hash_str (str : string) : Buff {
  return Buff.str(str).digest
}

export function has_key (
  key  : Bytes,
  keys : Bytes[]
) : boolean {
  const str = keys.map(e => buffer(e).hex)
  return str.includes(buffer(key).hex)
}

export function sort_keys (keys : Bytes[]) : Buff[] {
  const arr = keys.map(e => buffer(e).hex)
  arr.sort()
  return arr.map(e => Buff.hex(e))
}

export function parse_points (
  points : PointData[],
  xonly ?: boolean
) : Buff {
  let keys = points.map(P => ecc.pt.to_bytes(P))
  if (xonly) keys = keys.map(e => ecc.keys.normalize_32(e))
  // Return the combined points buffer.
  return Buff.join(keys)
}

export function parse_psig (psig : Bytes) : PartialSig {
  const keys = Buff.parse(psig, 32, 128)
  return {
    sig    : keys[0],
    pubkey : keys[1],
    nonces : keys.slice(2)
  }
}

export function hexify (item : any) : Buff | Buff[] | any {
  if (Array.isArray(item)) {
    return item.map(e => hexify(e))
  }
  if (item instanceof Buff) {
    return item.hex
  }
  return item
}

export function has_items<T> (arr : Array<T>) : boolean {
  return (Array.isArray(arr) && arr.length > 0)
}
