import { Buff, Bytes } from '@cmdcode/buff-utils'
import * as assert     from './assert.js'

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

// export function parse_key (
//   key   : Bytes,
//   size ?: number
// ) : Buff {
//   const bytes = Buff.bytes(key)
//   assert.size(bytes, size)
//   return bytes
// }

export function get_key_data (
  key_data : Bytes
) : [ size: number, rounds: number ] {
  const size = Buff.bytes(key_data).length
  switch (true) {
    case (size % 32 === 0):
      return [ 32, size / 32 ]
    case (size % 33 === 0):
      return [ 33, size / 33 ]
    default:
      throw new TypeError(`Invalid key size: ${size}`)
  }
}

export function parse_keys (
  key_data  : Bytes,
  chk_size ?: number
) : Buff[] {
  const data = Buff.bytes(key_data)
  assert.size(data, chk_size)
  const [ key_size, rounds ] = get_key_data(data)
  const keys   = []
  const stream = data.stream
  for (let i = 0; i < rounds; i++) {
    keys.push(stream.read(key_size))
  }
  return keys
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
