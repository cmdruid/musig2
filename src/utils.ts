import { Buff, Bytes }  from '@cmdcode/buff-utils'

export function buffer (bytes : Bytes) : Buff {
  return (bytes instanceof Buff) ? bytes : Buff.bytes(bytes)
}

export function hash_str (str : string) : Buff {
  return Buff.str(str).digest
}

export function assert_size (key : Bytes, size ?: number) : void {
  if (size !== undefined) {
    const b = buffer(key)
    if (size !== b.length) {
      throw new TypeError(`[${b.hex}] Invalid key size: ${b.length} !== ${size}`)
    }
  }
}

export function sort_keys (keys : Bytes[]) : Buff[] {
  const arr = keys.map(e => Buff.bytes(e).hex)
  arr.sort()
  return arr.map(e => Buff.hex(e))
}

export function parse_key (
  key   : Bytes,
  size ?: number
) : Buff {
  const bytes = buffer(key)
  assert_size(bytes, size)
  return bytes
}

export function get_keydata (
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
  assert_size(data, chk_size)
  const [ key_size, rounds ] = get_keydata(data)
  const keys   = []
  const stream = data.stream
  for (let i = 0; i < rounds; i++) {
    keys.push(stream.read(key_size))
  }
  return keys
}

export function hashTag (
  tag : string,
  ...data : Bytes[]
) : Buff {
  const htag = Buff.str(tag).digest.raw
  const buff = data.map(e => Buff.normalize(e))
  return Buff.join([ htag, htag, Buff.join(buff) ]).digest
}

export function hexify (
  obj : Record<any, any>
) : Record<string, string> {
  const ent : [ string, Bytes ][] = Object.entries(obj)
  const hex = ent.map(([ key, bytes ]) => {
    if (bytes instanceof Buff) {
      bytes = bytes.hex
    }
    return [ key, bytes ]
  })
  return Object.fromEntries(hex)
}

export function has_items<T> (arr : Array<T>) : boolean {
  return (Array.isArray(arr) && arr.length > 0)
}
