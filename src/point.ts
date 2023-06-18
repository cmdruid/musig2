import { Buff, Bytes }    from '@cmdcode/buff-utils'
import { mod, modN, pow } from './math.js'

export interface Point { x : bigint, y : bigint }

const _0n = BigInt(0)
const _1n = BigInt(1)
const _2n = BigInt(2)
const _3n = BigInt(3)

const _P = Buff.hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F').big
const _N = Buff.hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141').big

const _G : Point = {
  x : Buff.hex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798').big,
  y : Buff.hex('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8').big
}

export const P = BigInt(_P)
export const N = BigInt(_N)
export const G = { ..._G }

export function check_key (
  pubkey : Bytes
) : void {
  // Normalize key into bytes.
  const key = Buff.bytes(pubkey)
  if (key.length !== 32 && key.length !== 33) {
    throw new Error(`Public key length is invalid: ${key.length}`)
  }
}

export function mod_key (key : Bytes) : Buff {
  const big = Buff.bytes(key).big
  return Buff.big(modN(big))
}

export function negate_point (point : Point) : Point {
  const { x, y } = point
  return { x, y: _P - y }
}

export function negate_key (key : Bytes) : Buff {
  const k = Buff.bytes(key)
  const n = _N - k.big
  return Buff.big(n)
}

export function point_x (
  pubkey : Bytes,
  xonly  : boolean = false
) : Point {
  // Normalize key into bytes.
  const key = Buff.bytes(pubkey)
  // Check pubkey is valid.
  check_key(pubkey)
  // Marks if key is even or odd.
  const even = (xonly || key.length === 32 || key[0] === 2)
  // Define our variables.
  const x = parse_x(key).big
  // If key is greater than curve, return null.
  if (x >= _P) {
    throw new Error('Lifted key value is greater than curve!')
  }
  // Calculate square root of Y coordiante.
  const y_sq = (pow(x, 3n, _P) + 7n) % _P
  const y_ng = (_P + 1n) / 4n
  const y    = pow(y_sq, y_ng, _P)
  // If y ** 2 does not equal its sqrt, return null.
  if (pow(y, 2n, _P) !== y_sq) {
    console.log('key:', key.hex)
    throw new Error('Computed x value does not equal square root!')
  }
  // Make sure key is negated for even-ness.
  if (
    (even  && (y & _1n) !== _0n) ||
    (!even && (y & _1n) === _0n)
  ) {
    return { x, y: _P - y }
  }
  return { x, y }
}

export function get_points (
  ...bytes : Bytes[]
) : Point[] {
  return bytes.map(e => point_x(e))
}

export function get_keys (
  points : Point[],
  xonly ?: boolean
) : Buff {
  const keys = points.map(P => {
    return to_bytes(P, xonly)
  })
  // Return the combined points buffer.
  return Buff.join(keys)
}

export function add_points (
  points : Point[]
) : Point {
  // Initialize P at null.
  let P : Point | null = null
  points.forEach(p => {
    P = point_add(P, p)
  })
  assert_point(P)
  return P
}

export function parse_x (pubkey : Bytes) : Buff {
  const key = Buff.bytes(pubkey)
  // Key length must be either 32 or 33 bytes.
  if (key.length !== 32 && key.length !== 33) {
    throw new Error(`Invalid key size: ${key.length}`)
  }
  // Ensure only a 32 byte x coordinate is returned.
  return (key.length === 32) ? key : key.slice(1, 33)
}

export function point_eq (
  A : Point,
  B : Point
) : boolean {
  if (A === null && B === null) {
    return true
  }
  if (A !== null && B !== null) {
    if (A.x === B.x && A.y === B.y) {
      return true
    }
  }
  return false
}

export function assert_point (
  P : Point | null
) : asserts P is Point {
  if (P === null) {
    throw new TypeError('Point is null!')
  }
}

export function is_even (P : Point) : boolean {
  return (P.y & _1n) === _0n
}

export function point_add (
  A : Point | null,
  B : Point | null
) : Point {
  if (A === null && B !== null) {
    return B
  }
  if (B === null && A !== null) {
    return A
  }
  if (A === null || B === null) {
    throw new TypeError('Both points are null!')
  }
  if (A.x === B.x && A.y !== B.y) {
    throw new TypeError('Matching x has unequal y!')
  }

  let lam = _0n

  if (point_eq(A, B)) {
    const num = _2n * A.y
    const exp = _P - _2n
    lam = _3n * A.x * A.x * pow(num, exp, _P)
    lam = mod(lam, _P)
  } else {
    const dif = B.y - A.y
    const num = B.x - A.x
    const exp = _P - _2n
    lam = dif * pow(num, exp, _P)
    lam = mod(lam, _P)
  }
  const x3 = lam * lam - A.x - B.x
  const y  = lam * (A.x - x3) - A.y
  return { x: mod(x3, _P), y: mod(y, _P) }
}

export function point_mul (
  P : Point,
  x : bigint
) : Point | null {
  let R : Point | null = null
  for (let i = 0n; i < 256n; i++) {
    if (((x >> i) & _1n) === _1n) {
      R = point_add(R, P)
    }
    P = point_add(P, P)
  }
  return R
}

export function to_point (
  bytes : Bytes,
  xonly : boolean = false
) : Point {
  const sk = mod_key(bytes)
  const P  = point_mul(G, sk.big)
  assert_point(P)
  return (xonly && !is_even(P))
    ? { x: P.x, y: _P - P.y }
    : P
}

export function to_bytes (
  P : Point,
  xonly : boolean = false
) : Buff {
  const x = Buff.big(P.x)
  if (xonly) return x
  return (is_even(P))
    ? Buff.join([ 0x02, x ])
    : Buff.join([ 0x03, x ])
}
