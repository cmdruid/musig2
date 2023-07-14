import { Buff } from '@cmdcode/buff-utils'

const _N  = Buff.hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141').big

const _0n = BigInt(0)
const _1n = BigInt(1)
const _2n = BigInt(2)
const _3n = BigInt(3)

export const CONST = {
  0 : BigInt(_0n),
  1 : BigInt(_1n),
  2 : BigInt(_2n),
  3 : BigInt(_3n)
}

export function mod (a : bigint, b : bigint) : bigint {
  const result = a % b
  return result >= _0n ? result : b + result
}

export function pow (
  num    : bigint,
  exp    : bigint,
  modulo : bigint = _N
) : bigint {
  const is_mod = (typeof modulo === 'bigint')
  switch (true) {
    case (exp < _0n):
      throw new Error('Exponent must be greater than or equal to zero.')
    case (is_mod && modulo < _1n):
      throw new Error('Modulo must be greater than or equal to zero.')
    case (is_mod && modulo === _1n):
      return _0n
    default:
      break
  }

  let ans = _1n

  while (exp > _0n) {
    if ((exp & _1n) === _1n) {
      ans *= num
      ans = is_mod ? mod(ans, modulo) : ans
    }
    num *= num
    num = is_mod ? mod(num, modulo) : num
    exp >>= _1n
  }
  return ans
}

export function modN (a : bigint) : bigint {
  return mod(a, _N)
}

export function powN (
  num : bigint,
  exp : bigint
) : bigint {
  return pow(num, exp, _N)
}
