import { Buff }         from '@cmdcode/buff-utils'
import { PointData }    from '@cmdcode/crypto-utils'
import { MusigOptions } from './config.js'

interface Return<T> {
  ok   : true
  data : T
}

interface Fail<T> {
  ok   : false
  data : T
  err  : string
}

interface Warn<T> extends Return<T> {
  warn : T
  err  : string
}

export type OpReturn<T = string> = Return<T> | Fail<T> | Warn<T>

export type KeyCoeff = [
  key   : string,
  coeff : Buff
]

export interface PointState {
  point  : PointData
  parity : bigint
  state  : bigint
  tweak  : bigint
}

export interface MusigContext {
  pub_keys     : Buff[]
  pub_nonces   : Buff[]
  int_pubkey   : Buff
  int_nonce    : Buff
  group_pubkey : Buff
  group_nonce  : Buff
  Q            : PointState
  R            : PointState
  key_coeffs   : KeyCoeff[]
  nonce_coeff  : Buff
  group_rx     : Buff
  challenge    : Buff
  options      : MusigOptions
  to_hex       : () => MusigContext
}

export interface PartialSig {
  sig    : Buff
  pubkey : Buff
  nonces : Buff[]
}
