import { Buff }        from '@cmdcode/buff'
import { PointData }   from '@cmdcode/crypto-tools'
import { MusigConfig } from './config.js'

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

export interface KeyContext {
  group_state   : PointState
  group_pubkey  : Buff
  int_state    ?: PointState
  int_pubkey   ?: Buff
  key_coeffs    : KeyCoeff[]
  pub_keys      : Buff[]
}

export interface NonceContext {
  message      : Buff
  pub_nonces   : Buff[]
  int_nonce    : Buff
  group_nonce  : Buff
  nonce_state  : PointState
  nonce_coeff  : Buff
  group_rx     : Buff
  challenge    : Buff
}

export type MusigContext = KeyContext   &
                           NonceContext &
                           { config : MusigConfig }

export interface PartialSig {
  sig    : Buff
  pubkey : Buff
  nonces : Buff[]
}
