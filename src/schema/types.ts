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

export type KeyVector = [
  key : string,
  vec : Buff
]

export interface PointState {
  point      : PointData
  key_parity : bigint
  key_state  : bigint
  key_tweak  : bigint
}

export interface MusigContext {
  pub_keys     : Buff[]
  pub_nonces   : Buff[]
  R_state      : bigint
  key_state    : bigint
  key_parity   : bigint
  key_tweak    : bigint
  int_pubkey   : Buff
  group_pubkey : Buff
  group_nonce  : Buff
  key_vectors  : KeyVector[]
  nonce_vector : Buff
  group_rx     : Buff
  challenge    : Buff
  options      : MusigOptions
  to_hex       : () => MusigContext
}
