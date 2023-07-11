import { N, is_even, to_bytes } from './point.js'
import { combine_pubkeys }      from './pubkey.js'
import { apply_tweaks }         from './tweak.js'
import { buffer }               from './utils.js'
import { compute_R, get_challenge }        from './sign.js'
import { combine_nonces, get_nonce_coeff } from './nonce.js'

import {
  apply_defaults,
  Buff,
  Bytes,
  MusigConfig,
  MusigOptions
} from './schema/index.js'

export interface KeyContext {
  pubkeys      : Buff[]
  nonces       : Buff[]
  vectors      : Map<string, Bytes>
  R_state      : bigint
  key_parity   : bigint
  key_state    : bigint
  key_tweak    : bigint
  internal_key : Buff
  group_pubkey : Buff
  group_nonce  : Buff
  nonce_vector : Buff
  group_R      : Buff
  challenge    : Buff
  options      : MusigOptions
}

export function get_key_context (
  pubkeys  : Bytes[],
  nonces   : Bytes[],
  message  : Bytes,
  options ?: MusigConfig
) : KeyContext {
  const opt = apply_defaults(options)
  const { tweaks } = opt
  const [ gP, vectors ] = combine_pubkeys(pubkeys)
  const [ Q, parity, state, tweak ] = apply_tweaks(gP, tweaks)
  const group_pubkey = to_bytes(Q)
  const internal_key = to_bytes(gP)
  const group_nonce  = combine_nonces(nonces)
  const nonce_vector = get_nonce_coeff(group_nonce, group_pubkey, message)
  const R            = compute_R(group_nonce, nonce_vector)
  const R_state      = (!is_even(R)) ? N - 1n : 1n
  const group_R      = to_bytes(R)
  const challenge    = get_challenge(group_R, group_pubkey, message)

  return {
    vectors,
    internal_key,
    group_pubkey,
    group_nonce,
    nonce_vector,
    group_R,
    challenge,
    R_state,
    key_parity : parity,
    key_state  : state,
    key_tweak  : tweak,
    pubkeys    : pubkeys.map(e => buffer(e)),
    nonces     : nonces.map(e => buffer(e)),
    options    : opt
  }
}
