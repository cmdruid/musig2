import { Buff, Bytes }     from '@cmdcode/buff-utils'
import { MusigOptions }    from './schema/types.js'
import { DEFAULT_OPT }     from './schema/config.js'
import { to_bytes }        from './point.js'
import { apply_tweaks, combine_pubkeys }   from './pubkey.js'
import { compute_R, get_challenge }        from './sign.js'
import { combine_nonces, get_nonce_coeff } from './nonce.js'

export interface KeyContext {
  pubkeys      : Buff[]
  nonces       : Buff[]
  vectors      : Map<string, Bytes>
  gacc         : bigint
  tacc         : bigint
  internal_key : Buff
  group_pubkey : Buff
  group_nonce  : Buff
  nonce_vector : Buff
  group_R      : Buff
  challenge    : Buff
  options      : MusigOptions
}

export function get_key_context (
  pubkeys : Bytes[],
  nonces  : Bytes[],
  message : Bytes,
  options : Partial<MusigOptions> = {}
) : KeyContext {
  const opt = { ...DEFAULT_OPT, ...options }
  const [ gP, vectors ] = combine_pubkeys(pubkeys)
  const [ Q, gacc, tacc ] = apply_tweaks(gP, opt.tweaks)
  const group_pubkey = to_bytes(Q)
  const internal_key = to_bytes(gP)
  const group_nonce  = combine_nonces(nonces, opt)
  const nonce_vector = get_nonce_coeff(group_nonce, group_pubkey, message)
  const group_R      = compute_R(group_nonce, nonce_vector)
  const challenge    = get_challenge(group_R, group_pubkey, message)

  return {
    vectors,
    gacc,
    tacc,
    internal_key,
    group_pubkey,
    group_nonce,
    nonce_vector,
    group_R,
    challenge,
    pubkeys : pubkeys.map(e => Buff.bytes(e)),
    nonces  : nonces.map(e => Buff.bytes(e)),
    options : opt
  }
}
