import { Buff, Bytes }     from '@cmdcode/buff-utils'
import { combine_pubkeys } from './pubkey.js'
import { apply_tweaks }    from './tweak.js'
import { sort_keys }       from './utils.js'

import {
  digest,
  ecc,
  math,
  point
} from '@cmdcode/crypto-utils'

import {
  compute_R,
  get_challenge
} from './compute.js'

import {
  combine_nonces,
  get_nonce_coeff,
  get_shared_nonces
} from './nonce.js'

import {
  musig_config,
  MusigOptions,
  MusigContext
} from './schema/index.js'

const { CONST } = math

export function get_context (
  pubkeys  : Bytes[],
  nonces   : Bytes[],
  message  : Bytes,
  options ?: MusigOptions
) : MusigContext {
  const opt = musig_config(options)
  const { tweaks } = opt
  const [ int_pt, key_vectors ]    = combine_pubkeys(pubkeys)
  const { point: twk_pt, ...rest } = apply_tweaks(int_pt, tweaks)
  const int_pubkey   = point.to_bytes(int_pt)
  const group_pubkey = point.to_bytes(twk_pt)
  const group_nonce  = combine_nonces(nonces)
  const nonce_vector = get_nonce_coeff(group_nonce, group_pubkey, message)
  const R            = compute_R(group_nonce, nonce_vector)
  const R_state      = (!point.is_even(R)) ? CONST.N - 1n : 1n
  const group_rx     = point.to_bytes(R)
  const challenge    = get_challenge(group_rx, group_pubkey, message)

  const session = {
    ...rest,
    key_vectors,
    int_pubkey,
    group_pubkey,
    group_nonce,
    nonce_vector,
    group_rx,
    challenge,
    R_state,
    pub_keys   : pubkeys.map(e => Buff.bytes(e)),
    pub_nonces : nonces.map(e => Buff.bytes(e)),
    options    : opt,
    to_hex     : () => hexify(session)
  }

  return session
}

export function get_shared (
  pub_keys  : Bytes[],
  pub_code  : Bytes,
  sec_code  : Bytes,
  message   : Bytes,
  options  ?: MusigOptions
) : [ MusigContext, Buff ] {
  const self_code   = ecc.get_pubkey(sec_code, false)
  const sorted_pubs = sort_keys(pub_keys)
  const sorted_code = sort_keys([ self_code, pub_code ])
  const preimg = [ ...sorted_pubs, ...sorted_code, message ]
  const hash   = digest('musig/shared', ...preimg)
  const shared = get_shared_nonces(sec_code, pub_code, hash)
  const [ sec_nonce, ...nonces ] = shared
  const ctx = get_context(pub_keys, nonces, message, options)
  return [ ctx, sec_nonce ]
}

function hexify (
  session : MusigContext
) : MusigContext {
  const obj : any = {}
  for (const k in session) {
    const key = k as keyof MusigContext
    const val = session[key]
    if (Array.isArray(val)) {
      obj[key] = val.map(e => {
        if (Array.isArray(e)) {
          return e.map(x => (x instanceof Buff) ? x.hex : x)
        } else if (e instanceof Buff) {
          return e.hex
        } else {
          return e
        }
      })
    } else if (val instanceof Buff) {
      obj[key] = val.hex
    }
  }
  return obj as MusigContext
}
