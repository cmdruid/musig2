import { Buff, Bytes }     from '@cmdcode/buff-utils'
import { math, point }     from '@cmdcode/crypto-utils'
import { combine_pubkeys } from './pubkey.js'
import { apply_tweaks }    from './tweak.js'

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
  MusigConfig,
  MusigSession
} from './schema/index.js'

const { CONST } = math

export function get_context (
  pubkeys  : Bytes[],
  nonces   : Bytes[],
  message  : Bytes,
  options ?: MusigConfig
) : MusigSession {
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

export function get_shared_ctx (
  pubkeys     : Bytes[],
  self_seckey : Bytes,
  peer_pubkey : Bytes,
  message     : Bytes,
  options    ?: MusigConfig
) : [ session : MusigSession, sec_nonce : Buff ] {
  const nonce_ctx = get_shared_nonces(self_seckey, peer_pubkey, message)
  const [ sec_nonce, pub_nonce, alt_nonce ] = nonce_ctx
  const nonces  = [ pub_nonce, alt_nonce ]
  const session = get_context(pubkeys, nonces, message, options)
  return [ session, sec_nonce ]
}

function hexify (
  session : MusigSession
) : MusigSession {
  const obj : any = {}
  for (const k in session) {
    const key = k as keyof MusigSession
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
  return obj as MusigSession
}
