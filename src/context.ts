import { Buff, Bytes }     from '@cmdcode/buff-utils'
import { combine_pubkeys } from './pubkey.js'

import * as ecc from '@cmdcode/crypto-utils'

import {
  compute_R,
  compute_point_state,
  get_challenge
} from './compute.js'

import {
  combine_nonces,
  get_nonce_coeff
} from './nonce.js'

import {
  musig_config,
  MusigOptions,
  MusigContext
} from './schema/index.js'

export function get_ctx (
  pubkeys  : Bytes[],
  nonces   : Bytes[],
  message  : Bytes,
  options ?: MusigOptions
) : MusigContext {
  const opt = musig_config(options)
  const [ int_point, key_coeffs ] = combine_pubkeys(pubkeys)
  const Q            = compute_point_state(int_point, opt.tweaks)
  const int_pubkey   = ecc.pt.to_bytes(int_point)
  const group_pubkey = ecc.pt.to_bytes(Q.point).slice(1)
  const group_nonce  = combine_nonces(nonces)
  const nonce_coeff  = get_nonce_coeff(group_nonce, group_pubkey, message)
  const R_point      = compute_R(group_nonce, nonce_coeff)
  const int_nonce    = ecc.pt.to_bytes(R_point)
  const R            = compute_point_state(R_point)
  const group_rx     = ecc.pt.to_bytes(R.point).slice(1)
  const challenge    = get_challenge(group_rx, group_pubkey, message)

  const context = {
    Q,
    R,
    key_coeffs,
    int_pubkey,
    int_nonce,
    group_pubkey,
    group_nonce,
    nonce_coeff,
    group_rx,
    challenge,
    pub_keys   : pubkeys.map(e => Buff.bytes(e)),
    pub_nonces : nonces.map(e => Buff.bytes(e)),
    options    : opt,
    to_hex     : () => hexify(context)
  }

  return context
}

function hexify (
  ctx : MusigContext
) : MusigContext {
  const obj : any = {}
  for (const [ key, val ] of Object.entries(ctx)) {
    if (Array.isArray(val)) {
      obj[key] = val.map(e => {
        if (Array.isArray(e)) {
          return e.map(x => (x.hex !== undefined) ? x.hex : x)
        } else if (e instanceof Buff) {
          return e.hex
        } else {
          return e
        }
      })
    } else if (val.hex !== undefined) {
      obj[key] = val.hex
    }
  }
  return obj
}
