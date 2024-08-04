import { Buff, Bytes }     from '@cmdcode/buff'
import { combine_pubkeys } from './pubkey.js'

import { pt } from '@cmdcode/crypto-tools/math'

import {
  compute_R,
  get_pt_state,
  get_challenge
} from './compute.js'

import {
  combine_nonces,
  get_nonce_coeff
} from './nonce.js'

import {
  musig_config,
  MusigOptions
} from './config.js'

import {
  KeyContext,
  NonceContext,
  MusigContext
} from './types.js'

import * as assert from './assert.js'

export function get_key_ctx (
  pubkeys : Bytes[],
  tweaks ?: Bytes[]
) : KeyContext {
  pubkeys.forEach(e => { assert.size(e, 32) })
  const [ point, key_coeffs ] = combine_pubkeys(pubkeys)
  const int_state    = get_pt_state(point)
  const int_pubkey   = pt.to_bytes(point).slice(1)
  const group_state  = get_pt_state(point, [], tweaks)
  const group_pubkey = pt.to_bytes(group_state.point).slice(1)
  return {
    int_pubkey,
    int_state,
    group_state,
    group_pubkey,
    key_coeffs,
    pub_keys: pubkeys.map(e => Buff.bytes(e))
  }
}

export function get_nonce_ctx (
  pub_nonces : Bytes[],
  grp_pubkey : Bytes,
  message    : Bytes,
  adaptors  ?: Bytes[]
) : NonceContext {
  assert.size(grp_pubkey, 32)
  pub_nonces.forEach(e => { assert.size(e, 64) })
  const group_nonce = combine_nonces(pub_nonces)
  const nonce_coeff = get_nonce_coeff(group_nonce, grp_pubkey, message)
  const R_point     = compute_R(group_nonce, nonce_coeff)
  const int_R       = get_pt_state(R_point)
  const int_rx      = pt.to_bytes(int_R.point).slice(1)
  const nonce_state = get_pt_state(R_point, adaptors)
  const group_rx    = pt.to_bytes(nonce_state.point).slice(1)
  const challenge   = get_challenge(group_rx, grp_pubkey, message)

  return {
    group_nonce,
    nonce_coeff,
    int_rx,
    int_R,
    nonce_state,
    group_rx,
    challenge,
    message    : Buff.bytes(message),
    pub_nonces : pub_nonces.map(e => Buff.bytes(e))
  }
}

export function get_ctx (
  pubkeys  : Bytes[],
  nonces   : Bytes[],
  message  : Bytes,
  options ?: MusigOptions
) : MusigContext {
  const { nonce_tweaks = [], pubkey_tweaks = [] } = options ?? {}
  const key_ctx   = get_key_ctx(pubkeys, pubkey_tweaks)
  const nonce_ctx = get_nonce_ctx(nonces, key_ctx.group_pubkey, message, nonce_tweaks)
  return create_ctx(key_ctx, nonce_ctx, options)
}

export function create_ctx (
  key_ctx  : KeyContext,
  non_ctx  : NonceContext,
  options ?: MusigOptions
) : MusigContext {
  const config = musig_config(options)
  return { ...key_ctx, ...non_ctx, config }
}

export function hexify (
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
