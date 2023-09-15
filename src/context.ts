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
  pubkeys : Bytes[]
) : KeyContext {
  pubkeys.forEach(e => { assert.size(e, 32) })
  const [ point, key_coeffs ] = combine_pubkeys(pubkeys)
  const group_state  = get_pt_state(point)
  const group_pubkey = pt.to_bytes(point).slice(1)
  return {
    group_state,
    group_pubkey,
    key_coeffs,
    pub_keys: pubkeys.map(e => Buff.bytes(e))
  }
}

export function tweak_key_ctx (
  context : KeyContext,
  tweaks ?: Bytes[]
) : KeyContext {
  const { group_state, group_pubkey } = context
  const twk_state  = get_pt_state(group_state.point, tweaks)
  const twk_pubkey = pt.to_bytes(twk_state.point).slice(1)
  return {
    ...context,
    int_state    : group_state,
    int_pubkey   : group_pubkey,
    group_state  : twk_state,
    group_pubkey : twk_pubkey
  }
}

export function get_nonce_ctx (
  pub_nonces : Bytes[],
  grp_pubkey : Bytes,
  message    : Bytes
) : NonceContext {
  assert.size(grp_pubkey, 32)
  pub_nonces.forEach(e => { assert.size(e, 64) })
  const group_nonce = combine_nonces(pub_nonces)
  const nonce_coeff = get_nonce_coeff(group_nonce, grp_pubkey, message)
  const R_point     = compute_R(group_nonce, nonce_coeff)
  const int_nonce   = pt.to_bytes(R_point)
  const nonce_state = get_pt_state(R_point)
  const group_rx    = pt.to_bytes(nonce_state.point).slice(1)
  const challenge   = get_challenge(group_rx, grp_pubkey, message)

  return {
    group_nonce,
    nonce_coeff,
    int_nonce,
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
  const { key_tweaks = [] } = options ?? {}
  let key_ctx = get_key_ctx(pubkeys)
  if (key_tweaks.length > 0) {
    key_ctx = tweak_key_ctx(key_ctx, key_tweaks)
  }
  const nonce_ctx = get_nonce_ctx(nonces, key_ctx.group_pubkey, message)
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
