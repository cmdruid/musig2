import { Buff, Bytes }   from '@cmdcode/buff-utils'
import { math }          from '@cmdcode/crypto-utils'
import { compute_s }     from './compute.js'
import { get_key_coeff } from './pubkey.js'
import { get_ctx }       from './context.js'

import {
  MusigOptions,
  MusigContext
}  from './schema/index.js'

import * as keys from './keys.js'
import * as util from './utils.js'

export function with_ctx (
  context   : MusigContext,
  secret    : Bytes,
  sec_nonce : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, Q, key_coeffs, R, nonce_coeff } = context
  // Load secret key into buffer.
  const [ sec, pub ] = keys.get_keypair(secret)
  // Get the coeff for our pubkey.
  const p_v = get_key_coeff(pub, key_coeffs).big
  const sk  = math.modN(Q.parity * Q.state * sec.big)
  const cha = util.buffer(challenge).big
  const n_v = util.buffer(nonce_coeff).big
  // Parse nonce values into an array.
  const sn  = Buff.parse(sec_nonce, 32, 64).map(e => {
    // Negate our nonce values if needed.
    return R.parity * e.big
  })
  const pn  = keys.get_pub_nonce(sec_nonce)
  // Get partial signature.
  const psig = compute_s(sk, p_v, cha, sn, n_v)
  // Return partial signature.
  return Buff.join([ psig, pub, pn ])
}

export function musign (
  message    : Bytes,
  pub_keys   : Bytes[],
  pub_nonces : Bytes[],
  sec_key    : Bytes,
  sec_nonce  : Bytes,
  options   ?: MusigOptions
) : [ sig : Buff, ctx : MusigContext ] {
  const pub_key = keys.get_pubkey(sec_key)
  const pub_non = keys.get_pub_nonce(sec_nonce)
  if (!util.has_key(pub_key, pub_keys)) {
    pub_keys.push(pub_key)
  }
  if (!util.has_key(pub_non, pub_nonces)) {
    pub_keys.push(pub_non)
  }
  const ctx = get_ctx(
    pub_keys,
    pub_nonces,
    message,
    options
  )
  return [ with_ctx(ctx, sec_key, sec_nonce), ctx ]
}
