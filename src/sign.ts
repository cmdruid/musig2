import { Buff, Bytes } from '@cmdcode/buff-utils'
import { math }        from '@cmdcode/crypto-utils'
import { compute_s }   from './compute.js'
import { get_vector }  from './pubkey.js'
import { get_context, get_shared } from './context.js'

import {
  MusigOptions,
  MusigContext
}  from './schema/index.js'

import * as keys from './keys.js'
import * as util from './utils.js'

// We will have a separate method for deriving nonces from seeds.
// We can pre-calc the pub nonces and give them out for the group R calc.
// We can also pass these seeds into the signer to generate the proper sec nonces.

const buffer = Buff.bytes

export function sign (
  context   : MusigContext,
  secret    : Bytes,
  sec_nonce : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, nonce_vector, R_state }   = context
  const { key_state, key_parity, key_vectors } = context
  // Load secret key into buffer.
  const [ sec, pub ] = keys.get_keypair(secret, true, true)
  // Get the vector for our pubkey.
  const p_v = get_vector(key_vectors, pub).big
  const sk  = math.modN(key_parity * key_state * sec.big)
  const cha = buffer(challenge).big
  const n_v = buffer(nonce_vector).big
  // Parse nonce values into an array.
  const sn  = util.parse_keys(sec_nonce).map(e => {
    // Negate our nonce values if needed.
    return  R_state * e.big
  })
  // Return partial signature.
  return compute_s(sk, p_v, cha, sn, n_v)
  // NOTE: Add a partial sig verfiy check here.
}

export function musign (
  message    : Bytes,
  pub_keys   : Bytes[],
  pub_nonces : Bytes[],
  sec_key    : Bytes,
  sec_nonce  : Bytes,
  options   ?: MusigOptions
) : [ sig : Buff, ctx : MusigContext ] {
  const pub_key = keys.get_pubkey(sec_key, true)
  const pub_non = keys.get_pub_nonce(sec_nonce, true)
  if (!util.has_key(pub_key, pub_keys)) {
    pub_keys.push(pub_key)
  }
  if (!util.has_key(pub_non, pub_nonces)) {
    pub_keys.push(pub_non)
  }
  const ctx = get_context(
    pub_keys,
    pub_nonces,
    message,
    options
  )
  return [ sign(ctx, sec_key, sec_nonce), ctx ]
}

export function cosign (
  message   : Bytes,
  peer_pub  : Bytes,
  peer_code : Bytes,
  sec_key   : Bytes,
  sec_code  : Bytes,
  options  ?: MusigOptions
) : [ sig : Buff, ctx : MusigContext ] {
  const pub     = keys.get_pubkey(sec_key, true)
  const pubkeys = [ pub, peer_pub ]
  const [ ctx, sec_nonce ] = get_shared(
    pubkeys,
    peer_code,
    sec_code,
    message,
    options
  )
  return [ sign(ctx, sec_key, sec_nonce), ctx ]
}
