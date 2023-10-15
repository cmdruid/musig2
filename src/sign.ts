import { Buff, Bytes }   from '@cmdcode/buff'
import { get_key_coeff } from './pubkey.js'
import { parse_psig }    from './util.js'
import { MusigContext }  from './types.js'

import {
  CONST,
  keys,
  math
} from '@cmdcode/crypto-tools'

import {
  apply_sn,
  compute_ps,
  compute_s
} from './compute.js'

import {
  get_keypair,
  get_nonce_pair
} from './keys.js'

import * as assert from './assert.js'

function combine_s (
  signatures : Bytes[]
) : bigint {
  // Initialize s at zero.
  let s = CONST._0n
  // Iterate through each sig:
  for (const psig of signatures) {
    // Convert key to bigint.
    const s_i = Buff.bytes(psig).big
    // Assert key is within range.
    assert.in_field(s_i)
    // Add signature value to s.
    s = math.mod_n(s + s_i)
  }
  return s
}

export function combine_psigs (
  context    : MusigContext,
  signatures : Bytes[]
) : Buff {
  const { challenge, group_state, group_rx } = context
  const { parity, tweak } = group_state
  const sigs = signatures
    .map(e => parse_psig(e))
    .map(e => e.sig)
  const s   = combine_s(sigs)
  const e   = challenge.big
  const a   = e * parity * tweak
  const sig = math.mod_n(s + a)
  // Return the combined signature.
  return Buff.join([
    keys.convert_32b(group_rx),
    Buff.big(sig, 32)
  ])
}

export function musign (
  context : MusigContext,
  secret  : Bytes,
  snonce  : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, key_coeffs, nonce_coeff } = context
  const { group_state, nonce_state } = context
  // Load secret key and nonce values.
  const [ sec, pub ] = get_keypair(secret)
  const [ snp, pn  ] = get_nonce_pair(snonce)
  // Get the coeff for our pubkey.
  const Q   = group_state
  const R   = nonce_state
  const p_v = get_key_coeff(pub, key_coeffs).big
  const sk  = math.mod_n(Q.parity * Q.state * sec.big)
  const cha = Buff.bytes(challenge).big
  const n_v = Buff.bytes(nonce_coeff).big
  // Negate our sec nonce if needed.
  const sn  = Buff.parse(snp, 32, 64).map(e => {
    // Negate our nonce values if needed.
    return R.parity * e.big
  })
  // Get partial signature.
  const psig = compute_s(sk, p_v, cha, sn, n_v)
  // Return partial signature.
  return Buff.join([ psig, pub, pn ])
}

export function cosign_key (
  context : MusigContext,
  secret  : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, group_state, key_coeffs } = context
  // Load secret key and nonce values.
  const [ sec, pub ] = get_keypair(secret)
  // Get the coeff for our pubkey.
  const Q   = group_state
  const p_v = get_key_coeff(pub, key_coeffs).big
  const sk  = math.mod_n(Q.parity * Q.state * sec.big)
  const cha = Buff.bytes(challenge).big
  // Get cosignable signature.
  const csig = compute_ps(sk, p_v, cha)
  // Return partial signature.
  return Buff.join([ csig, pub ])
}

export function cosign_nonce (
  context : MusigContext,
  cosig   : Bytes,
  snonce  : Bytes
) : Buff {
  // Unpack the context we will use.
  const buffer = Buff.bytes(cosig)
  assert.size(buffer, 64)
  const ps  = buffer.subarray(0, 32)
  const pub = buffer.subarray(32, 64)
  const { nonce_coeff, nonce_state } = context
  // Load secret key and nonce values.
  const [ snp, pn ] = get_nonce_pair(snonce)
  // Get the coeff for our pubkey.
  const R   = nonce_state
  const n_v = Buff.bytes(nonce_coeff).big
  // Negate our sec nonce if needed.
  const sn  = Buff.parse(snp, 32, 64).map(e => {
    // Negate our nonce values if needed.
    return R.parity * e.big
  })
  // Get partial signature.
  const psig = apply_sn(ps.big, sn, n_v)
  // Return partial signature.
  return Buff.join([ psig, pub, pn ])
}
