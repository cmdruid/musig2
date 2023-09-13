import { Buff, Bytes }   from '@cmdcode/buff'
import { math }          from '@cmdcode/crypto-tools'
import { compute_s }     from './compute.js'
import { get_key_coeff } from './pubkey.js'
import { MusigContext }  from './types.js'

import {
  get_keypair,
  get_pub_nonce
} from './keys.js'

import * as util from './utils.js'

export function musign (
  context   : MusigContext,
  secret    : Bytes,
  sec_nonce : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, Q, key_coeffs, R, nonce_coeff } = context
  // Load secret key into buffer.
  const [ sec, pub ] = get_keypair(secret)
  // Get the coeff for our pubkey.
  const p_v = get_key_coeff(pub, key_coeffs).big
  const sk  = math.mod_n(Q.parity * Q.state * sec.big)
  const cha = util.buffer(challenge).big
  const n_v = util.buffer(nonce_coeff).big
  // Calculate our pub nonce.
  const pn  = get_pub_nonce(sec_nonce)
  // Negate our sec nonce if needed.
  const sn  = Buff.parse(sec_nonce, 32, 64).map(e => {
    // Negate our nonce values if needed.
    return R.parity * e.big
  })
  // Get partial signature.
  const psig = compute_s(sk, p_v, cha, sn, n_v)
  // Return partial signature.
  return Buff.join([ psig, pub, pn ])
}
