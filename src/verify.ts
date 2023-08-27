import { Buff, Bytes }   from '@cmdcode/buff-utils'
import { combine_sigs }  from './combine.js'
import { get_ctx }       from './context.js'
import { get_key_coeff } from './pubkey.js'
import { parse_psig }    from './utils.js'

import {
  MusigContext,
  MusigOptions
} from './schema/index.js'

import * as ecc    from '@cmdcode/crypto-utils'
import * as assert from './assert.js'

const { _G, _N } = ecc.CONST

export function psig (
  context : MusigContext,
  psig    : Bytes
) : boolean {
  const { challenge, Q, R, key_coeffs, nonce_coeff } = context
  const { sig, pubkey, nonces } = parse_psig(psig)
  assert.in_field(sig)
  const kvec = get_key_coeff(pubkey, key_coeffs)
  const P    = ecc.pt.lift_x(pubkey)
  const g_P  = (Q.parity * Q.state) % _N
  const coef = (challenge.big * kvec.big * g_P) % _N
  const R_s1 = ecc.pt.lift_x(nonces[0])
  const R_s2 = ecc.pt.lift_x(nonces[1])
  const R_sP = ecc.pt.add(R_s1, ecc.pt.mul(R_s2, nonce_coeff))
  const R_s  = ecc.pt.mul(R_sP, R.parity)
  assert.valid_point(R_s)
  const S1   = ecc.pt.gen(sig)
  const S2   = ecc.pt.add(R_s, ecc.pt.mul(P, coef))
  assert.valid_point(S1)
  assert.valid_point(S2)
  return ecc.pt.to_bytes(S1).hex === ecc.pt.to_bytes(S2).hex
}

export function with_ctx (
  context   : MusigContext,
  signature : Bytes
) : boolean {
  const { challenge, group_pubkey } = context
  const [ rx, s ] = Buff.parse(signature, 32, 64)
  const S  = ecc.pt.mul(_G, s.big)
  const R  = ecc.pt.lift_x(rx, true)
  const P  = ecc.pt.lift_x(group_pubkey, true)
  const c  = Buff.bytes(challenge).big
  const SP = ecc.pt.add(R, ecc.pt.mul(P, c))
  assert.valid_point(S)
  return ecc.pt.eq(S, SP)
}

export function musign (
  message    : Bytes,
  pub_keys   : Bytes[],
  pub_nonces : Bytes[],
  signatures : Bytes[],
  options   ?: MusigOptions
) : boolean {
  const ctx = get_ctx(pub_keys, pub_nonces, message, options)
  const sig = combine_sigs(ctx, signatures)
  return with_ctx(ctx, sig)
}
