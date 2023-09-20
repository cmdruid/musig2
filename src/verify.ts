import { Buff, Bytes }   from '@cmdcode/buff'
import { CONST }         from '@cmdcode/crypto-tools'
import { pt }            from '@cmdcode/crypto-tools/math'
import { get_key_coeff } from './pubkey.js'
import { combine_psigs } from './sign.js'
import { parse_psig }    from './util.js'
import { MusigContext }  from './types.js'

import * as assert from './assert.js'

const { _G, _N } = CONST

export function verify_psig (
  context : MusigContext,
  psig    : Bytes
) : boolean {
  const { challenge, key_coeffs, nonce_coeff } = context
  const { group_state, nonce_state } = context
  const { sig, pubkey, nonces } = parse_psig(psig)
  assert.in_field(sig)
  const Q    = group_state
  const R    = nonce_state
  const kvec = get_key_coeff(pubkey, key_coeffs)
  const P    = pt.lift_x(pubkey)
  const g_P  = (Q.parity * Q.state) % _N
  const coef = (challenge.big * kvec.big * g_P) % _N
  const R_s1 = pt.lift_x(nonces[0])
  const R_s2 = pt.lift_x(nonces[1])
  const R_sP = pt.add(R_s1, pt.mul(R_s2, nonce_coeff))
  const R_s  = pt.mul(R_sP, R.parity)
  assert.valid_point(R_s)
  const S1   = pt.gen(sig)
  const S2   = pt.add(R_s, pt.mul(P, coef))
  assert.valid_point(S1)
  assert.valid_point(S2)
  return pt.to_bytes(S1).hex === pt.to_bytes(S2).hex
}

export function verify_musig (
  context   : MusigContext,
  signature : Bytes | Bytes[]
) : boolean {
  const { challenge, group_pubkey } = context
  const sig = (Array.isArray(signature))
    ? combine_psigs(context, signature)
    : signature
  const [ rx, s ] = Buff.parse(sig, 32, 64)
  const S  = pt.mul(_G, s.big)
  const R  = pt.lift_x(rx, true)
  const P  = pt.lift_x(group_pubkey, true)
  const c  = Buff.bytes(challenge).big
  const SP = pt.add(R, pt.mul(P, c))
  assert.valid_point(S)
  return pt.eq(S, SP)
}
