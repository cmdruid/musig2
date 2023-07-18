import { Buff, Bytes }  from '@cmdcode/buff-utils'
import { math, point }  from '@cmdcode/crypto-utils'
import { get_context }  from './context.js'
import { combine_sigs } from './combine.js'
import { parse_keys }   from './utils.js'

import * as assert from './assert.js'

import {
  MusigContext,
  MusigOptions
} from './schema/index.js'

const { CONST } = math

export function verify_psig (
 psig : Bytes
) : boolean {
  void psig
  return true
}

export function verify_sig (
  context   : MusigContext,
  signature : Bytes
) : boolean {
  const { challenge, group_pubkey } = context
  const [ rx, s ] = parse_keys(signature, 64)
  const S  = point.mul(CONST.G, s.big)
  const R  = point.lift_x(rx, true)
  const P  = point.lift_x(group_pubkey, true)
  const c  = Buff.bytes(challenge).big
  const SP = point.add(R, point.mul(P, c))
  assert.valid_point(S)
  return point.eq(S, SP)
}

export function verify_psigs (
 context : MusigContext,
 psigs   : Bytes[]
) : boolean {
  const res = psigs.filter(e => !verify_psig(e))
  if (res.length > 0) return false
  const sig = combine_sigs(context, psigs)
  return verify_sig(context, sig)
}

export function verify_musig (
  message    : Bytes,
  pub_keys   : Bytes[],
  pub_nonces : Bytes[],
  signatures : Bytes[],
  options   ?: MusigOptions
) : boolean {
  const ctx = get_context(pub_keys, pub_nonces, message, options)
  return verify_psigs(ctx, signatures)
}
