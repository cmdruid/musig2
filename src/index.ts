import * as Comb  from './combine.js'
import * as Comp  from './compute.js'
import * as Nonce from './nonce.js'
import * as Pub   from './pubkey.js'

export * from './config.js'
export * from './context.js'
export * from './sign.js'
export * from './types.js'
export * from './verify.js'

export * as assert from './assert.js'
export * as keys   from './keys.js'
export * as util   from './utils.js'

export const calc = {
  key_coeff   : Pub.compute_key_coeff,
  nonce_coeff : Nonce.get_nonce_coeff,
  group_rx    : Comp.compute_R,
  group_s     : Comp.compute_s,
  challenge   : Comp.get_challenge
}

export const combine = {
  pubkeys : Pub.combine_pubkeys,
  nonces  : Nonce.combine_nonces,
  psigs   : Comb.combine_sigs
}
