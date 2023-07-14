import * as Comp  from './compute.js'
import * as Nonce from './nonce.js'
import * as Pub   from './pubkey.js'
import * as Ver   from './verify.js'
import * as keys  from './keys.js'
import * as Ctx   from './context.js'

export * from './sign.js'
export * from './schema/index.js'

export * as assert   from './assert.js'
export * as util     from './utils.js'

const {
  gen_seckey,
  gen_keypair,
  gen_nonce_pair,
  ...rest
} = keys

export const calc = {
  group_nonce  : Nonce.combine_nonces,
  group_key    : Pub.combine_pubkeys,
  nonce_vector : Nonce.get_nonce_coeff,
  key_vector   : Pub.get_key_vector,
  challenge    : Comp.get_challenge,
  signature    : Ver.combine_sigs,
  shared_nonce : Nonce.get_shared_nonces,
  group_rx     : Comp.compute_R,
  group_s      : Comp.compute_s
}

export const ctx = {
  get_session : Ctx.get_context,
  get_shared  : Ctx.get_shared_ctx
}

export const ecc = rest

export const gen = {
  seckey     : gen_seckey,
  keypair    : gen_keypair,
  nonce_pair : gen_nonce_pair
}

export const verify = {
  psig  : Ver.verify_psig,
  musig : Ver.verify_sig
}
