import * as Comb  from './combine.js'
import * as Comp  from './compute.js'
import * as Ctx   from './context.js'
import * as keys  from './keys.js'
import * as Nonce from './nonce.js'
import * as Pub   from './pubkey.js'
import * as Sig   from './sign.js'
import * as Ver   from './verify.js'

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
  group_key    : Pub.combine_pubkeys,
  key_vector   : Pub.get_key_vector,
  group_nonce  : Nonce.combine_nonces,
  nonce_vector : Nonce.get_nonce_coeff,
  shared_nonce : Nonce.get_shared_nonces,
  group_rx     : Comp.compute_R,
  group_s      : Comp.compute_s,
  challenge    : Comp.get_challenge
}

export const sig = {
  get_ctx      : Ctx.get_context,
  get_shared   : Ctx.get_shared,
  combine_sigs : Comb.combine_sigs,
  get_sig      : Comb.get_signature,
  cosign       : Sig.cosign,
  musign       : Sig.musign,
  sign         : Sig.sign
}

export const ecc = rest

export const gen = {
  seckey     : gen_seckey,
  keypair    : gen_keypair,
  nonce_pair : gen_nonce_pair
}

export const verify = {
  musig : Ver.verify_musig,
  psigs : Ver.verify_psigs,
  psig  : Ver.verify_psig,
  sig   : Ver.verify_sig
}
