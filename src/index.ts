import * as Gen      from './generate.js'
import * as Nonce    from './nonce.js'
import * as ecc      from './point.js'
import * as Pub      from './pubkey.js'
import * as Sig      from './sign.js'
import * as Ver      from './verify.js'
import * as math     from './math.js'
import * as util     from './utils.js'
import { get_key_context } from './context.js'

const calc = {
  group_nonce  : Nonce.combine_nonces,
  group_key    : Pub.combine_pubkeys,
  nonce_vector : Nonce.get_nonce_coeff,
  key_vector   : Pub.get_key_vector,
  challenge    : Sig.get_challenge,
  compute_R    : Sig.compute_R,
  compute_S    : Sig.compute_s
}

const check = {
  nonces: Nonce.check_nonces
}

const gen = {
  random     : Gen.generate_random,
  sec_key    : Gen.generate_seckey,
  pub_key    : Gen.generate_pubkey,
  sec_nonce  : Gen.generate_sec_nonce,
  pub_nonce  : Gen.generate_pub_nonce,
  key_pair   : Gen.generate_keys,
  nonce_pair : Gen.generate_nonces
}

const sign = Sig.sign

const verify = {
  sig: Ver.verify_sig
}

const combine = {
  keys : get_key_context,
  sigs : Ver.combine_sigs
}

export {
  combine,
  calc,
  check,
  ecc,
  gen,
  math,
  sign,
  util,
  verify
}
