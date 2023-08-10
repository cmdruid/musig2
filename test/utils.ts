import { Buff, Bytes }  from '@cmdcode/buff-utils'
import * as Musig2      from '../src/index.js'
import { MusigContext } from '../src/index.js'

import {
  MusigConfig,
  MusigOptions,
  musig_config
} from '../src/schema/config.js'

interface Wallet {
  sec_key   : string
  pub_key   : string 
  sec_nonce : string 
  pub_nonce : string
}

export class MusigTest {
  readonly wallets : Wallet[]
  readonly opt     : MusigOptions

  constructor (
    signers : string[] | string[][],
    config ?: MusigConfig
  ) {
    this.opt     = musig_config(config)
    this.wallets = []

    for (const signer of signers) {
      let sec_key : Bytes, sec_nonce : Bytes
      if (Array.isArray(signer)) {
        sec_key   = signer[0]
        sec_nonce = signer[1]
      } else {
        // Generate some random secrets using WebCrypto.
        const secret = Buff.str(signer).digest
        const nonce  = Buff.join([secret.digest, secret.digest.digest])
        sec_key   = Musig2.keys.get_seckey(secret).hex
        sec_nonce = Musig2.keys.get_sec_nonce(nonce).hex
      }
      this.wallets.push({
        sec_key,
        sec_nonce,
        pub_key   : Musig2.keys.get_pubkey(sec_key).hex,
        pub_nonce : Musig2.keys.get_pub_nonce(sec_nonce).hex
      })
    }
  }

  get pubkeys () : string[] {
    return this.wallets.map(e => e.pub_key)
  }

  get nonces () : string[] {
    return this.wallets.map(e => e.pub_nonce)
  }

  get_context (message : string) : MusigContext {
    return Musig2.get_ctx(
      this.pubkeys,
      this.nonces,
      message,
      this.opt
    )
  }

  sign (
    message : string, 
    config ?: MusigConfig
  ) : [ string[], MusigContext ] {
    config = { ...this.opt, ...musig_config(config) }
    const psigs : string[] = []
    const ctx   = this.get_context(message)
    for (const wallet of this.wallets) {
      psigs.push(
        Musig2.sign.with_ctx (
          ctx,
          wallet.sec_key,
          wallet.sec_nonce
        ).hex
      )
    }
    return [ psigs, ctx ]
  }
}
