import { Buff }         from '@cmdcode/buff-utils'
import { noble }        from '@cmdcode/crypto-utils'
import * as Musig2      from '../src/index.js'
import { MusigSession } from '../src/index.js'

import {
  MusigConfig,
  MusigOptions,
  musig_config
} from '../src/schema/config.js'

import { to_bytes } from '../src/ecc/point.js'

interface Wallet {
  name      : string
  sec_key   : string
  pub_key   : string 
  sec_nonce : string 
  pub_nonce : string
}

export class MusigTest {
  readonly signatures : string[]
  readonly wallets    : Wallet[]

  _session ?: MusigSession
  options   : MusigOptions

  constructor (
    signers : string[], 
    config ?: MusigConfig
  ) {
    this.options    = musig_config(config)
    this.signatures = []
    this.wallets    = []

    for (const name of signers) {
      // Generate some random secrets using WebCrypto.
      const secret = Buff.str(name).digest
      const nonce  = Buff.join([secret.digest, secret.digest.digest])
      // Create a pair of signing keys.
      const [ sec_key, pub_key     ] = Musig2.ecc.get_keypair(secret)
      // Create a pair of nonces (numbers only used once).
      const [ sec_nonce, pub_nonce ] = Musig2.ecc.get_nonce_pair(nonce)
      // Add the member's wallet to the array.
      this.wallets.push({
        name,
        sec_key   : sec_key.hex,
        pub_key   : pub_key.hex,
        sec_nonce : sec_nonce.hex,
        pub_nonce : pub_nonce.hex
      })
    }
  }

  get keys () : string[] {
    return this.wallets.map(e => e.pub_key)
  }

  get group_key () : string {
    const [ P ] = Musig2.calc.group_key(this.keys)
    return to_bytes(P, true).hex
  }

  get nonces () : string[] {
    return this.wallets.map(e => e.pub_nonce)
  }

  get session () : MusigSession {
    if (this._session === undefined) {
      throw new Error('Session undefined!')
    }
    return this._session
  }

  get state () : MusigSession {
    const payload = {}
    for (const key in this.session) {
      const value  = this.session[key]
      if (value instanceof Buff) {
        payload[key] = value.hex
      } else if (Array.isArray(value)) {
        payload[key] = value.map(e => {
          return (e instanceof Buff) ? e.hex : e
        })
      } else {
        payload[key] = value
      }
    }
    return payload as MusigSession
  }

  get signature () : string {
    const { session, signatures } = this
    return Musig2.calc.signature(session, signatures).hex
  }

  get_session (message : string) : MusigSession {
    return Musig2.ctx.get_session(
      this.keys,
      this.nonces,
      message,
      this.options
    )
  }

  sign (
    message : string, 
    config ?: MusigConfig
  ) : string {
    this.options  = (config !== undefined)
      ? musig_config(config)
      :this.options
    this._session = this.get_session(message)
    for (const wallet of this.wallets) {
      this.signatures.push(
        Musig2.musign (
          this.session,
          wallet.sec_key,
          wallet.sec_nonce
        ).hex
      )
    }
    return this.signature
  }

  verify (signature ?: string) : boolean {
    const sig = signature ?? this.signature
    return Musig2.verify.musig(this.session, sig)
  }

  verify2 (message : string) : boolean {
    const { group_pubkey } = this.session
    if (group_pubkey === undefined) {
      throw new Error('Group pubkey is undefined!')
    }
    const pub = group_pubkey.slice(1)
    return noble.schnorr.verify(
      this.signature,
      message,
      pub
    )
  }
}
