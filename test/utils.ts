import { Buff }       from '@cmdcode/buff-utils'
import { schnorr }    from '@cmdcode/crypto-utils'
import * as Musig2    from '../src/index.js'
import { KeyContext } from '../src/context.js'

import {
  MusigConfig,
  MusigOptions,
  apply_defaults
} from '../src/schema/config.js'
import { to_bytes } from '../src/point.js'

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

  _session ?: KeyContext
  options   : MusigOptions

  constructor (
    signers : string[], 
    config ?: MusigConfig
  ) {
    this.options    = apply_defaults(config)
    this.signatures = []
    this.wallets    = []

    for (const name of signers) {
      // Generate some random secrets using WebCrypto.
      const secret = Buff.str(name).digest
      const nonce  = Buff.join([secret.digest, secret.digest.digest])
      // Create a pair of signing keys.
      const [ sec_key, pub_key     ] = Musig2.gen.key_pair(secret)
      // Create a pair of nonces (numbers only used once).
      const [ sec_nonce, pub_nonce ] = Musig2.gen.nonce_pair(nonce)
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

  get session () : KeyContext {
    if (this._session === undefined) {
      throw new Error('Session undefined!')
    }
    return this._session
  }

  get state () : KeyContext {
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
    return payload as KeyContext
  }

  get signature () : string {
    const { session, signatures } = this
    return Musig2.combine.sigs(session, signatures).hex
  }

  get_session (message : string) : KeyContext {
    return Musig2.combine.keys(
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
      ? apply_defaults(config)
      :this.options
    this._session = this.get_session(message)
    for (const wallet of this.wallets) {
      this.signatures.push(
        Musig2.sign (
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
    return Musig2.verify.sig(this.session, sig)
  }

  verify2 (message : string) : boolean {
    const { group_pubkey } = this.session
    if (group_pubkey === undefined) {
      throw new Error('Group pubkey is undefined!')
    }
    const pub = group_pubkey.slice(1)
    return schnorr.verify(
      this.signature,
      message,
      pub
    )
  }
}
