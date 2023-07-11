import { Buff }      from '@cmdcode/buff-utils'
import { SecretKey } from '@cmdcode/crypto-utils'
import { MusigTest } from './utils.js'

import {
  Address,
  Signer,
  Tap,
  Tx
} from '@cmdcode/tapscript'

const signers = [ 'alice', 'bob', 'carol' ]
const fee     = 1000
const height  = 2
const sec_key = new SecretKey('38d0a316ba776d6d2d7efba7f190b2a367b66bb7d6c5a40e174e237e9f725140')
const pub_key = sec_key.pub.x.hex

// Set the refund address to sweep.
const payout_address = 'bcrt1q6hwsrytc4njh09cx2jm07l0xfwff78c2mj5yp5'
const sweep_address  = 'bcrt1qgm05c5p6040u6428wrq5ag5jplhthpm9glu5y6'

// Set the UTXO details.
const utxo = {
  txid  : '8b96b6ed8d96c7ab148eaa92da5bced0230aa584f37279b8670ad4eede213ad9',
  vout  : 1,
  prevout : {
    value : 100_000,
    scriptPubKey : [ 'OP_1', pub_key ]
  }
}

const musig   = new MusigTest(signers)
const pubkey  = musig.group_key

const scripts = [
  [ height, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', pub_key, 'OP_CHECKSIG' ],
  [ pubkey, 'OP_CHECKSIG' ]
]

const leaves  = scripts.map(e => Tap.encodeScript(e))
const refund  = scripts[0]
const taproot = Tap.tree.getRoot(leaves)
const tweak   = Tap.tweak.getTweak(pubkey, taproot)
const [ tapkey, cblock ] = Tap.getPubKey(pubkey, { target: Tap.encodeScript(refund) })
const [ ______, pblock ] = Tap.getPubKey(pubkey, { target: Tap.encodeScript(pubkey) })

const deposit_tx = Tx.create({
  vin  : [ utxo ],
  vout : [{
    value : utxo.prevout.value - fee,
    scriptPubKey : [ 'OP_1', tapkey ]
  }]
})

const utxo_sig =  Signer.taproot.sign(sec_key, deposit_tx, 0)
deposit_tx.vin[0].witness = [ utxo_sig ]

const deposit_utxo = {
  txid      : Tx.util.getTxid(deposit_tx),
  vout      : 0,
  prevout   : deposit_tx.vout[0],
  scriptSig : [],
  sequence  : 0xFFFFFFFD,
  witness   : []
}

const deposit_value = deposit_utxo.prevout.value as number

const payout_tx = Tx.create({
  vin  : [ deposit_utxo ],
  vout : [{
    value: deposit_value - fee,
    scriptPubKey : Address.toScriptPubKey(payout_address)
  }]
})

const sighash = Signer.taproot.hash(payout_tx, 0, { sigflag : 0x81 })
const options = { tweaks : [ tweak ] }

const sig = musig.sign(sighash.hex, options)

console.log('internal_key:', pubkey)
console.log('tapkey:', tapkey)
console.log('group_key:', musig.session.group_pubkey.slice(1).hex)

payout_tx.vin = [ deposit_utxo ]
payout_tx.vin[0].witness = [ Buff.join([sig, 0x81]) ]

const refund_tx = Tx.create({
  vin : [{ ...deposit_utxo, sequence: height }],
  vout : [{
    value        : deposit_value - fee,
    scriptPubKey : Address.toScriptPubKey(sweep_address)
  }],
})

const refund_sig = Signer.taproot.sign(sec_key, refund_tx, 0, { extension: tapleaf })

refund_tx.vin[0].witness = [ refund_sig, refund_script, cblock ]

console.log('fund address:', Address.p2tr.fromPubKey(pub_key, 'regtest'))
console.log('deposit tx:', Tx.encode(deposit_tx).hex)
console.log('payout tx:', Tx.encode(payout_tx).hex)
console.log('refund tx:', Tx.encode(refund_tx).hex)

console.log(musig.state)