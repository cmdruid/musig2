const { keys } = require('../../dist/main.cjs')

const [ sec, pub ] = keys.gen_keypair()
const [ sn, pn   ] = keys.gen_nonce_pair()

console.log('seckey:', sec.hex)
console.log('pubkey:', pub.hex)
console.log('snonce:', sn.hex)
console.log('pnonce:', pn.hex)
