import { combine, ctx, verify } from '../src/index.js'
import { MusigTest }   from './utils.js'

import { noble } from '@cmdcode/crypto-utils'

const message = '68656c6c6f20776f726c640a'

const session = new MusigTest([
  [
    "8ecaedb40c0cd7c8c82a249449a39faaede06ffcca88b02e90b7edf02082edb9",
    "3d0863a9a6ee328226aeea4a7edeed404b5b27212a1cfde51deb72350b89f0678dadb8238f2f0473931bb16cbaf3ddd673b5f597f7f7d3900154499b406a1c9c"
  ],
  [
    "c6899970c1b3492cfbe3c0bd13e788e51b9b62ede741a75fe0bc7adbfe9d4227",
    "abe1dc409f0266c58430866f108b2507d9de571e6d139f393b8e7c22c2ff50c0cdd0a91108469256c6854801a82e300c871da20c48f83c6dd71c89e8383c5a3e"
  ],
  [
    "ce4ab18a4ea355b12a0082dfefb705a84be4d7ffae55086e8baaa787eb269806",
    "6ac9426fc9bb2933dd9ff74fe542ffcc272df73d03086d8edb79568a9d4b7821d31de473186e85015142b7e50d6cd9861563b0859fbd597dd31cc2f23151d4ee"
  ]
])

const [ psigs, context ] = session.sign(message)

for (const psig of psigs) {
  const isValid = verify.psig(context, psig)
  console.log('psig:', psig)
  console.log('psig valid:', isValid)
}

const signature = combine.psigs(context, psigs)

console.log('signature:', signature.hex)

const isValid1 = verify.with_ctx(context, signature)
const isValid2 = noble.schnorr.verify(signature, message, context.group_pubkey)

console.log(ctx.hexify(context))

console.log('isValid:', isValid1, isValid2)
