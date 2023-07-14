import tape from 'tape'

import { unit_tests }  from './src/unit.test.js'
import { demo_test }   from './src/demo.test.js'
import { ecdh_test }   from './src/ecdh.test.js'

tape('Musig2 testing suite.', t => {
  unit_tests(t)
  demo_test(t)
  ecdh_test(t)
})
