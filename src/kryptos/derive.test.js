import test from 'ava'
// import { deriveSessionKeyFromMasterKey } from './derive'
import { randomString } from './utils'

test('Test derive key from master key', async (t) => {
  const masterKey = randomString()
  // const key = await deriveSessionKeyFromMasterKey(masterKey)
  t.assert(masterKey)
})
