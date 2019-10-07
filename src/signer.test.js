import test from 'ava'
import { signIt } from './kryptos/signer'
import { generateSigningKeyPair } from './kryptos/keys'
import * as algorithms from './kryptos/algorithms'
import { generateId } from './kryptos/utils'

test('Test create signed Identity', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const id = generateId(32)
  const identity = {
    id,
    pvk: keyPair.publicKey,
    signature: '',
  }
  const signature = await signIt(identity, keyPair.privateKey)
  identity.signature = signature
  t.assert(identity.signature)
})
