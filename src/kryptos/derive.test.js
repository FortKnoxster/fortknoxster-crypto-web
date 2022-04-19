import test from 'ava'
import {
  deriveAccountPassword,
  deriveSessionKeyFromMasterKey,
  deriveKeyFromPassword,
} from './derive.js'
import { SHA_512, AES_GCM, AES_KW } from './algorithms.js'
import { LENGTH_32 } from './constants.js'
import { randomString, randomValue } from './utils.js'

test('Test derive AES-GCM key from a master key', async (t) => {
  const masterKey = randomString()
  const key = await deriveSessionKeyFromMasterKey(masterKey)
  t.assert(key && key.algorithm.name === AES_GCM.name)
})

test('Test derive account password default 50000 iterations with SHA-256 (length 64)', async (t) => {
  const username = 'Username'
  const password = 'MyPassw0rd!'
  const domain = 'fortknoxster.com'
  const encryptedPassword = await deriveAccountPassword(
    username,
    password,
    domain,
  )
  t.assert(encryptedPassword && encryptedPassword.length === 64)
})

test('Test derive account password 300000 iterations with SHA-512 (length 128)', async (t) => {
  const username = 'Username'
  const password = 'MyPassw0rd!'
  const domain = 'fortknoxster.com'
  const iterations = 300000
  const hash = SHA_512.name
  const encryptedPassword = await deriveAccountPassword(
    username,
    password,
    domain,
    iterations,
    hash,
  )
  t.assert(encryptedPassword && encryptedPassword.length === 128)
})

test('Test derive AES-KW protector key key from password and random salt with 300000 iterations and SHA-256', async (t) => {
  const password = 'MyPassw0rd!'
  const salt = randomValue(LENGTH_32)
  const iterations = 300000
  const protectorKey = await deriveKeyFromPassword(password, salt, iterations)
  t.assert(protectorKey && protectorKey.algorithm.name === AES_KW.name)
})
