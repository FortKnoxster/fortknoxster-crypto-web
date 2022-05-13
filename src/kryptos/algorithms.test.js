/* eslint-disable max-lines */
import test from 'ava'
import * as algorithms from './algorithms.js'

test.before(async (t) => {
  // eslint-disable-next-line no-param-reassign
  t.context = {}
})

test('Test get keyContainer ECDSA-P521 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.ECDSA_ALGO)
  t.assert(keyType === algorithms.ECDSA_P521)
})

test('Test get keyContainer ECDH-P521 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.ECDH_ALGO)
  t.assert(keyType === algorithms.ECDH_P521)
})

test('Test get keyContainer RSASSA-PKCS1-v1_5-2048 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.RSASSA_PKCS1_V1_5_ALGO)
  t.assert(keyType === algorithms.RSASSA_PKCS1_V1_5_2048)
})

test('Test get keyContainer RSA-OAEP-2048 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.RSA_OAEP_ALGO)
  t.assert(keyType === algorithms.RSA_OAEP_2048)
})

test('Test get keyContainer RSA-OAEP-8192 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.RSA_OAEP_ALGO_8K)
  t.assert(keyType === algorithms.RSA_OAEP_8192)
})

test('Test get keyContainer RSA-PSS-8192 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.RSA_PSS_ALGO_8K)
  t.assert(keyType === algorithms.RSA_PSS_8192)
})

test('Test get keyContainer AES-GCM-256 keyType by algorithm', async (t) => {
  const keyType = algorithms.keyContainerType(algorithms.AES_GCM_ALGO)
  t.assert(keyType === algorithms.AES_GCM_256)
})
