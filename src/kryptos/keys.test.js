import test from 'ava'
import * as kryptos from '../index'
import {
  generateSigningKeyPair,
  generateEncryptionKeyPair,
  generateSessionKey,
} from './keys'
import * as algorithms from './algorithms'
// import { publicKeyPem } from '../test/pem/publicKey.pem'

const publicKeyPem =
  '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqVLHT1YowYNMT3odUxRZ7DPgE9KOKof++zcIgOsuTVlW0H5MqYt2hdIMEX+3C2v7iKW+RUs6SdFLuMbASFym4jz36x1nUhVCTfSG2iSf31iIaiUK4Eg/Lb+D4/w3aN+JFXmkisH/asGrRp7yKCQf45sxv2A3E4eXHx3v8Ome4xajYerx2oa9ffFKtVlRQAL8chkMRP60HcZk/IoL1hDyq0h8c/iZYVStM4aEmMyaxUaVBfgE5+zCk3KMxvn6nOHS2bZI+ZHfCklsVTLlyo35Cfd4nceRtWcPzuqFKIA1Ki1+5xpw/VyJovk5nSKkCYa04LOBEM9a5BaXHDHStitPeQIDAQAB-----END PUBLIC KEY-----'

const privateKeyPem =
  '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpUsdPVijBg0xPeh1TFFnsM+AT0o4qh/77NwiA6y5NWVbQfkypi3aF0gwRf7cLa/uIpb5FSzpJ0Uu4xsBIXKbiPPfrHWdSFUJN9IbaJJ/fWIhqJQrgSD8tv4Pj/Ddo34kVeaSKwf9qwatGnvIoJB/jmzG/YDcTh5cfHe/w6Z7jFqNh6vHahr198Uq1WVFAAvxyGQxE/rQdxmT8igvWEPKrSHxz+JlhVK0zhoSYzJrFRpUF+ATn7MKTcozG+fqc4dLZtkj5kd8KSWxVMuXKjfkJ93idx5G1Zw/O6oUogDUqLX7nGnD9XImi+TmdIqQJhrTgs4EQz1rkFpccMdK2K095AgMBAAECggEAUcg/qBwvVzg5lXGf1E7SF/n+UtSyAezpxSCRpOLy3D04Zz95e7J2rrADUDhlisi/FwMm4YUyRBEpB7hHiyvlFwTnodHz43uNKOXgdGCYL2ItkUcO98EtcsU7yNQ7VxYQuiSkyrhky4V7WoLO54B7Po3o+0xXjcFBxq/JAo10Rq4RTujirI0JrxVc2sEr4YOQqKMqDdvYdn1+Mek/O71StUtNqcaAVuB07EynCzZGVi6Lo7uOU7/sIOsQpm2QyqMPGuiR57/AdCksnXy6A4JdrZlf1bFUIMFODyV2HJv1+AcnoAt4th3wHbyKcyoV2QP+/FqoTPkgdHNcmah+2ZhcWQKBgQDVyiBc22VGTH1zL5NMzuxmLiliHNylQDi37IEtrgS0cpL691CLXE7aYLkWxyOBlDqk2q58VABd0dUgMVgp3n+rGqiF71nbaotFk0PNbiA6lfqOm1Sm1bkUu1aPbe2R423kBdcjwLL0qHKF/9hCVlWeXk1JU1TeDzkvo8w7cy2XIwKBgQDKwSH+l0IGFMg6Dx1Cc2O5QAHSz+p+pbv2iKfCu2WGW0ZP1mS3v26S4MPLR1J8SpysKufSDL9xzXpHlJhcAgMIZk4EpIewpcNJ6ppb46n0FtxPYplmJFSXe+juvZzz5GE+VWwOasFwIoV4h6kPrzKkBUoVlO7B4rIk3rn8wiX2swKBgQDQ1MUyDzlpJvRv3KwlHgd7dGIGLa02WnpM5t/0UATWgwihz41E5CE+XbbO0i0TuUhjmh1Q4vkMrBhkfu7gzy+kYsD1O61pkDSE/OoBNC6VK8V5Ia/Z2/ETmD9gkX+7vw2r7CyQBv6H0Dc2P4jum8i8jt8t3hGLbBFvQLAR7ls9QwKBgQCdMvikZ6ntBRfoy+cnqkdbTeEcDdAFuYHuNy26sYiZjxMIu3UDcgzNHC8x4G53p3Gpmup51SBpn6J69R7b10N6s7cxqk76CstK9/YN4InYkhDmC9BbfTeI661BzQlvn1Y1+gz5cJPh2SIavTO60V82BFPYP8yNzrHIHFefPPgqOQKBgGSF/HCpBHASG36w6sbapB8wQtrkMaKKfPlrL4yi0Uwzo8vJgJJZ5IiC6KlRBZkwWuaJQg9fygicQWtcc+syJHEhOvJ+p2glU26oLxO8VIlieqR/P+p3+vWlbVyZFvT0OmulT7YT3z5lrmH5nhwua5nO+88H/ki3wEwIikHQrdSl-----END PRIVATE KEY-----'

test.before(async (t) => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    password: 'Pa$$w0rd!',
  }
})

test('Test importPublicKeyPem', async (t) => {
  const importedPublicKey = await kryptos.importPublicKeyPem(publicKeyPem)
  t.assert(importedPublicKey)
})

test('Test importPrivateKeyPem', async (t) => {
  const importedPrivateKey = await kryptos.importPrivateKeyPem(privateKeyPem)
  t.assert(importedPrivateKey)
})

test('Test deriveAccountPassword', async (t) => {
  const encryptedPassword = await kryptos.deriveAccountPassword(
    'FortKnoxster',
    t.context.password,
    'fortknoxster.com',
  )
  t.is(encryptedPassword.length, 64)
})

test('Test generate RSA signing key pair', async (t) => {
  const keyPair = await generateSigningKeyPair(
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
  )

  t.assert(keyPair.publicKey && keyPair.privateKey)
})

test('Test generate RSA encryption key pair', async (t) => {
  const keyPair = await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO)
  t.assert(keyPair.publicKey && keyPair.privateKey)
})

test('Test generate Elliptic Curve signing key pair', async (t) => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)

  t.assert(keyPair.publicKey && keyPair.privateKey)
})

test('Test generateSessionKey AES-CBC-256', async (t) => {
  const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_CBC_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_CBC_ALGO.length,
  )
})

test('Test generateSessionKey AES-GCM-256', async (t) => {
  const sessionKey = await generateSessionKey(algorithms.AES_GCM_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_GCM_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_GCM_ALGO.length,
  )
})
