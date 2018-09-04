import { EC_AES_GCM_256 } from './algorithms'
import { base64ToArrayBuffer, dummyCB } from './utils'
import { Encrypter } from '../legacy/kryptos.encrypter'
import { Decrypter } from '../legacy/kryptos.decrypter'

const protocol = {
  keyStore: null,
  nodeId: null,
  userId: null,
}
/**
 * Standard Communication Protocol format.
 *
 * @param {String} type
 * @param {JSON} data
 * @returns {JSON}
 */
function message(type, data) {
  const { nodeId, userId } = protocol
  return {
    From: `${userId}@${nodeId}`,
    To: nodeId,
    ServiceType: type,
    ServiceData: data,
    Flags: 0,
    Timestamp: new Date().getTime(),
    Sign: null,
  }
}

/**
 * Standard Encryption Envelope format used in the Standard Communication
 * Protocol.
 *
 * @param {type} algo
 * @param {type} data
 * @returns {JSON}
 */
function envelope(algo, data) {
  return {
    name: algo || null,
    iv: null,
    encryptedKey: null,
    data: JSON.stringify(data) || null,
  }
}

// TODO move to utils
function tryParseResult(result) {
  try {
    const o = JSON.parse(result)
    if (o && typeof o === 'object') {
      return o
    }
  } catch (e) {
    return result
  }
  return result
}

/**
 * Standard Communication Protocol used for encryption.
 *
 * @param {String} type
 * @param {Object} data
 * @param {Object} nodePrivateEncryptionKey
 * @returns {Promise}
 */
export function encryptProtocol(type, data, nodePEK) {
  const { keyStore } = protocol
  const encrypter = new Encrypter(keyStore, data, null, dummyCB)
  return encrypter.protocol(message(type), envelope(EC_AES_GCM_256), nodePEK)
}

/**
 * Standard Communication Protocol used for decryption.
 *
 * @param {Object} result
 * @param {bool} isError
 * @param {bool} verifyOnly
 * @param {Object} nodePEK
 * @param {Object} nodePVK
 * @returns {void}
 */
export function decryptProtocol(result, isError, verifyOnly, nodePEK, nodePVK) {
  const { keyStore } = protocol
  const data = isError
    ? JSON.parse(result.errors.message)
    : tryParseResult(result)
  const signature = base64ToArrayBuffer(data.Sign, true)
  data.Sign = null // TODO handle this in decrypter
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    null,
    signature,
    null,
    null,
    dummyCB,
  )
  return decrypter.protocol(data, nodePVK, nodePEK, verifyOnly)
}

export function initProtocol(keyStore, nodeId, userId) {
  protocol.keyStore = keyStore
  protocol.nodeId = nodeId
  protocol.userId = userId
}
