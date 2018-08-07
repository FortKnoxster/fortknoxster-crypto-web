export const utils = {
  /**
   * TODO consider TextEncoder.encode() Returns a Uint8Array containing utf-8 encoded text.
   * Converts a String to an ArrayBuffer.
   *
   * @param {type} str
   * @returns {ArrayBuffer}
   */
  stringToArrayBuffer(str) {
    const buf = new ArrayBuffer(str.length)
    const bufView = new Uint8Array(buf)
    for (let i = 0, strLen = str.length; i < strLen; i += 1) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  },

  /**
   * Converts an ArrayBuffer to a string of hexadecimal numbers.
   *
   * @param {ArrayBuffer} arrayBuffer
   * @returns {String}
   */
  arrayBufferToHex(arrayBuffer) {
    const byteArray = new Uint8Array(arrayBuffer)
    let hexString = ''
    let nextHexByte

    for (let i = 0; i < byteArray.byteLength; i += 1) {
      nextHexByte = byteArray[i].toString(16) // Integer to base 16
      if (nextHexByte.length < 2) {
        nextHexByte = `0${nextHexByte}` // Otherwise 10 becomes just a instead of 0a
      }
      hexString += nextHexByte
    }
    return hexString
  },
}
