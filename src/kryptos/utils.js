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
}
