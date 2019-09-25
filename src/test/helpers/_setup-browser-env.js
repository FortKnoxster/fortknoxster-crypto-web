/* eslint-disable import/no-extraneous-dependencies */
import browserEnv from 'browser-env'
import WebCrypto from 'node-webcrypto-ossl'

browserEnv(['window'])
Object.assign(window, { crypto: new WebCrypto() })
