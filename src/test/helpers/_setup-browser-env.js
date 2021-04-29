/* eslint-disable import/no-extraneous-dependencies */
import browserEnv from 'browser-env'
import { Crypto } from 'node-webcrypto-ossl'

browserEnv(['window'])
Object.assign(window, { crypto: new Crypto() })
