/* eslint-disable import/no-extraneous-dependencies */
import browserEnv from 'browser-env'
import { Crypto } from '@peculiar/webcrypto'

browserEnv(['window'])
Object.assign(window, { crypto: new Crypto() })
