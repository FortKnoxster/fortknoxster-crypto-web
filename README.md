![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)

# FortKnoxster Crypto Web

FortKnoxster Crypto Web is an open source, cross-browser cryptographic library implementing the Web Cryptography API. FortKnoxster Crypto Web supports symmetric keys and asymmetric key pair generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
It is the core end-to-end encryption library used in FortKnoxster Web Apps.

## Getting Started

For development the recommended way is to link this package from where you are using it.

In importing project run below commands:

```
(cd ../fkx-crypto-web; npm link)
npm link fkx-crypto-web
or
(cd ../fkx-crypto-web; npm link) && npm link fkx-crypto-web
```

## Testing

[Debug](https://github.com/avajs/ava/blob/main/docs/recipes/debugging-with-chrome-devtools.md)

```
npm test
```

## License

[APACHE](LICENSE)
