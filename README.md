[![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Naereen/badges/)

# fkx-crypto-web
FortKnoxsters encryption algorithms used in the web app. Kryptos is a cryptographic library wrapping and implementing the Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.

## Documentation
TODO

## Getting Started

For development the recommended way is to link this package from where you are using it.

In importing project run below commands:


```
(cd ../fkx-crypto-web; npm link)
npm link fkx-crypto-web 
```

## Development
TODO

## Testing
[Debug](https://github.com/avajs/ava/blob/main/docs/recipes/debugging-with-chrome-devtools.md)


### Troubleshooting
If error similar to this:
```
mickey@minux-x1:~/Dev/fkx-web-app$ (cd ../fkx-crypto-web; npm link) && npm link fkx-crypto-web
npm ERR! path /home/mickey/Dev/fkx-crypto-web
npm ERR! code EACCES
npm ERR! errno -13
npm ERR! syscall symlink
npm ERR! Error: EACCES: permission denied, symlink '/home/mickey/Dev/fkx-crypto-web' -> '/usr/lib/node_modules/fkx-crypto-web'
npm ERR!  { Error: EACCES: permission denied, symlink '/home/mickey/Dev/fkx-crypto-web' -> '/usr/lib/node_modules/fkx-crypto-web'
npm ERR!   stack: 'Error: EACCES: permission denied, symlink \'/home/mickey/Dev/fkx-crypto-web\' -> \'/usr/lib/node_modules/fkx-crypto-web\'',
npm ERR!   errno: -13,
npm ERR!   code: 'EACCES',
npm ERR!   syscall: 'symlink',
npm ERR!   path: '/home/mickey/Dev/fkx-crypto-web',
npm ERR!   dest: '/usr/lib/node_modules/fkx-crypto-web' }
npm ERR! 
npm ERR! The operation was rejected by your operating system.
npm ERR! It is likely you do not have the permissions to access this file as the current user
npm ERR! 
npm ERR! If you believe this might be a permissions issue, please double-check the
npm ERR! permissions of the file and its containing directories, or try running
npm ERR! the command again as root/Administrator (though this is not recommended).

npm ERR! A complete log of this run can be found in:
npm ERR!     /home/mickey/.npm/_logs/2018-09-28T11_48_04_023Z-debug.log
mickey@minux-x1:~/Dev/fkx-web-app$ 
```

Then try below steps to remove any global installs (with -g):

Step 1)  
From https://github.com/creationix/nvm  
Run: wget -qO- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
Open new terminal and verify installation with:
command -v nvm 

Step 2) 
nvm install stable

For linux use instead of above link commands:

(cd ../fkx-crypto-web; npm link) && npm link fkx-crypto-web 

## License

[APACHE](LICENSE)

