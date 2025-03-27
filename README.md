# PocketCrypt App

## What is this?
One day, I realized the amount of SSL certificate I was having to sign for my PKI. I thoaugh "Is thier a way to simplify this?", absolutly. This is a simple (vary early) SSL certificate managment application. It currenrtly has:

-   Public and Private RSA key generation (max of 4096 right now)
-   Certificate Signing Request(CSR) creation
-   CSR Signing(Currently signes the CSR with all extensions present in the presented CSR. I plan to add the ability to define the extensions and the extended uses on the signing page.)
-   CSR viewing

## Who is this for?
-   Anyone working with their own PKI.

## Build
```bash
bun i && bun run tauri build #This installs the dependencies and builds the application. It will build openssl from source by default but can be edited to use a local install/build of openssl.
```
