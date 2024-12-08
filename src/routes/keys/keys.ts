import forge, { type Byte, type Bytes } from 'node-forge'

const rsa = forge.pki.rsa

const _generateKeys = (keySize:number) => {
    const keys = rsa.generateKeyPair(keySize)
    return keys
}

export const generateKeysPEM = (keySize:number) => {

    const keys = _generateKeys(keySize)
    let privateKey = forge.pki.privateKeyToPem(keys.privateKey)
    let publicKey = forge.pki.publicKeyToPem(keys.publicKey)

    return {privateKey, publicKey}
}