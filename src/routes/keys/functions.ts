import forge, { type Byte, type Bytes } from 'node-forge'

const rsa = forge.pki.rsa

const generateKeys = (keySize:number) => {
    const keys = rsa.generateKeyPair(2048)
    return keys
}

export const makePEM = (privateKey:any, publicKey:any) => {
    let privKey = forge.pki.privateKeyToPem(privateKey);
    let pubKey = forge.pki.publicKeyToPem(publicKey);

    return ([
        {
            privateKeyPEM:privKey,
            publicKeyPEM:pubKey
        }
    ])
}

export const generateKeysPEM = (keySize:number) => {

    const keys = generateKeys(keySize)
    let privateKey = forge.pki.privateKeyToPem(keys.privateKey)
    let publicKey = forge.pki.publicKeyToPem(keys.publicKey)

    return {privateKey, publicKey}
}