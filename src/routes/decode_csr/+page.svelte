<script lang="ts">
    import forge from 'node-forge';
  
    let csrPem: string = '';
    let decodedCsr: string = '';
  
    function decodeCSR() {
      try {
        const csrObj = forge.pki.certificationRequestFromPem(csrPem);
  
        // Subject
        const subject = csrObj.subject.attributes
          .filter(attr => attr.name !== undefined) // Ensure attr.name is defined
          .map(attr => `${attr.name!.padEnd(25)}= ${attr.value}`) // Use non-null assertion
          .join('\n');
  
        // Public Key Info
        const publicKey = csrObj.publicKey as forge.pki.rsa.PublicKey; // Cast to RSA PublicKey
        if (!publicKey || !publicKey.n || !publicKey.e) {
          throw new Error('Invalid public key');
        }
        const modulusBytes = new Uint8Array(publicKey.n.toByteArray().map(byte => byte & 0xff));
        const modulusHex = forge.util.bytesToHex(String.fromCharCode(...modulusBytes));
        const modulusFormatted = modulusHex.match(/.{1,32}/g)?.join('\n') || '';
        const publicKeyInfo = `Public Key Algorithm: rsaEncryption\n    Public-Key: (${publicKey.n.bitLength()} bit)\n    Modulus:        \n${modulusFormatted}\n    Exponent: ${publicKey.e.toString(10)}`;
  
        // Extensions
        const extensions = csrObj.getAttribute({ name: 'extensionRequest' })?.extensions || [];
        const extText = extensions.map(ext => {
          switch (ext.name) {
            case 'keyUsage':
              return `X509v3 Key Usage: \n    ${Object.keys(ext).filter(k => ext[k] === true).join(', ')}`;
            case 'extKeyUsage':
              return `X509v3 Extended Key Usage: \n    ${Object.keys(ext).filter(k => ext[k] === true).join(', ')}`;
            case 'subjectAltName':
              return `X509v3 Subject Alternative Name: \n    ${ext.altNames.map((an: any) => `${an.type === 2 ? 'DNS' : an.type === 1 ? 'email' : 'URI'}:${an.value}`).join(', ')}`;
            case 'basicConstraints':
              return `X509v3 Basic Constraints: \n    CA:${ext.cA}${ext.pathLenConstraint ? `, pathlen:${ext.pathLenConstraint}` : ''}`;
            default:
              return '';
          }
        }).join('\n');
  
        decodedCsr = `Certificate Request:\n    Data:\n        Version: 0 (0x0)\n        Subject:\n${subject}\n    Subject Public Key Info:\n        ${publicKeyInfo}\n    Attributes:\n    Requested Extensions:\n${extText}`;
      } catch (error) {
        decodedCsr = 'Failed to decode CSR.';
      }
    }
  </script>
  
  <main>
    <h1>CSR Decoder</h1>
    <form on:submit|preventDefault={decodeCSR}>
      <div>
        <label for="csrInput">Enter CSR (PEM format):</label>
        <textarea id="csrInput" rows="10" bind:value={csrPem} required></textarea>
      </div>
      <button type="submit">Decode CSR</button>
    </form>
  
    {#if decodedCsr}
      <h2>Decoded CSR</h2>
      <pre>{decodedCsr}</pre>
    {/if}
  </main>
  
  <style>
    main {
      max-width: 800px;
      margin: 0 auto;
      padding: 1rem;
    }
    form {
      margin-bottom: 2rem;
    }
    textarea {
      width: 100%;
      padding: 0.5rem;
      box-sizing: border-box;
      margin-bottom: 1rem;
    }
    button {
      padding: 0.5rem 1rem;
      font-size: 1rem;
    }
    pre {
      background-color: #f4f4f4;
      padding: 1rem;
      white-space: pre-wrap;
    }
  </style>
  