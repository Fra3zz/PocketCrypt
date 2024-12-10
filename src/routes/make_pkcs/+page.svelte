<script lang="ts">
  import forge from 'node-forge';

  let certInput: string = '';
  let keyInput: string = '';
  let caChainInput: string = '';
  let password: string = '';
  let errorMessage: string = '';

  function createPkcs12() {
    try {
      // Convert inputs to forge objects
      const cert = forge.pki.certificateFromPem(certInput);
      const privateKey = forge.pki.privateKeyFromPem(keyInput);
      const caChain = caChainInput ? caChainInput.split('\n\n').map(cert => forge.pki.certificateFromPem(cert)) : [];

      // Create a PKCS#12 object
      const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
        privateKey, [cert, ...caChain], password,
        { algorithm: '3des' }
      );

      // Convert to DER format and then to Uint8Array
      const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
      const p12Bytes = new Uint8Array(p12Der.length);
      for (let i = 0; i < p12Der.length; i++) {
        p12Bytes[i] = p12Der.charCodeAt(i);
      }

      // Verify the PKCS#12 file
      const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(p12Der), password);
      if (!p12) {
        throw new Error('Failed to verify PKCS#12 structure');
      }

      // Create a Blob and trigger download
      const blob = new Blob([p12Bytes], { type: 'application/x-pkcs12' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'certificate.p12';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      errorMessage = '';

    } catch (error) {
      console.error('Error creating PKCS#12:', error);
      errorMessage = 'Error creating PKCS#12: ' + (error as Error).message;
    }
  }
</script>

<style>
  .input-group {
    margin-bottom: 1em;
  }

  textarea, input {
    width: 100%;
    box-sizing: border-box;
  }

  .error {
    color: red;
  }
</style>

<div>
  <h1>Create PKCS#12 File</h1>
  <div class="input-group">
    <label for="cert">Certificate (PEM format):</label>
    <textarea id="cert" bind:value={certInput} rows="5" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
  </div>
  <div class="input-group">
    <label for="key">Private Key (PEM format):</label>
    <textarea id="key" bind:value={keyInput} rows="5" placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
  </div>
  <div class="input-group">
    <label for="caChain">CA Chain (PEM format, optional):</label>
    <textarea id="caChain" bind:value={caChainInput} rows="5" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
  </div>
  <div class="input-group">
    <label for="password">Password (optional):</label>
    <input id="password" type="password" bind:value={password} />
  </div>
  <button on:click={createPkcs12}>Generate PKCS#12</button>
  {#if errorMessage}
    <p class="error">{errorMessage}</p>
  {/if}
</div>
