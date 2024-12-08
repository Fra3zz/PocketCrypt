<script>
  import forge from 'node-forge';

  let signingType = 'self'; // 'self' for self-signing, 'ca' for using a CA
  let caPrivateKey = '';
  let csr = '';
  let caCert = '';
  let crlUrl = '';
  let validityStart = '';
  let validityEnd = '';
  let signedCert = '';

  function signCertificate() {
    try {
      // Convert inputs to forge objects
      const caPrivateKeyForge = forge.pki.privateKeyFromPem(caPrivateKey);
      const csrForge = forge.pki.certificationRequestFromPem(csr);

      // Ensure the CSR contains a public key
      if (!csrForge.publicKey) {
        throw new Error('CSR does not contain a public key.');
      }

      let caCertForge = null;
      if (signingType === 'ca' && caCert) {
        caCertForge = forge.pki.certificateFromPem(caCert);
      }

      // Create a new certificate
      const cert = forge.pki.createCertificate();
      cert.publicKey = csrForge.publicKey; // Safe assignment
      cert.serialNumber = '01';

      // Set validity period
      cert.validity.notBefore = new Date(validityStart);
      cert.validity.notAfter = new Date(validityEnd);

      // Set certificate attributes from CSR
      cert.setSubject(csrForge.subject.attributes);

      if (signingType === 'self') {
        // For self-signing, issuer is the same as subject
        cert.setIssuer(csrForge.subject.attributes);
      } else if (signingType === 'ca' && caCertForge) {
        cert.setIssuer(caCertForge.subject.attributes);
      }

      // Add CRL distribution points if provided
      if (crlUrl) {
        cert.setExtensions([{
          name: 'cRLDistributionPoints',
          altNames: [{
            type: 6, // URI
            value: crlUrl
          }]
        }]);
      }

      // Sign the certificate
      cert.sign(caPrivateKeyForge, forge.md.sha256.create());

      // Convert the certificate to PEM format
      signedCert = forge.pki.certificateToPem(cert);
    } catch (error) {
      console.error('Error signing certificate:', error);
      signedCert = 'Error signing certificate. Please check your inputs.';
    }
  }
</script>

<div>
  <h1>Certificate Signer</h1>
  <label>
    Signing Type:
    <select bind:value={signingType}>
      <option value="self">Self-signing</option>
      <option value="ca">Using CA</option>
    </select>
  </label>
  <br />
  <label>
    CA Private Key (PEM):
    <textarea bind:value={caPrivateKey} rows="10" cols="50"></textarea>
  </label>
  <br />
  <label>
    CSR (PEM):
    <textarea bind:value={csr} rows="10" cols="50"></textarea>
  </label>
  <br />
  {#if signingType === 'ca'}
    <label>
      CA Certificate (PEM):
      <textarea bind:value={caCert} rows="10" cols="50"></textarea>
    </label>
    <br />
  {/if}
  <label>
    CRL URL:
    <input type="text" bind:value={crlUrl} />
  </label>
  <br />
  <label>
    Validity Start Date:
    <input type="date" bind:value={validityStart} />
  </label>
  <br />
  <label>
    Validity End Date:
    <input type="date" bind:value={validityEnd} />
  </label>
  <br />
  <button on:click={signCertificate}>Sign Certificate</button>
  <br />
  <h2>Signed Certificate:</h2>
  <pre>{signedCert}</pre>
</div>
