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
  let errorMessage = ''; // To hold general error messages
  let dateErrorMessage = ''; // To hold specific date error messages
  let copyMessage = ''; // To display copy success message

  function generateRandomSerialNumber() {
    // Generate a positive random serial number
    // Use a large random number and ensure it's positive by using absolute value
    return Math.abs(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString();
  }

  function signCertificate() {
    try {
      // Reset error messages and copy message
      errorMessage = '';
      dateErrorMessage = '';
      copyMessage = '';

      // Check if validity dates are provided
      if (!validityStart || !validityEnd) {
        dateErrorMessage = 'Both validity start and end dates are required.';
        return;
      }

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
      cert.serialNumber = generateRandomSerialNumber(); // Use a random serial number

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

      // Add extensions from CSR
      const extensionRequest = csrForge.getAttribute({ name: 'extensionRequest' });
      if (extensionRequest && extensionRequest.extensions) {
        const csrExtensions = extensionRequest.extensions;
        cert.setExtensions(csrExtensions);
      }

      // Add CRL distribution points if provided
      const crlExtension = crlUrl ? [{
        name: 'cRLDistributionPoints',
        altNames: [{
          type: 6, // URI
          value: crlUrl
        }]
      }] : [];

      cert.setExtensions((cert.extensions || []).concat(crlExtension));

      // Sign the certificate
      cert.sign(caPrivateKeyForge, forge.md.sha256.create());

      // Convert the certificate to PEM format
      signedCert = forge.pki.certificateToPem(cert);
    } catch (error) {
      console.error('Error signing certificate:', error);
      errorMessage = 'Error signing certificate. Please check your inputs.';
    }
  }

  function copyToClipboard() {
    navigator.clipboard.writeText(signedCert).then(() => {
      copyMessage = 'Certificate copied to clipboard!';
      setTimeout(() => {
        copyMessage = '';
      }, 2000); // Show message for 2 seconds
    }, (err) => {
      console.error('Could not copy text: ', err);
    });
  }
</script>

<style>
  .container {
    display: flex;
    flex-wrap: wrap;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    border: 1px solid #ccc;
    border-radius: 8px;
  }

  .form-section {
    flex: 1;
    padding: 10px;
    min-width: 300px;
  }

  .cert-section {
    flex: 1;
    padding: 10px;
    min-width: 300px;
    display: none;
  }

  .cert-section.visible {
    display: block;
  }

  h1 {
    text-align: center;
    margin-bottom: 20px;
  }

  label {
    display: block;
    margin-bottom: 10px;
  }

  textarea, input[type="text"], input[type="datetime-local"] {
    width: 100%;
    padding: 8px;
    margin-top: 5px;
    margin-bottom: 15px;
    box-sizing: border-box;
  }

  button {
    display: block;
    width: 100%;
    padding: 10px;
    margin-top: 10px;
    cursor: pointer;
  }

  .error-message {
    margin-top: 10px;
    font-weight: bold;
  }

  pre {
    white-space: pre-wrap;
    word-wrap: break-word;
    border: 1px solid #ccc;
    padding: 10px;
  }

  .copy-message {
    text-align: center;
    margin-top: 10px;
    font-weight: bold;
  }
</style>

<div class="container">
  <div class="form-section" style="flex: {signedCert ? '0 0 50%' : '1'};">
    <h1>Certificate Signer</h1>
    <label>
      Signing Type:
      <select bind:value={signingType}>
        <option value="self">Self-signing</option>
        <option value="ca">Using CA</option>
      </select>
    </label>
    <label>
      CA Private Key (PEM):
      <textarea bind:value={caPrivateKey} rows="10"></textarea>
    </label>
    <label>
      CSR (PEM):
      <textarea bind:value={csr} rows="10"></textarea>
    </label>
    {#if signingType === 'ca'}
      <label>
        CA Certificate (PEM):
        <textarea bind:value={caCert} rows="10"></textarea>
      </label>
    {/if}
    <label>
      CRL URL:
      <input type="text" bind:value={crlUrl} />
    </label>
    <label>
      Validity Start Date and Time:
      <input type="datetime-local" bind:value={validityStart} required />
    </label>
    <label>
      Validity End Date and Time:
      <input type="datetime-local" bind:value={validityEnd} required />
    </label>
    <button on:click={signCertificate}>Sign Certificate</button>
    {#if dateErrorMessage}
      <div class="error-message">{dateErrorMessage}</div>
    {/if}
    {#if errorMessage}
      <div class="error-message">{errorMessage}</div>
    {/if}
  </div>
  {#if signedCert}
    <div class="cert-section visible">
      <h2>Signed Certificate:</h2>
      <pre>{signedCert}</pre>
      {#if copyMessage}
        <div class="copy-message">{copyMessage}</div>
      {:else}
        <button on:click={copyToClipboard}>Copy Certificate</button>
      {/if}
    </div>
  {/if}
</div>
