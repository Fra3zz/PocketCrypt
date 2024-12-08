<script lang="ts">
    import forge from 'node-forge';
  
    let commonName: string = '';
    let organization: string = '';
    let organizationalUnit: string = '';
    let country: string = '';
    let state: string = '';
    let locality: string = '';
    let emailAddress: string = '';
    let userKeyPem: string = '';
    let selectedKeyUsages: string[] = [];
    let selectedExtendedKeyUsages: string[] = [];
    let sans: string = '';
    let csr: string = '';
    let isCA: boolean = false;
    let pathLength: string = '';
  
    const keyUsageOptions: string[] = [
      'digitalSignature', 'nonRepudiation', 'keyEncipherment',
      'dataEncipherment', 'keyAgreement', 'keyCertSign',
      'cRLSign', 'encipherOnly', 'decipherOnly'
    ];
  
    const extendedKeyUsageOptions: string[] = [
      'serverAuth', 'clientAuth', 'codeSigning',
      'emailProtection', 'timeStamping'
    ];
  
    function generateCSR() {
      let privateKey;
      try {
        privateKey = forge.pki.privateKeyFromPem(userKeyPem);
      } catch (error) {
        alert('Invalid Private Key');
        return;
      }
  
      const csrObject = forge.pki.createCertificationRequest();
      csrObject.publicKey = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e);
  
      csrObject.setSubject([
        { name: 'commonName', value: commonName },
        { name: 'organizationName', value: organization },
        { name: 'organizationalUnitName', value: organizationalUnit },
        { name: 'countryName', value: country },
        { name: 'stateOrProvinceName', value: state },
        { name: 'localityName', value: locality },
        { name: 'emailAddress', value: emailAddress }
      ]);
  
      const extensions = [];
  
      if (selectedKeyUsages.length) {
        const keyUsages = selectedKeyUsages.reduce((acc, usage) => {
          acc[usage] = true;
          return acc;
        }, {} as Record<string, boolean>);
        extensions.push({ name: 'keyUsage', ...keyUsages });
      }
  
      if (selectedExtendedKeyUsages.length) {
        const extKeyUsages = selectedExtendedKeyUsages.reduce((acc, usage) => {
          acc[usage] = true;
          return acc;
        }, {} as Record<string, boolean>);
        extensions.push({ name: 'extKeyUsage', ...extKeyUsages });
      }
  
      if (sans) {
        const altNames = sans.split(',').map(s => s.trim()).map(s => {
          if (s.includes('@')) return { type: 1, value: s }; // Email
          if (s.includes('://')) return { type: 6, value: s }; // URI
          return { type: 2, value: s }; // DNS
        });
  
        extensions.push({ name: 'subjectAltName', altNames });
      }
  
      if (isCA) {
  const basicConstraints: any = { name: 'basicConstraints', cA: true };
  if (pathLength) {
    basicConstraints.pathLenConstraint = parseInt(pathLength, 10);
  }
  extensions.push(basicConstraints);
}
      csrObject.setAttributes([{ name: 'extensionRequest', extensions }]);
  
      csrObject.sign(privateKey);
      csr = forge.pki.certificationRequestToPem(csrObject);
    }
  
    function copyToClipboard() {
      navigator.clipboard.writeText(csr).then(() => {
        alert('CSR copied to clipboard!');
      });
    }
  </script>
  
  <main>
    <h1>CSR Generator</h1>
    <form on:submit|preventDefault={generateCSR}>
      <div>
        <label for="commonName">Common Name:</label>
        <input id="commonName" type="text" bind:value={commonName} required />
      </div>
      <div>
        <label for="organization">Organization:</label>
        <input id="organization" type="text" bind:value={organization} />
      </div>
      <div>
        <label for="organizationalUnit">Organizational Unit:</label>
        <input id="organizationalUnit" type="text" bind:value={organizationalUnit} />
      </div>
      <div>
        <label for="country">Country:</label>
        <input id="country" type="text" bind:value={country} maxlength="2" />
      </div>
      <div>
        <label for="state">State:</label>
        <input id="state" type="text" bind:value={state} />
      </div>
      <div>
        <label for="locality">Locality:</label>
        <input id="locality" type="text" bind:value={locality} />
      </div>
      <div>
        <label for="emailAddress">Email Address:</label>
        <input id="emailAddress" type="email" bind:value={emailAddress} />
      </div>
      <div>
        <label for="userKeyPem">Private Key (PEM format):</label>
        <textarea id="userKeyPem" rows="5" bind:value={userKeyPem} required></textarea>
      </div>
      <div>
        <label for="keyUsages">Key Usages:</label>
        <select id="keyUsages" multiple bind:value={selectedKeyUsages}>
          {#each keyUsageOptions as usage}
            <option value={usage}>{usage}</option>
          {/each}
        </select>
      </div>
      <div>
        <label for="extendedKeyUsages">Extended Key Usages:</label>
        <select id="extendedKeyUsages" multiple bind:value={selectedExtendedKeyUsages}>
          {#each extendedKeyUsageOptions as usage}
            <option value={usage}>{usage}</option>
          {/each}
        </select>
      </div>
      <div>
        <label for="sans">Subject Alternative Names (comma separated):</label>
        <input id="sans" type="text" bind:value={sans} />
      </div>
      <div>
        <label for="isCA">Certificate Authority:</label>
        <input id="isCA" type="checkbox" bind:checked={isCA} />
      </div>
      <div>
        <label for="pathLength">Path Length Constraint:</label>
        <input id="pathLength" type="number" min="0" bind:value={pathLength} disabled={!isCA} />
      </div>
      <button type="submit">Generate CSR</button>
    </form>
  
    {#if csr}
      <h2>Generated CSR</h2>
      <textarea readonly rows="10" bind:value={csr}></textarea>
      <button on:click={copyToClipboard}>Copy to Clipboard</button>
    {/if}
  </main>
  
  <style>
    main {
      max-width: 600px;
      margin: 0 auto;
      padding: 1rem;
    }
    form div {
      margin-bottom: 1rem;
    }
    label {
      display: block;
      margin-bottom: 0.5rem;
    }
    input, textarea, select {
      width: 100%;
      padding: 0.5rem;
      box-sizing: border-box;
    }
    button {
      margin-top: 1rem;
    }
  </style>
  