<script lang="ts">
    import { onMount } from 'svelte';
    import forge from 'node-forge';
  
    // Define types for variables
    let pkcsFile: File | null = null;
    let password: string = '';
    let certificates: string[] = [];
    let privateKey: string = '';
    let errorMessage: string = '';
  
    const handleFileChange = (event: Event) => {
      const target = event.target as HTMLInputElement;
      const file = target.files ? target.files[0] : null;
      if (file) {
        pkcsFile = file;
      }
    };
  
    const handleSubmit = () => {
      if (!pkcsFile) {
        errorMessage = 'Please select a PKCS file.';
        return;
      }
      processFile();
    };
  
    const processFile = () => {
      if (!pkcsFile) {
        errorMessage = 'No file selected.';
        return;
      }
  
      const reader = new FileReader();
      reader.onload = (e) => {
        if (!e.target || !e.target.result) {
          errorMessage = 'Failed to read file.';
          return;
        }
  
        try {
          const p12Asn1 = forge.asn1.fromDer(e.target.result as string);
          const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  
          certificates = [];
          privateKey = '';
  
          p12.safeContents.forEach((safeContent) => {
            safeContent.safeBags.forEach((safeBag) => {
              if (safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
                const cert = forge.pki.certificateToPem(safeBag.cert);
                certificates.push(cert);
              } else if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag && safeBag.key) {
                const key = forge.pki.privateKeyToPem(safeBag.key);
                privateKey = key;
              }
            });
          });
        } catch (error) {
          errorMessage = 'Failed to parse PKCS file. Please check your password or file integrity.';
          console.error(error);
        }
      };
      reader.readAsBinaryString(pkcsFile); // Ensure pkcsFile is not null
    };
  
    const copyToClipboard = (text: string) => {
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard');
      }).catch((err) => {
        console.error('Could not copy text: ', err);
      });
    };
  
    onMount(() => {
      // Reset fields on mount
      pkcsFile = null;
      password = '';
      certificates = [];
      privateKey = '';
      errorMessage = '';
    });
  </script>
  
  <style>
    .upload-container {
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      border-radius: 8px;
      background-color: #f9f9f9;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
  
    .upload-container h2 {
      text-align: center;
      color: #333;
    }
  
    .form-group {
      margin-bottom: 15px;
    }
  
    .form-group label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
    }
  
    .form-group input {
      width: 100%;
      padding: 8px;
      border-radius: 4px;
      border: 1px solid #ccc;
    }
  
    .button {
      display: block;
      width: 100%;
      padding: 10px;
      margin-top: 10px;
      background-color: #007bff;
      color: white;
      text-align: center;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
  
    .button:hover {
      background-color: #0056b3;
    }
  
    .certificates, .private-key {
      margin-top: 20px;
    }
  
    .certificates pre, .private-key pre {
      background-color: #e8e8e8;
      padding: 10px;
      border-radius: 4px;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
  
    .error-message {
      color: red;
      font-weight: bold;
      text-align: center;
    }
  </style>
  
  <div class="upload-container">
    <h2>Upload PKCS File</h2>
    <div class="form-group">
      <label for="pkcsFile">Select PKCS File:</label>
      <input type="file" id="pkcsFile" on:change={handleFileChange} accept=".p12,.pfx" />
    </div>
    <div class="form-group">
      <label for="password">Password (if needed):</label>
      <input type="password" id="password" bind:value={password} />
    </div>
    <button class="button" on:click={handleSubmit}>Submit</button>
    {#if certificates.length > 0 || privateKey}
      <button class="button" on:click={() => copyToClipboard(certificates.join('\n'))}>Copy Certificate Chain</button>
      <button class="button" on:click={() => copyToClipboard(privateKey)}>Copy Private Key</button>
    {/if}
    {#if errorMessage}
      <div class="error-message">{errorMessage}</div>
    {/if}
    {#if certificates.length > 0}
      <div class="certificates">
        <h3>Certificates:</h3>
        {#each certificates as cert}
          <pre>{cert}</pre>
        {/each}
      </div>
    {/if}
    {#if privateKey}
      <div class="private-key">
        <h3>Private Key:</h3>
        <pre>{privateKey}</pre>
      </div>
    {/if}
  </div>
  