<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  
  let privateKey: string;
  let publicKey: string;
  let keySize: number = 2048; // Default key size
  let loading: boolean = false; // Loading state

  const makeKeys = async (strKeySize: number) => {
    loading = true; // Set loading state to true

    let keySize = Number(strKeySize);

    try {
      // Specify the expected return type of the invoke function
      const [privKey, pubKey]: [string, string] = await invoke<[string, string]>('make_rsa_keys', { keySize });
      privateKey = privKey;
      publicKey = pubKey;
    } catch (error) {
      console.error("Error generating keys:", error);
    } finally {
      loading = false; // Set loading state to false after keys are generated
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      alert("Copied to clipboard!");
    } catch (err) {
      console.error("Failed to copy: ", err);
    }
  };
</script>

<style>
  /* Add your styles here */
</style>

<form on:submit|preventDefault={() => makeKeys(keySize)}>
  <select name="key size" id="Key Size" bind:value={keySize}>
    <option value="1024">1024</option>
    <option value="2048">2048</option>
    <option value="3072">3072</option>
    <option value="4096">4096</option>
  </select>
  <button type="submit">Generate Keys</button>
</form>

{#if loading}
  <h1>LOADING KEYS</h1>
{:else if privateKey && publicKey}
  <div>
    <div>
      <label for="privKey">Private Key</label>
      <pre id="privKey">{privateKey}</pre>
      <button on:click={() => copyToClipboard(privateKey)}>Copy Private Key</button>
    </div>
    <div class="key-container">
      <label for="pubKey">Public Key</label>
      <pre id="pubKey">{publicKey}</pre>
      <button on:click={() => copyToClipboard(publicKey)}>Copy Public Key</button>
    </div>
  </div>
{/if}
