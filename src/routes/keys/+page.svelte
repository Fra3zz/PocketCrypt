<script lang="ts">
import { generateKeysPEM } from "./functions";

const KEYS = generateKeysPEM(2048)

</script>

<style>
    .container {
        display: flex;
        align-items: baseline;
        margin: 5px;
        border: black solid;
        padding: 2px;
        
    }
</style>


<div class="container">
    <div class="container">
        <label for="privKey" style="text-align: center;">Private Key</label>
        <pre id="privKey">
            {KEYS.privateKey}
        </pre>
    </div>
    <div class="container">
        <label for="pubKey">Public Key</label>
        <pre id="pubKey">
            {KEYS.publicKey}
        </pre>
    </div>
</div>
