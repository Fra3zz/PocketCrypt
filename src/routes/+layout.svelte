<script>
    import "bootstrap"
	let { children } = $props();
</script>

<style>
    @import "bootstrap";
</style>
  <nav class="navbar navbar-expand-lg bg-body-tertiary" data-bs-theme="dark">
    <div class="container-fluid">
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="/">Home</a>
              </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/keys">Make Keys</a>
          </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/csr">Create CSR</a>
          </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/decode_csr">Decrypt CSR</a>
          </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/sign_csr">Sign CSR</a>
          </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/make_pkcs">Make PKCS#12</a>
          </li>
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/pkcs_to_cert">Decode PKCS#12</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
  <br>

{@render children()}