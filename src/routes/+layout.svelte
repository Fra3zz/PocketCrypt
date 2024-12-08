<script>
	let { children } = $props();
</script>


<main>
    <div>
        <div>
            <a href="/keys">Make Keys</a>
        </div>
    </div>
</main>

<style>
:root {
  font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 24px;
  font-weight: 400;

  color: #b5b2b2;
  background-color: #585151;

  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-text-size-adjust: 100%;
}

</style>


{@render children()}