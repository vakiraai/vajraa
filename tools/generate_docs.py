"""
Vajraa GitHub Pages HTML generator.
Run: python tools/generate_docs.py
Writes all HTML pages into docs/
"""

import os

DOCS_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs')
os.makedirs(DOCS_DIR, exist_ok=True)

NAV = [
    ("🏠", "Home", "index.html"),
    ("🚀", "Getting Started", "getting-started.html"),
    ("🏛️", "Architecture", "architecture.html"),
    ("🔄", "Flows", "flows.html"),
    ("🐍", "Python API", "python-api.html"),
    ("⚙️", "C++ API", "cpp-api.html"),
    ("🛡️", "Memory Security", "memory-security.html"),
]

def nav_sidebar(active):
    items = []
    items.append('<nav class="sidebar">')
    items.append('<span class="sidebar-label">Documentation</span>')
    for icon, label, href in NAV:
        cls = 'sidebar-link active' if href == active else 'sidebar-link'
        items.append(f'<a href="{href}" class="{cls}"><span class="icon">{icon}</span>{label}</a>')
    items.append('</nav>')
    return '\n'.join(items)

def page(title, active, breadcrumb, content):
    crumbs = ''.join(
        f'<a href="{h}">{t}</a><span class="sep">/</span>' if h else f'<span class="current">{t}</span>'
        for t, h in breadcrumb
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Vajraa — AI Model Security Library documentation">
<title>{title} — Vajraa Docs</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>

<!-- TOP HEADER -->
<header class="top-header">
  <a href="index.html" class="logo-link">
    <div class="logo-icon">V</div>
    <span class="logo-text">Vajraa</span>
    <span class="logo-badge">v1.0</span>
  </a>
  <div class="header-search">
    <span class="search-icon">🔍</span>
    <input type="text" id="search-input" placeholder="Search docs…">
  </div>
  <nav class="header-nav">
    <a href="https://github.com/vakiraai/vajraa" target="_blank">GitHub</a>
  </nav>
</header>

<div class="layout">
  {nav_sidebar(active)}
  <main class="main">
    <div class="breadcrumb">{crumbs}</div>
    {content}
  </main>
</div>

<button class="back-to-top" id="back-to-top" title="Back to top">↑</button>
<script src="assets/docs.js"></script>
</body>
</html>"""


# ════════════════════════════════════════════════════
#  PAGE 1 — index.html
# ════════════════════════════════════════════════════
INDEX = '''
<h1 class="page-title"><span class="accent">Vajraa</span> — AI Model Security</h1>
<p class="page-subtitle">Encrypt, protect, and distribute machine learning model weights — without ever exposing them to your customers or deployment servers.</p>

<div class="cards-grid">
  <a href="getting-started.html" class="card">
    <div class="card-icon">🚀</div>
    <div class="card-title">Getting Started</div>
    <div class="card-desc">Install Vajraa and encrypt your first model in 5 minutes.</div>
  </a>
  <a href="architecture.html" class="card">
    <div class="card-icon">🏛️</div>
    <div class="card-title">Architecture</div>
    <div class="card-desc">Understand the layered design — from Python API to OS memory pages.</div>
  </a>
  <a href="flows.html" class="card">
    <div class="card-icon">🔄</div>
    <div class="card-title">How It Works</div>
    <div class="card-desc">Step-by-step flows for compilation, inference, and licensing.</div>
  </a>
  <a href="python-api.html" class="card">
    <div class="card-icon">🐍</div>
    <div class="card-title">Python API</div>
    <div class="card-desc">Complete reference for every function in every Python module.</div>
  </a>
  <a href="cpp-api.html" class="card">
    <div class="card-icon">⚙️</div>
    <div class="card-title">C++ API</div>
    <div class="card-desc">The Platform Abstraction Layer and custom ONNX operators.</div>
  </a>
  <a href="memory-security.html" class="card">
    <div class="card-icon">🛡️</div>
    <div class="card-title">Memory Security</div>
    <div class="card-desc">W^R double-mapping, pool tiers, and dynamic cache compaction.</div>
  </a>
</div>

<div class="section">
<h2 id="what-is-vajraa">What is Vajraa?</h2>
<p>Vajraa is a <strong>Python + native C++ library</strong> that solves one of the hardest problems in commercial AI deployment:</p>
<blockquote style="border-left:3px solid var(--accent); padding-left:16px; margin:16px 0; color:var(--text-muted); font-style:italic;">
"How do I give a customer access to my trained ML model without them being able to steal, copy, or reverse-engineer it?"
</blockquote>
<p>Traditional approaches (code obfuscation, DRM wrappers) all share one fatal weakness: the weights eventually end up in RAM in plain form, where a debugger or memory scanner can capture them.</p>
<p>Vajraa solves this at the <strong>operating system memory page level</strong>:</p>
<ul>
  <li>Weights are <strong>never written to RAM in plain form</strong> — they are decrypted directly into OS page-locked memory, behind <code>PAGE_NOACCESS</code> protection.</li>
  <li>A separate <strong>read-only virtual page view</strong> is created for execution — while the write view is simultaneously locked.</li>
  <li>Weights are <strong>zero-wiped immediately</strong> after each forward pass.</li>
  <li>Anti-debug sensors terminate the process if a debugger attaches.</li>
</ul>
</div>

<div class="section">
<h2 id="supported-platforms">Supported Platforms &amp; Frameworks</h2>
<div class="cards-grid" style="grid-template-columns: repeat(auto-fit, minmax(150px,1fr));">
  <div class="card"><div class="card-icon">🪟</div><div class="card-title">Windows</div><div class="card-desc">VirtualAlloc, DPAPI, CreateFileMapping</div></div>
  <div class="card"><div class="card-icon">🐧</div><div class="card-title">Linux</div><div class="card-desc">mmap, /dev/urandom, shm_open</div></div>
  <div class="card"><div class="card-icon">🍎</div><div class="card-title">macOS</div><div class="card-desc">mmap, shm_open, PT_DENY_ATTACH</div></div>
  <div class="card"><div class="card-icon">🔦</div><div class="card-title">PyTorch</div><div class="card-desc">Forward hooks, JIT decryption</div></div>
  <div class="card"><div class="card-icon">📦</div><div class="card-title">ONNX Runtime</div><div class="card-desc">Custom C++ operators</div></div>
</div>
</div>

<div class="section">
<h2 id="quick-example">Quick Example</h2>
<pre><code><span class="cm"># ── Vendor side (offline, one-time) ──────────────────────────────────</span>
<span class="kw">from</span> <span class="nm">vajraa</span> <span class="kw">import</span> compile_model_weights, generate_license
<span class="kw">import</span> <span class="nm">os</span>, <span class="nm">pickle</span>

master_key  = <span class="nm">os</span>.urandom(<span class="nu">32</span>)
customer_key = <span class="nm">os</span>.urandom(<span class="nu">32</span>)   <span class="cm"># share this with customer securely</span>

compiled = compile_model_weights(model.state_dict(), master_key)
pickle.dump(compiled, <span class="fn">open</span>(<span class="st">"model_secured.pkl"</span>, <span class="st">"wb"</span>))

lic = generate_license(<span class="st">"acme_corp"</span>, master_key, customer_key, expiry_days=<span class="nu">365</span>)
<span class="fn">open</span>(<span class="st">"license.lic"</span>, <span class="st">"wb"</span>).write(lic)

<span class="cm"># ── Customer / deployment side ────────────────────────────────────────</span>
<span class="kw">from</span> <span class="nm">vajraa</span> <span class="kw">import</span> secure_wrap_model, VajraaConfig

compiled   = pickle.load(<span class="fn">open</span>(<span class="st">"model_secured.pkl"</span>, <span class="st">"rb"</span>))
config     = <span class="nm">VajraaConfig</span>(use_shuffling=<span class="kw">True</span>, use_tiered_pools=<span class="kw">True</span>, idle_timeout=<span class="nu">5.0</span>)
secure_wrap_model(model, compiled, master_key, config=config)

output = model(input_tensor)   <span class="cm"># weights decrypted JIT, wiped after</span></code></pre>
</div>

<div class="section">
<h2 id="how-it-defends">What Attacks Does It Defend Against?</h2>
<table class="params-table">
<thead><tr><th>Attack Vector</th><th>Vajraa Defence</th></tr></thead>
<tbody>
<tr><td>Process memory dump</td><td>Weights only exist in NOACCESS pages between calls</td></tr>
<tr><td>Debugger breakpoint on memory read</td><td>W^R double mapping — read and write views never overlap</td></tr>
<tr><td>Live process inspection (IDA, x64dbg)</td><td>Anti-debug sensors (IsDebuggerPresent, RDTSC timing, ptrace)</td></tr>
<tr><td>Weight file theft</td><td>Weights stored AES-256-GCM encrypted; master key inside signed license</td></tr>
<tr><td>License sharing</td><td>License tied to customer_key; expiry timestamp enforced</td></tr>
<tr><td>RAM retention after inference</td><td>Secure zero-wipe + OS page release after every forward pass</td></tr>
<tr><td>Idle server memory scan</td><td>Dynamic cache compaction frees pages when server is idle</td></tr>
</tbody>
</table>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 2 — getting-started.html
# ════════════════════════════════════════════════════
GETTING_STARTED = '''
<h1 class="page-title">Getting <span class="accent">Started</span></h1>
<p class="page-subtitle">A step-by-step guide for freshers — from installation to running your first secure inference in under 10 minutes.</p>

<div class="section">
<h2 id="prerequisites">Prerequisites</h2>
<p>Before installing Vajraa, make sure you have the following:</p>
<ul>
  <li><strong>Python 3.9+</strong> — <a href="https://python.org">python.org</a></li>
  <li><strong>PyTorch 2.0+</strong> — <a href="https://pytorch.org">pytorch.org</a></li>
  <li><strong>ONNX Runtime</strong> (optional, for ONNX support) — <code>pip install onnxruntime</code></li>
  <li><strong>cryptography</strong> — <code>pip install cryptography</code></li>
  <li><strong>Visual Studio 2022 Build Tools</strong> (Windows) or <strong>GCC 11+</strong> (Linux) for the C++ extension</li>
</ul>
</div>

<div class="section">
<h2 id="installation">Installation</h2>
<pre><code><span class="cm"># Clone the repository</span>
git clone https://github.com/vakiraai/vajraa.git
cd vajraa

<span class="cm"># Build the native C++ library</span>
cmake -B build -S .
cmake --build build --config Release

<span class="cm"># Copy the compiled DLL into the Python package</span>
cp build/Release/vajraa.dll python/vajraa/    <span class="cm"># Windows</span>
cp build/libvajraa.so python/vajraa/          <span class="cm"># Linux</span>
cp build/libvajraa.dylib python/vajraa/       <span class="cm"># macOS</span>

<span class="cm"># Install Python package</span>
pip install -e python/</code></pre>
</div>

<div class="section">
<h2 id="step1">Step 1 — Create and Train a Model</h2>
<p>You need a trained PyTorch model. Here is a tiny example:</p>
<pre><code><span class="kw">import</span> <span class="nm">torch</span>
<span class="kw">import</span> <span class="nm">torch.nn</span> <span class="kw">as</span> <span class="nm">nn</span>

<span class="kw">class</span> <span class="tp">MyModel</span>(nn.Module):
    <span class="kw">def</span> <span class="fn">__init__</span>(self):
        <span class="fn">super</span>().__init__()
        self.fc1 = nn.Linear(<span class="nu">128</span>, <span class="nu">256</span>)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(<span class="nu">256</span>, <span class="nu">64</span>)
        self.fc3 = nn.Linear(<span class="nu">64</span>, <span class="nu">10</span>)

    <span class="kw">def</span> <span class="fn">forward</span>(self, x):
        <span class="kw">return</span> self.fc3(self.relu(self.fc2(self.relu(self.fc1(x)))))

model = <span class="nm">MyModel</span>()
<span class="cm"># ... train model here ...</span></code></pre>
</div>

<div class="section">
<h2 id="step2">Step 2 — Compile (Encrypt) the Model</h2>
<p>This step is done <strong>once by the vendor</strong>, offline. It encrypts the model weights so they can never be read without the master key.</p>
<pre><code><span class="kw">import</span> <span class="nm">os</span>, <span class="nm">pickle</span>
<span class="kw">from</span> <span class="nm">vajraa.compiler</span> <span class="kw">import</span> compile_model_weights

<span class="cm"># Generate a cryptographically-secure random 32-byte master key</span>
master_key = os.urandom(<span class="nu">32</span>)

<span class="cm"># Compile: encrypts first/last layers, obfuscates intermediate layers</span>
compiled = compile_model_weights(model.state_dict(), master_key)

<span class="cm"># Save to disk — this file can be distributed to customers</span>
<span class="kw">with</span> <span class="fn">open</span>(<span class="st">"model_secured.pkl"</span>, <span class="st">"wb"</span>) <span class="kw">as</span> f:
    pickle.dump(compiled, f)

print(<span class="st">"✅ Encrypted layers:"</span>, <span class="fn">len</span>(compiled[<span class="st">"encrypted_layers"</span>]))
print(<span class="st">"✅ Obfuscated layers:"</span>, <span class="fn">len</span>(compiled[<span class="st">"obfuscated_layers"</span>]))
print(<span class="st">"✅ Max layer size:"</span>, compiled[<span class="st">"metadata"</span>][<span class="st">"max_layer_size_bytes"</span>], <span class="st">"bytes"</span>)</code></pre>
<div class="callout callout-info"><p><strong>ℹ️ What happens inside?</strong> The compiler applies two protections: <strong>AES-256-GCM encryption</strong> to boundary layers (first and last), and <strong>channel permutation + scaling obfuscation</strong> to intermediate layers. See the <a href="flows.html">Flows</a> page for the full walkthrough.</p></div>
</div>

<div class="section">
<h2 id="step3">Step 3 — Generate a License File</h2>
<p>A license ties the model to a specific customer. It contains the master key, encrypted with the customer's own unique key.</p>
<pre><code><span class="kw">from</span> <span class="nm">vajraa.crypto</span> <span class="kw">import</span> generate_license

<span class="cm"># The customer_key is shared with the customer via a secure channel</span>
customer_key = os.urandom(<span class="nu">32</span>)

<span class="cm"># Create license — valid for 365 days</span>
lic_bytes = generate_license(
    customer_id=<span class="st">"acme_corp"</span>,
    master_key=master_key,
    customer_key=customer_key,
    expiry_days=<span class="nu">365</span>
)

<span class="kw">with</span> <span class="fn">open</span>(<span class="st">"license.lic"</span>, <span class="st">"wb"</span>) <span class="kw">as</span> f:
    f.write(lic_bytes)</code></pre>
</div>

<div class="section">
<h2 id="step4">Step 4 — Secure Wrap for Inference (PyTorch)</h2>
<p>On the customer's machine, load the compiled model and wrap it for secure inference. <strong>The customer never has access to the raw master key</strong> — it is unwrapped from the license file on the fly.</p>
<pre><code><span class="kw">import</span> <span class="nm">pickle</span>
<span class="kw">from</span> <span class="nm">vajraa.crypto</span> <span class="kw">import</span> decrypt_license
<span class="kw">from</span> <span class="nm">vajraa.pytorch_wrapper</span> <span class="kw">import</span> secure_wrap_model, VajraaConfig

<span class="cm"># Load compiled model (distributed by vendor)</span>
<span class="kw">with</span> <span class="fn">open</span>(<span class="st">"model_secured.pkl"</span>, <span class="st">"rb"</span>) <span class="kw">as</span> f:
    compiled = pickle.load(f)

<span class="cm"># Decrypt license to get master_key</span>
<span class="kw">with</span> <span class="fn">open</span>(<span class="st">"license.lic"</span>, <span class="st">"rb"</span>) <span class="kw">as</span> f:
    lic_data = decrypt_license(f.read(), customer_key)
master_key = lic_data[<span class="st">"master_key"</span>]

<span class="cm"># Choose security profile</span>
config = <span class="nm">VajraaConfig</span>(
    use_shuffling=<span class="kw">True</span>,       <span class="cm"># random slot selection (prevents timing analysis)</span>
    use_tiered_pools=<span class="kw">True</span>,    <span class="cm"># tiered memory buckets by size</span>
    use_hybrid_mode=<span class="kw">True</span>,     <span class="cm"># auto-fall back to JIT if RAM is low</span>
    idle_timeout=<span class="nu">5.0</span>,          <span class="cm"># release pages after 5s idle (web server mode)</span>
)

<span class="cm"># Attach secure hooks — model.forward() is now protected</span>
secure_wrap_model(model, compiled, master_key, config=config)

<span class="cm"># Run inference — weights decrypt JIT and are wiped immediately after</span>
x = torch.randn(<span class="nu">1</span>, <span class="nu">128</span>)
output = model(x)
print(output.shape)   <span class="cm"># torch.Size([1, 10])</span></code></pre>
</div>

<div class="section">
<h2 id="step5">Step 5 — ONNX Runtime Path</h2>
<p>Alternatively, export your model to ONNX, rewrite it with Vajraa's encrypted operators, then run via <code>SecureONNXSession</code>.</p>
<pre><code><span class="kw">import</span> <span class="nm">torch</span>
<span class="kw">import</span> <span class="nm">numpy</span> <span class="kw">as</span> <span class="nm">np</span>
<span class="kw">from</span> <span class="nm">vajraa.onnx_compiler</span> <span class="kw">import</span> rewrite_onnx_graph
<span class="kw">from</span> <span class="nm">vajraa.onnx_wrapper</span> <span class="kw">import</span> SecureONNXSession

<span class="cm"># Step A: Export to plain ONNX</span>
torch.onnx.export(model, torch.randn(<span class="nu">1</span>,<span class="nu">128</span>), <span class="st">"model.onnx"</span>,
                  input_names=[<span class="st">"input"</span>], output_names=[<span class="st">"output"</span>])

<span class="cm"># Step B: Rewrite with encrypted operators (vendor side)</span>
rewrite_onnx_graph(<span class="st">"model.onnx"</span>, <span class="st">"model.ems"</span>, master_key)

<span class="cm"># Step C: Deploy — customer loads the secured model</span>
session = <span class="nm">SecureONNXSession</span>(
    model_path=<span class="st">"model.ems"</span>,
    license_path=<span class="st">"license.lic"</span>,
    customer_key=customer_key,
    config=config
)
output = session.run([<span class="st">"output"</span>], {<span class="st">"input"</span>: np.random.randn(<span class="nu">1</span>,<span class="nu">128</span>).astype(<span class="st">"float32"</span>)})
print(output[<span class="nu">0</span>].shape)</code></pre>
</div>

<div class="section">
<h2 id="troubleshooting">Common Issues</h2>
<table class="params-table">
<thead><tr><th>Error</th><th>Cause</th><th>Fix</th></tr></thead>
<tbody>
<tr><td><code>FileNotFoundError: vajraa.dll</code></td><td>C++ library not built or not copied</td><td>Run <code>cmake --build build --config Release</code> then copy DLL</td></tr>
<tr><td><code>SecurityError: License verification failed</code></td><td>Wrong customer_key or tampered license</td><td>Check you're using the same customer_key used to generate the license</td></tr>
<tr><td><code>SecurityError: License has expired</code></td><td>expiry_days elapsed</td><td>Generate a new license with <code>generate_license(..., expiry_days=N)</code></td></tr>
<tr><td><code>MemoryError: pal_alloc_secure failed</code></td><td>Insufficient memory or sandbox restriction</td><td>Enable <code>use_hybrid_mode=True</code> in VajraaConfig</td></tr>
</tbody>
</table>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 3 — architecture.html
# ════════════════════════════════════════════════════
ARCHITECTURE = '''
<h1 class="page-title">System <span class="accent">Architecture</span></h1>
<p class="page-subtitle">A layered walkthrough of every component — from the Python developer API down to OS virtual memory pages.</p>

<div class="section">
<h2 id="overview">Layer Overview</h2>
<div class="arch-diagram"><pre class="layer-api">
┌─────────────────────────────────────────────────────────────────────┐
│                      DEVELOPER API LAYER                            │
│  compile_model_weights()  │  rewrite_onnx_graph()                  │
│  generate_license()       │  secure_wrap_model()                   │
│  SecureONNXSession        │  VajraaConfig                          │
└────────────┬──────────────────────────────────────┬────────────────┘
             │                                      │</pre>
<pre class="layer-rt">┌────────────▼──────────────┐         ┌──────────────▼──────────────┐
│    PYTORCH RUNTIME        │         │    ONNX RUNTIME             │
│  secure_wrap_model()      │         │  SecureONNXSession          │
│  Pre / Post forward hooks │         │  C++ Custom Operators:      │
│  VajraaMemoryPool         │         │   SecureGemmKernel          │
│  VajraaMemorySlot         │         │   SecureConvKernel          │
│  (write_ptr + read_ptr)   │         │   SecureConvTransposeKernel │
└────────────┬──────────────┘         └──────────────┬──────────────┘
             │                                       │</pre>
<pre class="layer-crypto">             └──────────────────┬────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                    CRYPTO ENGINE                                     │
│  crypto.py                   │  crypto_engine.cpp                   │
│  encrypt_tensor()            │  vajraa_decrypt_gcm()                │
│  decrypt_tensor()            │  AES-256-GCM (OpenSSL on Linux/Mac) │
│  generate_license()          │  AES-256-GCM (CNG/BCrypt on Windows)│
│  decrypt_license()           │                                      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │</pre>
<pre class="layer-pal">┌───────────────────────────────▼─────────────────────────────────────┐
│                  PLATFORM ABSTRACTION LAYER (PAL)                   │
│  pal.h declares: pal_alloc_secure  pal_unlock  pal_lock             │
│                  pal_secure_zero   pal_free_secure                  │
│                  pal_store_key     pal_retrieve_key                 │
│                  pal_configure_pool  pal_lease_secure_slot          │
│                  pal_get_read_view   pal_compact_pool               │
│                                                                     │
│  pal_windows.cpp   pal_linux.cpp   pal_macos.cpp                   │
│  pal_android.cpp   pal_embedded.c                                   │
│                                                                     │
│  OS Primitives:                                                     │
│  Windows → VirtualAlloc / VirtualProtect / CreateFileMapping        │
│  Linux   → mmap / mprotect / shm_open / /dev/urandom               │
│  macOS   → mmap / mprotect / shm_open / PT_DENY_ATTACH             │
└─────────────────────────────────────────────────────────────────────┘</pre>
</div>
</div>

<div class="section">
<h2 id="python-modules">Python Modules</h2>
<table class="params-table">
<thead><tr><th>File</th><th>Responsibility</th></tr></thead>
<tbody>
<tr><td><code>crypto.py</code></td><td>AES-256-GCM encrypt/decrypt for tensors and license blobs</td></tr>
<tr><td><code>compiler.py</code></td><td>One-time compilation: encrypt + obfuscate + inject mixer weights</td></tr>
<tr><td><code>base_shield.py</code></td><td>Simple JIT hook wrapping for all model layers (no pool)</td></tr>
<tr><td><code>lora_shield.py</code></td><td>Same as base_shield but for LoRA adapter A/B weight matrices</td></tr>
<tr><td><code>pytorch_wrapper.py</code></td><td>Advanced pooled JIT wrapping with VajraaConfig, double-mapping, compaction</td></tr>
<tr><td><code>onnx_compiler.py</code></td><td>Rewrites ONNX graph: replaces Gemm/Conv with encrypted custom op nodes</td></tr>
<tr><td><code>onnx_wrapper.py</code></td><td>SecureONNXSession: loads .ems, configures C++ pool, manages compaction timer</td></tr>
<tr><td><code>pal.py</code></td><td>Python ctypes bridge to the native C++ shared library</td></tr>
</tbody>
</table>
</div>

<div class="section">
<h2 id="cpp-modules">C++ Native Modules</h2>
<table class="params-table">
<thead><tr><th>File</th><th>Responsibility</th></tr></thead>
<tbody>
<tr><td><code>pal.h</code></td><td>C ABI header — all PAL function declarations</td></tr>
<tr><td><code>pal_windows.cpp</code></td><td>Windows implementation using VirtualAlloc, VirtualProtect, DPAPI, CreateFileMapping</td></tr>
<tr><td><code>pal_linux.cpp</code></td><td>Linux implementation using mmap, mprotect, shm_open, /dev/urandom</td></tr>
<tr><td><code>pal_macos.cpp</code></td><td>macOS implementation using mmap, mprotect, shm_open, ptrace PT_DENY_ATTACH</td></tr>
<tr><td><code>pal_android.cpp</code></td><td>Android/ARM variant (mmap, /dev/urandom)</td></tr>
<tr><td><code>pal_embedded.c</code></td><td>Minimal C implementation for embedded targets (no OS memory APIs)</td></tr>
<tr><td><code>crypto_engine.cpp</code></td><td>AES-256-GCM decryption using BCrypt (Windows) or OpenSSL (Linux/macOS)</td></tr>
<tr><td><code>secure_gemm_op.cpp</code></td><td>ONNX Runtime custom operators: SecureGemm, SecureConv, SecureConvTranspose</td></tr>
</tbody>
</table>
</div>

<div class="section">
<h2 id="memory-model">Memory Model — What Happens to Weights</h2>
<pre><code>
At REST (compiled model on disk):
  ┌─────────────────┐
  │  model.pkl      │  ← encrypted_layers: { "fc1.weight": { iv, ciphertext, tag } }
  │  license.lic    │  ← master_key wrapped with customer_key (AES Key Wrap RFC 3394)
  └─────────────────┘

During INFERENCE (one forward pass):

  Time →    │  pre_hook      │ layer.forward()  │ post_hook       │  idle
  ──────────┼────────────────┼──────────────────┼─────────────────┼─────────
  write_ptr │ READWRITE      │ NOACCESS         │ zeroed→NOACCESS │ NOACCESS
  read_ptr  │ NOACCESS       │ READONLY         │ NOACCESS        │ NOACCESS
  weights   │ decrypting     │ readable only    │ zeroed          │ gone
  ──────────┼────────────────┼──────────────────┼─────────────────┼─────────

  At no point are READWRITE and READABLE simultaneously accessible
  from the same virtual address → defeats memory dump attacks
</code></pre>
</div>

<div class="section">
<h2 id="key-derivation">Key Derivation Hierarchy</h2>
<pre><code>
  master_key (32 bytes, random)
       │
       ├── SHA-256(master_key + "_crypto")  →  key_crypto
       │   Used for: AES-256-GCM encrypt/decrypt of weight tensors
       │
       └── SHA-256(master_key + "_obfusc")  →  key_obfusc
           Used for: deterministic permutation and scaling via seeded RNG
               │
               ├── SHA-256(key_obfusc + layer_name)       → permutation seed for output channels
               ├── SHA-256(key_obfusc + layer_name+"_in") → permutation seed for input channels
               └── SHA-256(key_obfusc + "mixer_" + name)  → mixer weight seed
</code></pre>
</div>

<div class="section">
<h2 id="build-system">Build System</h2>
<p>The C++ extension uses CMake:</p>
<pre><code><span class="cm"># CMakeLists.txt selects the correct PAL implementation at configure time:</span>
<span class="kw">if</span>(WIN32)
    target_sources(vajraa PRIVATE native/src/pal_windows.cpp)
<span class="kw">elseif</span>(APPLE)
    target_sources(vajraa PRIVATE native/src/pal_macos.cpp)
<span class="kw">else</span>()
    target_sources(vajraa PRIVATE native/src/pal_linux.cpp)
<span class="kw">endif</span>()

<span class="cm"># Always built regardless of platform:</span>
target_sources(vajraa PRIVATE
    native/src/crypto_engine.cpp
    native/src/secure_gemm_op.cpp
)</code></pre>
<p>All PAL implementations expose the <strong>same C ABI</strong> declared in <code>pal.h</code> — so Python code and ONNX operators never call platform-specific functions directly.</p>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 4 — flows.html
# ════════════════════════════════════════════════════
FLOWS = '''
<h1 class="page-title">How It <span class="accent">Works</span></h1>
<p class="page-subtitle">Six complete walkthroughs — every step from model compilation to OS memory management.</p>

<div class="section">
<h2 id="flow1">Flow 1 — Model Compilation (Vendor Side, One-Time)</h2>
<p>This step happens <strong>offline on the vendor's machine</strong>. No customer involvement. The output is a compiled model file and a license file that can be shipped to customers.</p>
<div class="flow">
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">1</div>
    <div class="flow-content">
      <h4>Load model state_dict</h4>
      <p>All weight tensors are read from the PyTorch model's <code>state_dict()</code>. Layer names are preserved (e.g. <code>fc1.weight</code>, <code>fc2.bias</code>).</p>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">2</div>
    <div class="flow-content">
      <h4>Derive sub-keys</h4>
      <p><code>key_crypto = SHA-256(master_key + "_crypto")</code> — used for AES encryption.<br>
      <code>key_obfusc = SHA-256(master_key + "_obfusc")</code> — used for deterministic permutation seeding.</p>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">3</div>
    <div class="flow-content">
      <h4>Boundary layers → AES-256-GCM encrypt</h4>
      <p>The <strong>first and last layer</strong> weights are fully encrypted. These control the input/output representation and are the most sensitive. Encryption uses a random 12-byte IV per tensor.</p>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">4</div>
    <div class="flow-content">
      <h4>Intermediate layers → Permute + Scale + Encrypt</h4>
      <p>For each 2D weight matrix (Linear layers):<br>
      1. Derive deterministic channel permutation <code>P_out</code>, <code>P_in</code> from <code>key_obfusc + layer_name</code>.<br>
      2. Derive scaling vectors <code>S_out</code>, <code>S_in</code> (values in [0.5, 2.0]).<br>
      3. Scramble: <code>W_scrambled = D_out · W[P_out, :][P_in, :] · D_in</code><br>
      4. Then AES-256-GCM encrypt the scrambled tensor.</p>
      <div class="callout callout-tip"><p><strong>💡 Why scramble AND encrypt?</strong> Scrambling is reversible (by the runtime) but makes the raw ciphertext uninformative even if decrypted with a wrong key — it just looks like a permuted version of unrelated weights.</p></div>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">5</div>
    <div class="flow-content">
      <h4>Inject Secret Mixer weights</h4>
      <p>For each obfuscated layer, a tiny <code>mix_size × mix_size</code> weight matrix is generated (seeded from <code>key_obfusc</code>) and AES-encrypted. At inference, <code>GeLU(X · W_mix)</code> is applied as a non-linear transformation after unscrambling — making the transformation harder to approximate without the key.</p>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">6</div>
    <div class="flow-content">
      <h4>Build metadata</h4>
      <p><code>max_layer_size_bytes</code> and per-layer sizes are tracked. This is used later to pre-size the memory pool without needing to inspect encrypted ciphertexts at runtime.</p>
    </div>
  </div>
  <div class="flow-step">
    <div class="flow-dot" style="background:linear-gradient(135deg,#7c3aed,#06b6d4)">7</div>
    <div class="flow-content">
      <h4>Generate license</h4>
      <p>The master_key is wrapped using <strong>RFC 3394 AES Key Wrap</strong> with the customer_key. This wrapped key, plus customer_id and optional expiry timestamp, is then AES-256-GCM encrypted with the customer_key and serialized to JSON → bytes.</p>
    </div>
  </div>
</div>
</div>

<div class="section">
<h2 id="flow2">Flow 2 — PyTorch Secure Inference (Per Forward Pass)</h2>
<pre><code>
model(input)
  │
  ├─ [pre_hook fires for each wrapped layer]
  │    1. pal_is_debugger_attached() → kill if true
  │    2. decrypt_tensor(enc_weight, key_crypto) → weight_np
  │    3. lease_slot() or pal_alloc_secure() → write_ptr
  │    4. pal_unlock(write_ptr) → READWRITE
  │    5. memmove(write_ptr ← weight_np bytes)
  │    6. get_read_view() → copies write→read, locks write (NOACCESS)
  │    7. torch.from_numpy(read_ptr buffer) → mod.weight (parameter)
  │
  ├─ [layer.forward() executes with torch ops reading mod.weight]
  │
  └─ [post_hook fires for each wrapped layer]
       1. mod.weight_transient.zero_()  ← zero pytorch tensor
       2. release_slot(slot)
          └─ pal_unlock(write_ptr)
             pal_secure_zero(write_ptr, size)  ← OS-guaranteed zero
             pal_lock(write_ptr)  ← NOACCESS
             pal_lock(read_ptr)   ← NOACCESS
       3. del mod.weight, del mod.weight_transient
       4. gc.collect()
</code></pre>
<div class="callout callout-warn"><p><strong>⚠️ Why gc.collect()?</strong> Python's garbage collector may not immediately release objects. <code>gc.collect()</code> forces the tensor's backing memory to be released before any potential memory scan can capture it.</p></div>
</div>

<div class="section">
<h2 id="flow3">Flow 3 — ONNX Secure Inference (Per Operator Kernel Call)</h2>
<p>For ONNX models, the C++ custom operator runs inside ONNX Runtime's thread pool. Each call is independent.</p>
<pre><code>
ONNX Runtime calls SecureGemmKernel::Compute(context):
  │
  ├─ if (!key_retrieved_):
  │    pal_retrieve_key(master_key, 32)  ← reconstruct from XOR shares or DPAPI
  │    key_retrieved_ = true
  │
  ├─ Extract inputs from context:
  │    input_data  ← input tensor (e.g. activations)
  │    w_enc_data  ← encrypted weight blob (ciphertext bytes)
  │    iv_data     ← 12-byte IV
  │    tag_data    ← 16-byte GCM authentication tag
  │
  ├─ pal_lease_secure_slot(ciphertext_len, &allocated_size)
  │    → returns write_ptr (READWRITE, random slot from pool)
  │
  ├─ vajraa_decrypt_gcm(w_enc_data, len, master_key, iv, tag, write_ptr)
  │    → decrypts directly into write_ptr
  │
  ├─ pal_secure_zero(master_key, 32)   ← wipe master_key from stack
  │
  ├─ pal_get_read_view(write_ptr, allocated_size)
  │    → write_ptr page set NOACCESS
  │    → read_ptr page set READONLY
  │    → returns read_ptr
  │
  ├─ const float* w_data = reinterpret_cast&lt;const float*&gt;(read_ptr)
  │
  ├─ [OpenMP parallelized matrix multiply using w_data]
  │
  └─ pal_release_secure_slot(write_ptr, allocated_size)
       → read_ptr set NOACCESS
       → write_ptr unlocked, zeroed, re-locked NOACCESS
       → slot.in_use = false
</code></pre>
</div>

<div class="section">
<h2 id="flow4">Flow 4 — License Verification</h2>
<pre><code>
license_bytes (from .lic file)
  │
  ▼
JSON parse → { "iv": "...", "ciphertext": "...", "tag": "..." }
  │
  ▼
AES-256-GCM decrypt with customer_key
  │
  ▼
Inner JSON → { "customer_id": "acme_corp",
               "master_key": "&lt;base64 AES-Key-Wrapped&gt;",
               "expires_at": 1234567890.0 }
  │
  ├─ time.time() > expires_at? → raise SecurityError("License has expired")
  │
  ▼
AES Key Unwrap (RFC 3394) with customer_key
  → raw master_key bytes (32 bytes)
  │
  ▼
Returns { "customer_id": "acme_corp", "master_key": b"..." }
</code></pre>
<div class="callout callout-info"><p><strong>ℹ️ Why AES Key Wrap?</strong> RFC 3394 AES Key Wrap is a NIST-standardized algorithm specifically designed to protect key material. It includes integrity checking — so if anyone tampers with the wrapped key bytes, unwrapping fails.</p></div>
</div>

<div class="section">
<h2 id="flow5">Flow 5 — W^R Double-Mapped Virtual Memory</h2>
<pre><code>
Physical memory (OS kernel manages):
  ┌──────────────────────────────────┐
  │  Page frame #4A2F (4096 bytes)  │
  └──────────────────────────────────┘
            ▲               ▲
            │               │
  Virtual address 0x7F00  Virtual address 0x8B00
  [write_ptr]             [read_ptr]
  Both map to same physical page via:
    Windows → CreateFileMapping + MapViewOfFile (x2)
    Linux   → shm_open + ftruncate + mmap (x2)
    macOS   → shm_open + ftruncate + mmap (x2)

State machine per slot:

  IDLE:       write_ptr=NOACCESS   read_ptr=NOACCESS
  DECRYPTING: write_ptr=READWRITE  read_ptr=NOACCESS   ← pal_lease_secure_slot
  EXECUTING:  write_ptr=NOACCESS   read_ptr=READONLY   ← pal_get_read_view
  IDLE:       write_ptr=NOACCESS   read_ptr=NOACCESS   ← pal_release_secure_slot

At no point are both views simultaneously accessible.
A memory scanner searching for "readable + writable" pages finds nothing.
</code></pre>
</div>

<div class="section">
<h2 id="flow6">Flow 6 — Dynamic Cache Compaction</h2>
<p>This is particularly important for web servers handling bursty inference traffic.</p>
<pre><code>
                        inference  inference                  inference
                           │          │                          │
Time →  ──────────────────┬──────────┬──────────────────────────┬────
                           │          │                          │
Pool:  INIT ──────────────[ACTIVE]──[ACTIVE]──────────────────[RE-INIT]
                                          │
                                          └── idle_timeout fires
                                              compact() runs:
                                              - munmap(write_ptr) per slot
                                              - munmap(read_ptr)  per slot
                                              - close(fd) per slot
                                              - slots.clear()
                                              - is_initialized = False
                                              → OS reclaims all page frames
</code></pre>
<p>On the next inference call, <code>lease_slot()</code> detects <code>is_initialized = False</code>, calls <code>initialize()</code> (allocating new double-mapped slots), and proceeds normally. The re-initialization is transparent to the caller.</p>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 5 — python-api.html
# ════════════════════════════════════════════════════
PYTHON_API = '''
<h1 class="page-title">Python <span class="accent">API Reference</span></h1>
<p class="page-subtitle">Complete documentation for every function, class, and method in the Vajraa Python package.</p>

<div class="section">
<h2 id="crypto">Module: <code>vajraa.crypto</code></h2>
<p>Cryptographic primitives for tensor encryption and license management. All encryption uses AES-256-GCM, an authenticated encryption scheme that provides both confidentiality and integrity.</p>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-class">exception</span>
    <span class="fn-sig">class SecurityError(Exception)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Custom exception raised for all security-related failures including decryption errors, tampered data, and expired licenses. Always catch this specifically rather than a bare <code>Exception</code> so security failures are never silently swallowed.</p>
    <pre><code><span class="kw">from</span> <span class="nm">vajraa.crypto</span> <span class="kw">import</span> SecurityError
<span class="kw">try</span>:
    lic_data = decrypt_license(lic_bytes, customer_key)
<span class="kw">except</span> <span class="tp">SecurityError</span> <span class="kw">as</span> e:
    print(<span class="st">f"License error: {e}"</span>)
    sys.exit(<span class="nu">1</span>)</code></pre>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">encrypt_tensor(tensor_np, key) → dict</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Encrypts a NumPy array using AES-256-GCM. A fresh random 12-byte IV is generated for every call, ensuring ciphertexts are non-deterministic even for identical inputs. The authentication tag guarantees the ciphertext has not been tampered with.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>tensor_np</td><td>np.ndarray</td><td>The weight tensor to encrypt (any dtype, any shape)</td></tr>
        <tr><td>key</td><td>bytes (32)</td><td>AES-256 key — must be exactly 32 bytes</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>dict</code> with keys: <code>iv</code> (base64 str), <code>ciphertext</code> (base64 str), <code>tag</code> (base64 str), <code>shape</code> (list[int]), <code>dtype</code> (str)</p>
    <pre><code>enc = encrypt_tensor(weight_np, key_crypto)
<span class="cm"># enc = {"iv": "...", "ciphertext": "...", "tag": "...", "shape": [256,128], "dtype": "float32"}</span></code></pre>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">decrypt_tensor(enc_dict, key) → np.ndarray</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Decrypts an encrypted tensor dictionary back into a NumPy array. GCM authentication tag is verified before decryption — if the ciphertext or tag have been tampered with, a <code>SecurityError</code> is raised and no partial decryption is exposed.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>enc_dict</td><td>dict</td><td>Output of <code>encrypt_tensor</code></td></tr>
        <tr><td>key</td><td>bytes (32)</td><td>Must match the key used during encryption</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>np.ndarray</code> with original shape and dtype. Raises <code>SecurityError</code> on any failure.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">generate_license(customer_id, master_key, customer_key, expiry_days=None) → bytes</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Creates an encrypted license blob. The master key is protected using RFC 3394 AES Key Wrap — a NIST standard for key material storage. The wrapped key and metadata are then AES-256-GCM encrypted with the customer_key. The result is a self-contained, tamper-evident binary blob.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>customer_id</td><td>str</td><td>Human-readable customer identifier (stored in license JSON)</td></tr>
        <tr><td>master_key</td><td>bytes (32)</td><td>The model's master decryption key</td></tr>
        <tr><td>customer_key</td><td>bytes (32)</td><td>The customer's unique key (share this securely with them)</td></tr>
        <tr><td>expiry_days</td><td>float or None</td><td>Days from now until license expires. None = never expires.</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>bytes</code> — JSON-encoded, GCM-encrypted license blob. Safe to write to disk.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">decrypt_license(license_bytes, customer_key) → dict</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Decrypts and validates a license file. Checks the expiry timestamp against <code>time.time()</code>. Unwraps the master key using RFC 3394 AES Key Unwrap. Raises <code>SecurityError</code> for any failure — tampered data, wrong key, or expired license.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>license_bytes</td><td>bytes</td><td>Contents of the .lic file</td></tr>
        <tr><td>customer_key</td><td>bytes (32)</td><td>The customer's unique key</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>dict</code> with <code>customer_id</code> (str) and <code>master_key</code> (bytes). Raises <code>SecurityError</code> on failure.</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="compiler">Module: <code>vajraa.compiler</code></h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">derive_permutation_and_scales(seed_key, size) → tuple[ndarray, ndarray]</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Generates a deterministic channel permutation vector and a scaling factor vector from a SHA-256-seeded NumPy random generator. Given the same <code>seed_key</code> and <code>size</code>, the output is always identical — this is how the runtime can reverse the scrambling without storing the permutation.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>seed_key</td><td>bytes</td><td>Key-derived seed (e.g. key_obfusc + layer_name.encode())</td></tr>
        <tr><td>size</td><td>int</td><td>Number of channels (out_features or in_features)</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>(perm: np.ndarray[int64], scales: np.ndarray[float32])</code>. Permutation is a shuffle of <code>[0, size)</code>. Scales are uniform in <code>[0.5, 2.0]</code>.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">compile_model_weights(state_dict, master_key) → dict</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">The central compilation function. Takes a PyTorch <code>state_dict</code> and returns a compiled representation where every weight is either encrypted or obfuscated. This function is called <strong>once by the vendor</strong> and its output is what gets distributed to customers.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>state_dict</td><td>OrderedDict</td><td>From <code>model.state_dict()</code></td></tr>
        <tr><td>master_key</td><td>bytes (32)</td><td>Random master key, keep this secret</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>dict</code> with keys:</p>
    <ul>
      <li><code>encrypted_layers</code> — dict of <code>{layer_name: enc_dict}</code> for boundary layers and biases</li>
      <li><code>obfuscated_layers</code> — dict of <code>{layer_name: enc_dict}</code> for intermediate 2D weights (scrambled before encryption)</li>
      <li><code>mixers</code> — dict of <code>{mixer_name: enc_dict}</code> for secret mixer weight matrices</li>
      <li><code>metadata</code> — dict with <code>max_layer_size_bytes</code> and <code>layer_sizes_dict</code></li>
    </ul>
  </div>
</div>
</div>

<div class="section">
<h2 id="pytorch-wrapper">Module: <code>vajraa.pytorch_wrapper</code></h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-class">class</span>
    <span class="fn-sig">VajraaConfig</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Configuration dataclass for the PyTorch secure inference engine. Each option controls a different aspect of the memory security vs performance tradeoff.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>use_shuffling</td><td>bool</td><td>False</td><td>Randomly select which pool slot to use — prevents timing-based side-channel analysis that could deduce slot addresses</td></tr>
        <tr><td>use_tiered_pools</td><td>bool</td><td>False</td><td>Segregate slots by size (Tier1: 4MB, Tier2: 32MB, Tier3: max_layer) to reduce internal fragmentation</td></tr>
        <tr><td>capped_pool_size_bytes</td><td>int</td><td>100MB</td><td>If max layer size exceeds this, hybrid mode falls back to JIT allocation</td></tr>
        <tr><td>use_hybrid_mode</td><td>bool</td><td>False</td><td>Auto-detect at runtime whether pooling is feasible given available RAM. Prevents OOM on low-memory servers.</td></tr>
        <tr><td>lazy_init</td><td>bool</td><td>False</td><td>Delay pool page allocation until the first inference call rather than at wrap time</td></tr>
        <tr><td>idle_timeout</td><td>float</td><td>5.0</td><td>Seconds of no inference before dynamic compaction fires and releases all pool pages back to OS</td></tr>
        <tr><td>use_double_mapping</td><td>bool</td><td>True</td><td>Enable W^R virtual page isolation — each slot gets two virtual addresses pointing to the same physical page</td></tr>
      </tbody>
    </table>
    <pre><code>config = <span class="nm">VajraaConfig</span>(
    use_shuffling=<span class="kw">True</span>,
    use_tiered_pools=<span class="kw">True</span>,
    use_hybrid_mode=<span class="kw">True</span>,
    idle_timeout=<span class="nu">10.0</span>,        <span class="cm"># release after 10s idle</span>
    use_double_mapping=<span class="kw">True</span>,  <span class="cm"># W^R isolation</span>
)</code></pre>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-class">class</span>
    <span class="fn-sig">VajraaMemorySlot</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Represents one pre-allocated secure memory slot in the pool. When <code>use_double_mapping=True</code>, each slot allocates TWO virtual address ranges (<code>write_ptr</code> and <code>read_ptr</code>) that map to the same physical pages. This means the write address and read address are completely different virtual locations — defeating memory dump tools that rely on scanning contiguous writable memory.</p>
    <h4>Key attributes:</h4>
    <ul>
      <li><code>write_ptr: int</code> — Virtual address for decryption. Held at NOACCESS except during the decryption window.</li>
      <li><code>read_ptr: int</code> — Virtual address for torch execution. Held at NOACCESS except during the execution window.</li>
      <li><code>size: int</code> — Slot capacity in bytes.</li>
      <li><code>in_use: bool</code> — Whether this slot is currently leased.</li>
    </ul>
    <h4>Key methods:</h4>
    <table class="params-table">
      <thead><tr><th>Method</th><th>What it does</th></tr></thead>
      <tbody>
        <tr><td><code>get_write_ptr()</code></td><td>Unlocks write view to READWRITE, returns write_ptr</td></tr>
        <tr><td><code>get_read_view()</code></td><td>Copies write→read buffer, locks write to NOACCESS, unlocks read to READONLY, returns read_ptr</td></tr>
        <tr><td><code>zero_wipe()</code></td><td>Unlocks both views, secure-zeroes both, re-locks both to NOACCESS</td></tr>
        <tr><td><code>free()</code></td><td>Calls pal_free_secure on both ptrs</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-class">class</span>
    <span class="fn-sig">VajraaMemoryPool</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Thread-safe pool manager. Maintains a list of pre-allocated <code>VajraaMemorySlot</code> objects, protected by a <code>threading.Lock</code>. Handles slot leasing, release, and idle-triggered compaction via a background daemon timer.</p>
    <h4>Methods:</h4>
    <table class="params-table">
      <thead><tr><th>Method</th><th>What it does</th></tr></thead>
      <tbody>
        <tr><td><code>initialize()</code></td><td>Allocates all slots (calls pal_alloc_secure twice per slot for double-mapping). Thread-safe via lock.</td></tr>
        <tr><td><code>lease_slot(required_size)</code></td><td>Finds a free slot ≥ required_size. Randomly picks from candidates if use_shuffling=True. Returns VajraaMemorySlot or None if pool exhausted (caller falls back to dynamic alloc).</td></tr>
        <tr><td><code>release_slot(slot)</code></td><td>Calls slot.zero_wipe(), marks in_use=False, schedules compaction timer.</td></tr>
        <tr><td><code>schedule_compaction()</code></td><td>Cancels any existing timer, starts a new threading.Timer(idle_timeout, self.compact).</td></tr>
        <tr><td><code>compact()</code></td><td>If all slots are free, calls slot.free() on each, clears list, sets is_initialized=False. Logs compaction.</td></tr>
        <tr><td><code>shutdown()</code></td><td>Cancels timer, frees all slots. Call this when tearing down the model.</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">secure_wrap_model(model, compiled_model, master_key, config=None) → list</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">The main deployment API for PyTorch models. Attaches forward pre-hooks and post-hooks to every layer that has encrypted or obfuscated weights. After this call, the model runs securely — weights are decrypted JIT and wiped after each layer execution.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>model</td><td>nn.Module</td><td>The PyTorch model (weights should already be removed/zeroed)</td></tr>
        <tr><td>compiled_model</td><td>dict</td><td>Output of compile_model_weights</td></tr>
        <tr><td>master_key</td><td>bytes</td><td>The model's master decryption key (from license)</td></tr>
        <tr><td>config</td><td>VajraaConfig or None</td><td>Security profile. Defaults to VajraaConfig() (no pooling).</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>list</code> of <code>(module_name, strategy)</code> tuples indicating which layers were wrapped and whether they use "crypto" or "obfuscated" strategy.</p>
    <p><strong>Side effects:</strong> Sets <code>model._vajraa_pool</code> if a pool was created.</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="onnx-compiler">Module: <code>vajraa.onnx_compiler</code></h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-func">function</span>
    <span class="fn-sig">rewrite_onnx_graph(input_path, output_path, master_key)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Transforms a plain ONNX model file into a Vajraa-secured <code>.ems</code> file. Every Gemm, Conv, and ConvTranspose node is rewritten: the weight initializers are extracted, AES-256-GCM encrypted, injected as ONNX Constant nodes, and the original ops are replaced with custom Vajraa operators.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>input_path</td><td>str</td><td>Path to the plain .onnx model file</td></tr>
        <tr><td>output_path</td><td>str</td><td>Path to write the secured .ems file</td></tr>
        <tr><td>master_key</td><td>bytes (32)</td><td>The model's master key</td></tr>
      </tbody>
    </table>
    <p><strong>Custom operator mapping:</strong></p>
    <ul>
      <li><code>Gemm</code> → <code>Vajraa.SecureGemm</code></li>
      <li><code>Conv</code> → <code>Vajraa.SecureConv</code></li>
      <li><code>ConvTranspose</code> → <code>Vajraa.SecureConvTranspose</code></li>
    </ul>
    <p>Each custom op receives additional inputs: encrypted weight blob, IV bytes, and GCM tag bytes.</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="onnx-wrapper">Module: <code>vajraa.onnx_wrapper</code></h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-class">class</span>
    <span class="fn-sig">SecureONNXSession</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Wraps ONNX Runtime's <code>InferenceSession</code> with Vajraa security. On construction, it decrypts the license, stores the key in the C++ memory vault, configures the C++ page pool, registers the custom operators library, and creates the ONNX Runtime session.</p>

    <h4>__init__(model_path, license_path, customer_key, config=None)</h4>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>model_path</td><td>str</td><td>Path to the .ems secured ONNX file</td></tr>
        <tr><td>license_path</td><td>str</td><td>Path to the .lic license file</td></tr>
        <tr><td>customer_key</td><td>bytes (32)</td><td>The customer's key for license decryption</td></tr>
        <tr><td>config</td><td>VajraaConfig or None</td><td>Security and memory profile</td></tr>
      </tbody>
    </table>

    <h4>run(output_names, input_feed) → list</h4>
    <p>Runs inference. Before calling ONNX Runtime, cancels any pending compaction timer (prevents pages from being freed mid-inference). After completion, schedules a new compaction timer.</p>
    <table class="params-table">
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>output_names</td><td>list[str]</td><td>Names of output tensors to return (e.g. ["output"])</td></tr>
        <tr><td>input_feed</td><td>dict[str, np.ndarray]</td><td>Input tensors as numpy arrays (e.g. {"input": x_np})</td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> <code>list[np.ndarray]</code> — inference outputs.</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="pal-python">Module: <code>vajraa.pal</code></h2>
<p>Python ctypes bridge to the native C++ shared library. Automatically loads the correct DLL/so/dylib based on platform. Also contains pure-Python fallbacks for environments without the native library.</p>
<table class="params-table">
  <thead><tr><th>Function</th><th>Returns</th><th>Description</th></tr></thead>
  <tbody>
    <tr><td><code>pal_alloc_secure(size)</code></td><td>int (ptr)</td><td>Allocate NOACCESS pages. Returns 0 on failure.</td></tr>
    <tr><td><code>pal_unlock(ptr, size)</code></td><td>bool</td><td>Set pages to READWRITE</td></tr>
    <tr><td><code>pal_lock(ptr, size)</code></td><td>bool</td><td>Set pages to NOACCESS</td></tr>
    <tr><td><code>pal_secure_zero(ptr, size)</code></td><td>None</td><td>Zero memory (native or ctypes.memset fallback)</td></tr>
    <tr><td><code>pal_free_secure(ptr, size)</code></td><td>None</td><td>Release pages (VirtualFree / munmap)</td></tr>
    <tr><td><code>pal_is_debugger_attached()</code></td><td>bool</td><td>True if debugger detected</td></tr>
    <tr><td><code>pal_kill_if_debugged()</code></td><td>None</td><td>Terminate process immediately</td></tr>
    <tr><td><code>pal_store_key(key)</code></td><td>bool</td><td>Store key using DPAPI (Windows) or XOR-shares</td></tr>
    <tr><td><code>pal_retrieve_key()</code></td><td>bytearray</td><td>Reconstruct stored key</td></tr>
    <tr><td><code>pal_get_available_memory()</code></td><td>int (bytes)</td><td>Available physical RAM</td></tr>
    <tr><td><code>pal_compact_pool()</code></td><td>bool</td><td>Free all idle C++ pool slots</td></tr>
    <tr><td><code>pal_get_read_view(write_ptr, size)</code></td><td>int (ptr)</td><td>Transition to read-only view, return read_ptr</td></tr>
  </tbody>
</table>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 6 — cpp-api.html
# ════════════════════════════════════════════════════
CPP_API = '''
<h1 class="page-title">C++ <span class="accent">API Reference</span></h1>
<p class="page-subtitle">The Platform Abstraction Layer (PAL) and custom ONNX Runtime operators — every function documented.</p>

<div class="callout callout-info"><p><strong>ℹ️ Note for freshers:</strong> You rarely need to call PAL functions directly from Python — that's handled by <code>pal.py</code>. This reference is for understanding what happens under the hood, or for contributing new platform implementations.</p></div>

<div class="section">
<h2 id="memory">Memory Allocation &amp; Protection</h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">void* pal_alloc_secure(size_t size)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Allocates page-aligned, inaccessible memory. On all platforms, the returned pages are immediately set to <code>PAGE_NOACCESS</code> / <code>PROT_NONE</code> — meaning any access (read or write) before calling <code>pal_unlock</code> causes a segmentation fault / access violation.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Implementation</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_NOACCESS)</code></td></tr>
        <tr><td>Linux/macOS</td><td><code>mmap(NULL, size, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)</code></td></tr>
      </tbody>
    </table>
    <p><strong>Returns:</strong> Pointer to allocated memory, or <code>NULL</code> on failure.</p>
    <div class="callout callout-warn"><p><strong>⚠️ Always check for NULL!</strong> Secure allocations can fail under memory pressure. The callers always check <code>if (ptr == NULL)</code> before proceeding.</p></div>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_unlock(void* ptr, size_t size)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Transitions pages from <code>NOACCESS</code> to <code>READWRITE</code>. Must be called before writing decrypted data into the buffer. Always followed by <code>pal_lock</code> as soon as writing is complete.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Implementation</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>VirtualProtect(ptr, size, PAGE_READWRITE, &amp;old_protect)</code></td></tr>
        <tr><td>Linux/macOS</td><td><code>mprotect(ptr, size, PROT_READ | PROT_WRITE)</code></td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">void pal_secure_zero(void* ptr, size_t size)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Securely zeroes memory in a way that is <strong>guaranteed not to be optimized away by the compiler</strong>. Regular <code>memset</code> can be removed by an optimizing compiler if it determines the memory is never read afterwards — a dangerous silent omission in security code.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Implementation</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>RtlSecureZeroMemory(ptr, size)</code> — OS function guaranteed to execute</td></tr>
        <tr><td>Linux</td><td><code>explicit_bzero(ptr, size)</code> — POSIX extension that cannot be optimized out</td></tr>
        <tr><td>macOS</td><td>Volatile pointer loop: <code>volatile char* p = ptr; while(size--) *p++ = 0;</code></td></tr>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="section">
<h2 id="anti-debug">Anti-Debugging &amp; Tamper Detection</h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_is_debugger_attached(void)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Queries the OS to determine if a debugger is present. Called at the start of every pre-hook to prevent live inspection of decrypted weights.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Check</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>IsDebuggerPresent()</code> + <code>CheckRemoteDebuggerPresent()</code> + DR0-DR3 hardware breakpoint check via NtQueryInformationThread</td></tr>
        <tr><td>Linux</td><td>Parse <code>/proc/self/status</code> for <code>TracerPid:</code> (non-zero = debugger attached)</td></tr>
        <tr><td>macOS</td><td><code>ptrace(PT_DENY_ATTACH, 0, 0, 0)</code> — prevents future attachment; sysctl check for P_TRACED</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_timing_check(uint64_t* start_time)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Detects step-through debugging by measuring execution time using CPU timestamp counters (RDTSC on x86). If a debugger is single-stepping instructions, the elapsed time between two calls exceeds a threshold that would be impossible without a debugger pausing execution.</p>
    <p>Call pattern: <code>pal_timing_check(&amp;start)</code> before a critical block, then <code>pal_timing_check(&amp;start)</code> again after — if it returns <code>true</code>, terminate.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">void pal_kill_if_debugged(void)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Immediately terminates the process. Does not print errors, does not call Python exit handlers — it uses the lowest-level OS kill available to prevent any teardown code from leaking state.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Implementation</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>ExitProcess(0xC0000005)</code> — STATUS_ACCESS_VIOLATION exit code</td></tr>
        <tr><td>Linux/macOS</td><td><code>_exit(1)</code> — bypasses atexit handlers</td></tr>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="section">
<h2 id="key-storage">Key Storage</h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_store_key(const uint8_t* key, size_t len)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Stores a key securely in process memory using OS-level protection mechanisms. The key is never stored in plain form in a C-level global variable.</p>
    <table class="params-table">
      <thead><tr><th>Platform</th><th>Implementation</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td><code>CryptProtectMemory</code> (DPAPI) — encrypts key in-place using a per-process OS-managed key. Only the same process context can decrypt it.</td></tr>
        <tr><td>Linux/macOS</td><td>XOR split: generate random 32-byte <code>share1</code> from <code>/dev/urandom</code>. Compute <code>share2 = key XOR share1</code>. Store both shares separately. Neither alone reveals the key.</td></tr>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="section">
<h2 id="pool-api">Memory Pool API</h2>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_configure_pool(bool use_shuffling, bool use_tiered, size_t capped_size, bool use_hybrid, size_t max_layer_size, size_t avail_ram)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Initializes the C++ double-mapped page pool. Called once by <code>SecureONNXSession.__init__</code>. Applies hybrid logic: if <code>max_layer_size &gt; capped_size</code> or estimated pool memory exceeds 20% of available RAM, pooling is disabled and the library falls back to per-call JIT allocation.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">void* pal_lease_secure_slot(size_t required_size, size_t* allocated_size)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Returns the write_ptr of a free pool slot large enough for <code>required_size</code> bytes. If <code>use_shuffling</code> is true, picks randomly from all qualifying slots — preventing attackers from predicting slot addresses across calls. If no slot is available, falls back to <code>pal_alloc_secure</code> (dynamic JIT allocation).</p>
    <p><strong>Returns:</strong> Pointer to an READWRITE page (write view). <code>*allocated_size</code> is set to the actual slot size (may be larger than required_size).</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">void* pal_get_read_view(void* write_ptr, size_t allocated_size)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Performs the W→R page view transition. Finds the pool slot with matching <code>write_ptr</code>, sets the write view to <code>PROT_NONE</code>, sets the read view to <code>PROT_READ</code>, and returns the read view pointer. For dynamic (non-pooled) allocations, returns <code>write_ptr</code> unchanged (no double-mapping in JIT mode).</p>
    <div class="callout callout-tip"><p><strong>💡 This is where W^R enforcement happens.</strong> After this call, attempting to write to write_ptr will cause an immediate segfault — so any rogue code trying to modify the weight post-decryption is caught by the OS.</p></div>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C API</span>
    <span class="fn-sig">bool pal_compact_pool(void)</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Frees all currently un-leased slots, releases their OS memory (munmap / CloseHandle), removes them from the pool vector. If all slots are freed, <code>g_pool_initialized</code> is set to false. The next call to <code>pal_lease_secure_slot</code> will trigger re-initialization.</p>
    <p>On Linux/macOS, this calls <code>munmap(write_ptr, size)</code> and <code>munmap(read_ptr, size)</code>, then <code>close(fd)</code> for each slot — fully returning the physical page frames to the OS.</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="custom-ops">ONNX Custom Operators (<code>secure_gemm_op.cpp</code>)</h2>
<p>These operators are registered into ONNX Runtime's custom operator domain <code>"Vajraa"</code> via the <code>RegisterCustomOps</code> function which ONNX Runtime calls when the library is loaded.</p>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C++ class</span>
    <span class="fn-sig">struct SecureGemmKernel</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Implements <code>Vajraa.SecureGemm</code> — a matrix multiply operator that decrypts its weight matrix on every call, executes, and wipes. Replaces standard ONNX <code>Gemm</code> nodes.</p>
    <h4>Compute(context) — full execution flow:</h4>
    <ol style="color:var(--text-muted); padding-left: 22px;">
      <li>If <code>!key_retrieved_</code>: call <code>pal_retrieve_key(master_key, 32)</code>, set flag to avoid re-retrieval on every call</li>
      <li>Get input tensor (activations) from <code>context</code> input 0</li>
      <li>Get encrypted weight bytes from input 1, IV from input 2, GCM tag from input 3</li>
      <li>Call <code>pal_lease_secure_slot(ciphertext_len, &amp;allocated_size)</code> → <code>decrypted_weights_ptr</code></li>
      <li>Call <code>vajraa_decrypt_gcm(..., decrypted_weights_ptr)</code> to decrypt directly into the write-view page</li>
      <li>Call <code>pal_secure_zero(master_key, 32)</code> to wipe master key from stack</li>
      <li>On decryption failure: release slot, return early (no partial result)</li>
      <li>Call <code>pal_get_read_view(decrypted_weights_ptr, allocated_size)</code> → <code>read_weights_ptr</code></li>
      <li>Cast: <code>const float* w_data = reinterpret_cast&lt;const float*&gt;(read_weights_ptr)</code></li>
      <li>Get output tensor from context, execute OpenMP-parallelized matrix multiply</li>
      <li>Call <code>pal_release_secure_slot(decrypted_weights_ptr, allocated_size)</code></li>
    </ol>
    <pre><code><span class="cm">// Simplified pseudocode:</span>
<span class="kw">void</span> <span class="fn">Compute</span>(OrtKernelContext* context) {
    <span class="kw">if</span> (!key_retrieved_) {
        pal_retrieve_key(master_key, <span class="nu">32</span>);
        key_retrieved_ = <span class="kw">true</span>;
    }
    <span class="kw">void</span>* write_ptr = pal_lease_secure_slot(ciphertext_len, &allocated_size);
    vajraa_decrypt_gcm(ciphertext, len, master_key, iv, tag, write_ptr);
    pal_secure_zero(master_key, <span class="nu">32</span>);
    <span class="kw">void</span>* read_ptr = pal_get_read_view(write_ptr, allocated_size);
    <span class="kw">const float</span>* w = <span class="kw">reinterpret_cast</span>&lt;<span class="kw">const float</span>*&gt;(read_ptr);
    <span class="cm">// ... matrix multiply ...</span>
    pal_release_secure_slot(write_ptr, allocated_size);
}</code></pre>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C++ class</span>
    <span class="fn-sig">struct SecureConvKernel</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Same decryption flow as SecureGemmKernel, but executes a 2D convolution instead of a matrix multiply. Strides, padding, and dilation attributes are cached in the kernel constructor to avoid re-reading per call.</p>
  </div>
</div>

<div class="fn-card">
  <div class="fn-card-header">
    <span class="fn-badge badge-cpp">C++ class</span>
    <span class="fn-sig">struct SecureConvTransposeKernel</span>
  </div>
  <div class="fn-card-body">
    <p class="fn-desc">Same decryption flow, but executes a transposed convolution (deconvolution). Used for decoder/generator architectures (e.g. autoencoders, super-resolution models, GANs).</p>
  </div>
</div>
</div>

<div class="section">
<h2 id="adding-platform">How to Add a New Platform</h2>
<p>To add Vajraa support for a new OS (e.g. QNX, FreeBSD):</p>
<ol style="color:var(--text-muted)">
  <li>Create <code>native/src/pal_yourplatform.cpp</code></li>
  <li>Implement ALL functions declared in <code>native/include/pal.h</code></li>
  <li>Add your file to <code>CMakeLists.txt</code> under the correct platform detection block</li>
  <li>Add platform detection in <code>python/vajraa/pal.py</code> (the <code>IS_*</code> variables)</li>
  <li>Run the full test suite: <code>python -m unittest discover -s tests</code></li>
</ol>
<p>All PAL functions must maintain the same memory state machine: NOACCESS → READWRITE (write) → NOACCESS | READONLY (read) → NOACCESS (released).</p>
</div>
'''

# ════════════════════════════════════════════════════
#  PAGE 7 — memory-security.html
# ════════════════════════════════════════════════════
MEMORY_SECURITY = '''
<h1 class="page-title">Memory <span class="accent">Security</span> Deep Dive</h1>
<p class="page-subtitle">How Vajraa uses OS virtual memory features to make encrypted model weights invisible to memory scanners, debuggers, and dump tools.</p>

<div class="section">
<h2 id="the-problem">The Core Problem: RAM is Readable</h2>
<p>Every software DRM system has the same fatal weakness: to run a model, the weights <em>must</em> be loaded into RAM. And RAM can be read by:</p>
<ul>
  <li><strong>Debuggers</strong> (x64dbg, IDA Pro, lldb, gdb) — can dump memory at any address</li>
  <li><strong>Memory scanners</strong> (Cheat Engine, process monitors) — scan for floating-point patterns</li>
  <li><strong>OS-level tools</strong> (<code>/proc/pid/mem</code> on Linux, <code>ReadProcessMemory</code> on Windows)</li>
  <li><strong>Cold boot attacks</strong> — physically reading DRAM chips after power-off</li>
</ul>
<p>Traditional DRM solutions encrypt weights on disk, but decrypt them entirely into a normal heap allocation before use. Once there, a memory dump captures everything.</p>
<p>Vajraa's solution: <strong>make the decrypted weights exist only inside OS pages that are locked to NOACCESS, and expose them only through a separate read-only view for the exact duration of the computation.</strong></p>
</div>

<div class="section">
<h2 id="page-protection">Virtual Memory Page Protection</h2>
<p>Modern CPUs have a Memory Management Unit (MMU) that enforces access permissions on a per-page basis (typically 4KB pages). The OS sets these permissions in page table entries.</p>
<table class="params-table">
  <thead><tr><th>Protection Flag</th><th>Windows</th><th>Linux/macOS</th><th>Meaning</th></tr></thead>
  <tbody>
    <tr><td>No Access</td><td>PAGE_NOACCESS</td><td>PROT_NONE</td><td>Any access (read or write) triggers SIGSEGV / Access Violation</td></tr>
    <tr><td>Read Only</td><td>PAGE_READONLY</td><td>PROT_READ</td><td>Reads OK, writes cause fault</td></tr>
    <tr><td>Read+Write</td><td>PAGE_READWRITE</td><td>PROT_READ|PROT_WRITE</td><td>Normal accessible memory</td></tr>
  </tbody>
</table>
<p>All Vajraa pool slots are allocated with <strong>NOACCESS</strong> by default. This means the pages exist but any attempt to touch them immediately crashes the process — including memory scanner tools that try to enumerate all readable memory regions.</p>
</div>

<div class="section">
<h2 id="double-mapping">W^R Double-Mapped Virtual Views</h2>
<p>The crown jewel of Vajraa's memory protection. Two different virtual addresses point to the <strong>same physical memory page</strong>, but each has different permissions at different times — and they are <em>never simultaneously accessible</em>.</p>

<pre><code>
              PHYSICAL MEMORY (OS kernel manages)
              ┌───────────────────────────────────┐
              │  Page frame(s) — 4KB+ of data     │
              └───────────────────────────────────┘
                     ▲                    ▲
                     │                    │
              [write_ptr]           [read_ptr]
              0x7F1234000           0x7F5678000
          Different virtual           Different virtual
           address, same               address, same
          physical pages              physical pages

How it's created:
  Windows:  CreateFileMapping(INVALID_HANDLE_VALUE, ...)
            write_ptr = MapViewOfFile(hmap, FILE_MAP_WRITE, ...)
            read_ptr  = MapViewOfFile(hmap, FILE_MAP_READ, ...)

  Linux:    shm_fd = shm_open("/vajra_shm_PID_N", O_RDWR|O_CREAT|O_EXCL, ...)
            shm_unlink(name)  ← immediately unlink so no process can open it
            ftruncate(shm_fd, size)
            write_ptr = mmap(NULL, size, PROT_NONE, MAP_SHARED, shm_fd, 0)
            read_ptr  = mmap(NULL, size, PROT_NONE, MAP_SHARED, shm_fd, 0)

  macOS:    Same as Linux — shm_open + double mmap
</code></pre>

<h3 id="state-machine">The Permission State Machine</h3>
<pre><code>
                ┌─────────────────────────────────────────────────────┐
                │  IDLE STATE (between inference calls)               │
                │  write_ptr: NOACCESS   read_ptr: NOACCESS           │
                │  Any access = instant crash                          │
                └─────────────────┬───────────────────────────────────┘
                                  │ pal_lease_secure_slot()
                                  ▼
                ┌─────────────────────────────────────────────────────┐
                │  DECRYPT STATE                                       │
                │  write_ptr: READWRITE  read_ptr: NOACCESS           │
                │  Decrypted bytes written into write_ptr buffer       │
                │  read_ptr still inaccessible — cannot be read yet   │
                └─────────────────┬───────────────────────────────────┘
                                  │ pal_get_read_view()
                                  ▼
                ┌─────────────────────────────────────────────────────┐
                │  EXECUTE STATE                                       │
                │  write_ptr: NOACCESS   read_ptr: READONLY           │
                │  write_ptr is now inaccessible (write protection)   │
                │  read_ptr is read-only — torch reads weights here   │
                │  Any attempt to write to write_ptr = crash          │
                └─────────────────┬───────────────────────────────────┘
                                  │ pal_release_secure_slot()
                                  ▼
                ┌─────────────────────────────────────────────────────┐
                │  WIPE STATE                                          │
                │  write_ptr briefly unlocked to READWRITE            │
                │  pal_secure_zero(write_ptr) — guaranteed zero       │
                │  write_ptr: NOACCESS   read_ptr: NOACCESS           │
                └─────────────────────────────────────────────────────┘
                              Back to IDLE STATE
</code></pre>

<h3 id="why-effective">Why This Defeats Memory Dumping</h3>
<ul>
  <li><strong>Memory scanners</strong> enumerate pages with <code>VirtualQuery</code> / <code>/proc/maps</code> looking for <code>READWRITE</code> regions. Vajraa's pages appear as <code>NOACCESS</code> at rest — invisible to scanners.</li>
  <li><strong>Hardware breakpoints on reads</strong> (DR0-DR3 on x86) only fire when the monitored address is accessed. With two separate virtual addresses, a breakpoint on <code>write_ptr</code> won't fire during execution (execution uses <code>read_ptr</code>), and a breakpoint on <code>read_ptr</code> won't fire during decryption (decryption uses <code>write_ptr</code>).</li>
  <li><strong>Kernel memory dumps</strong> (e.g. crash dumps) capture page contents, but NOACCESS pages have undefined/zeroed contents in dumps on most OS implementations.</li>
</ul>
</div>

<div class="section">
<h2 id="tiered-pools">Tiered Memory Pools</h2>
<p>Pre-allocating a pool of slots avoids the overhead of calling <code>VirtualAlloc</code>/<code>mmap</code> on every inference. Tiered pools group slots by size to minimize wasted space (internal fragmentation):</p>

<table class="params-table">
  <thead><tr><th>Tier</th><th>Slot Size</th><th>Count</th><th>Best for</th></tr></thead>
  <tbody>
    <tr><td>Tier 1 — Small</td><td>4 MB</td><td>3 slots</td><td>Small layers (biases, BatchNorm, attention projections)</td></tr>
    <tr><td>Tier 2 — Medium</td><td>32 MB</td><td>2 slots</td><td>Medium layers (hidden dimensions 256–4096)</td></tr>
    <tr><td>Tier 3 — Large</td><td>max_layer_size</td><td>2 slots</td><td>Largest weight tensors (e.g. embedding tables, dense layers)</td></tr>
  </tbody>
</table>

<p>With <code>use_shuffling=True</code>, the slot selected from each tier is random — so even if an attacker learns the virtual addresses of all slots from a previous run, the next run will use different addresses for different layers.</p>
</div>

<div class="section">
<h2 id="hybrid-mode">Hybrid Mode — Dynamic Fallback</h2>
<p>On memory-constrained servers (e.g. 8GB RAM shared across multiple model instances), pre-allocating a large pool may not be feasible. Hybrid mode detects this at runtime:</p>
<pre><code><span class="cm"># At wrap time (secure_wrap_model):</span>
avail_ram = pal_get_available_memory()
pool_cost = max_layer_size * <span class="nu">4</span>   <span class="cm"># uniform pool estimate</span>
<span class="kw">if</span> use_tiered_pools:
    pool_cost = (<span class="nu">3</span> * <span class="nu">4</span>MB) + (<span class="nu">2</span> * <span class="nu">32</span>MB) + (<span class="nu">2</span> * max_layer_size)

<span class="kw">if</span> max_layer_size > capped_pool_size <span class="kw">or</span> pool_cost > avail_ram * <span class="nu">0.20</span>:
    <span class="cm"># Pool would consume >20% of available RAM — fall back to JIT</span>
    use_shuffling_pool = <span class="kw">False</span>
    print(<span class="st">"[Vajraa] Hybrid Fallback: Using standard JIT allocation"</span>)</code></pre>
<p>In JIT mode, each inference call calls <code>pal_alloc_secure</code> and <code>pal_free_secure</code> directly. Slightly more overhead per call, but no upfront memory commitment.</p>
</div>

<div class="section">
<h2 id="compaction">Dynamic Cache Compaction</h2>
<p>Web servers handle bursty traffic — lots of requests for a few seconds, then nothing for minutes. Without compaction, the pre-allocated pool pages sit idle in RAM, wasting valuable memory that other processes could use.</p>

<p>Vajraa addresses this with an <strong>idle-triggered daemon timer</strong>:</p>
<ol style="color:var(--text-muted)">
  <li>After every <code>release_slot()</code> call, the pool schedules a <code>threading.Timer(idle_timeout, compact)</code></li>
  <li>If a new inference starts before the timer fires, the timer is cancelled</li>
  <li>If no inference occurs for <code>idle_timeout</code> seconds, <code>compact()</code> fires:
    <ul>
      <li>For each un-leased slot: call <code>slot.free()</code> → <code>munmap(write_ptr) + munmap(read_ptr) + close(fd)</code></li>
      <li>Clear the slots list</li>
      <li>Set <code>is_initialized = False</code></li>
      <li>Print <code>"[Vajraa] Dynamic Cache Compaction: Released idle memory pool slots."</code></li>
    </ul>
  </li>
  <li>Next inference: <code>lease_slot()</code> detects <code>is_initialized = False</code>, calls <code>initialize()</code>, proceeds normally</li>
</ol>

<pre><code>config = <span class="nm">VajraaConfig</span>(
    use_shuffling=<span class="kw">True</span>,
    idle_timeout=<span class="nu">10.0</span>,   <span class="cm"># Release pages after 10 seconds of no inference</span>
)

<span class="cm"># For ONNX sessions, compaction happens in C++ via pal_compact_pool():</span>
session = <span class="nm">SecureONNXSession</span>(model_path, license_path, customer_key, config=config)
<span class="cm"># After idle_timeout seconds of no session.run() calls:</span>
<span class="cm"># → dll.pal_compact_pool() is called</span>
<span class="cm"># → All C++ pool pages released to OS</span></code></pre>
</div>

<div class="section">
<h2 id="concurrent-models">Concurrent Models &amp; Web Servers</h2>
<p>A common production pattern is running a web server that serves multiple users, potentially with multiple different models:</p>
<pre><code><span class="cm"># FastAPI example — each model has its own wrapped instance</span>
<span class="kw">from</span> <span class="nm">fastapi</span> <span class="kw">import</span> FastAPI
<span class="kw">import</span> <span class="nm">torch</span>

app = <span class="nm">FastAPI</span>()
models = {}

<span class="kw">def</span> <span class="fn">load_model</span>(model_id: str):
    model = <span class="nm">MyModel</span>()
    compiled = pickle.load(<span class="fn">open</span>(<span class="st">f"models/{model_id}.pkl"</span>, <span class="st">"rb"</span>))
    config = <span class="nm">VajraaConfig</span>(
        use_shuffling=<span class="kw">True</span>, 
        use_tiered_pools=<span class="kw">True</span>,
        use_hybrid_mode=<span class="kw">True</span>,
        idle_timeout=<span class="nu">30.0</span>   <span class="cm"># free pages after 30s idle</span>
    )
    secure_wrap_model(model, compiled, master_key, config=config)
    models[model_id] = model

@app.post(<span class="st">"/infer/{model_id}"</span>)
<span class="kw">async def</span> <span class="fn">infer</span>(model_id: str, data: dict):
    <span class="kw">if</span> model_id <span class="kw">not in</span> models:
        load_model(model_id)
    <span class="kw">return</span> models[model_id](torch.tensor(data[<span class="st">"input"</span>])).tolist()</code></pre>

<div class="callout callout-tip"><p><strong>💡 Concurrent request safety:</strong> <code>VajraaMemoryPool</code> uses <code>threading.Lock</code> to protect all slot operations. Concurrent requests to the same model will safely queue for slot availability — no race conditions on pool state.</p></div>
</div>
'''

# ════════════════════════════════════════════════════
#  WRITE ALL PAGES
# ════════════════════════════════════════════════════
pages = [
    ("index.html",         "Vajraa Docs",         "index.html",
     [("Home", None)], INDEX),
    ("getting-started.html", "Getting Started",   "getting-started.html",
     [("Home", "index.html"), ("Getting Started", None)], GETTING_STARTED),
    ("architecture.html",  "Architecture",        "architecture.html",
     [("Home", "index.html"), ("Architecture", None)], ARCHITECTURE),
    ("flows.html",         "Flows",               "flows.html",
     [("Home", "index.html"), ("How It Works", None)], FLOWS),
    ("python-api.html",    "Python API",          "python-api.html",
     [("Home", "index.html"), ("Python API", None)], PYTHON_API),
    ("cpp-api.html",       "C++ API",             "cpp-api.html",
     [("Home", "index.html"), ("C++ API", None)], CPP_API),
    ("memory-security.html","Memory Security",    "memory-security.html",
     [("Home", "index.html"), ("Memory Security", None)], MEMORY_SECURITY),
]

for filename, title, active, breadcrumb, content in pages:
    html = page(title, active, breadcrumb, content)
    path = os.path.join(DOCS_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[Done] {filename}")

print("\nAll documentation pages generated successfully!")
print(f"   Location: {os.path.abspath(DOCS_DIR)}")
print("\n   Enable GitHub Pages in your repo settings:")
print("   Settings -> Pages -> Source -> Deploy from branch -> main / docs/")

