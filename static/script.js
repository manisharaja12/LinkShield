document.addEventListener('DOMContentLoaded', function() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const analyzeBtn = document.getElementById('analyze-btn');
    const urlInput = document.getElementById('url-input');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const batchAnalyzeBtn = document.getElementById('batch-analyze-btn');
    const batchInput = document.getElementById('batch-input');
    const batchLoading = document.getElementById('batch-loading');
    const batchResult = document.getElementById('batch-result');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            
            if (tabName === 'info') {
                loadModelInfo();
            }
        });
    });

    analyzeBtn.addEventListener('click', analyzeSingleUrl);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeSingleUrl();
        }
    });

    batchAnalyzeBtn.addEventListener('click', analyzeBatchUrls);

    async function analyzeSingleUrl() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a URL');
            return;
        }

        loading.classList.remove('hidden');
        result.classList.add('hidden');
        analyzeBtn.disabled = true;

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            displayResult(data);
        } catch (error) {
            result.innerHTML = `
                <div class="result suspicious">
                    <h2>❌ Error</h2>
                    <p>${error.message}</p>
                </div>
            `;
            result.classList.remove('hidden');
        } finally {
            loading.classList.add('hidden');
            analyzeBtn.disabled = false;
        }
    }

    function displayResult(data) {
        const isSafe = data.verdict === 'safe';
        const icon = isSafe ? '✅' : '🚨';
        const verdictText = isSafe ? 'SAFE / LEGITIMATE' : 'SUSPICIOUS / MALICIOUS';
        const confidence = (data.confidence * 100).toFixed(1);

        let html = `
            <div class="verdict">
                <div class="verdict-icon">${icon}</div>
                <div class="verdict-text">
                    <h2>${verdictText}</h2>
                    <p class="confidence">Confidence: ${confidence}%</p>
                </div>
            </div>
            <div class="url-display">
                <strong>URL:</strong> ${escapeHtml(data.url)}
            </div>
        `;

        if (!isSafe && data.reasons && data.reasons.length > 0) {
            html += `
                <div class="reasons">
                    <h3>⚠️ Warning Signs Detected:</h3>
                    <ul>
                        ${data.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else if (isSafe) {
            html += `
                <div class="reasons">
                    <p style="color: var(--success-color); font-weight: 600;">
                        ✓ No suspicious patterns detected<br>
                        ✓ URL appears to follow normal conventions
                    </p>
                </div>
            `;
        }

        if (data.features) {
            html += `
                <div class="features">
                    <div class="feature-item">
                        <div class="feature-label">URL Length</div>
                        <div class="feature-value">${data.features.url_length}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">HTTPS</div>
                        <div class="feature-value">${data.features.has_https ? '✓ Yes' : '✗ No'}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">IP Address</div>
                        <div class="feature-value">${data.features.has_ip ? '⚠️ Yes' : '✓ No'}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Suspicious Keywords</div>
                        <div class="feature-value">${data.features.suspicious_keywords}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Dots</div>
                        <div class="feature-value">${data.features.num_dots}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Hyphens</div>
                        <div class="feature-value">${data.features.num_hyphens}</div>
                    </div>
                </div>
            `;
        }

        result.innerHTML = html;
        result.className = `result ${data.verdict}`;
        result.classList.remove('hidden');
    }

    async function analyzeBatchUrls() {
        const urlsText = batchInput.value.trim();
        
        if (!urlsText) {
            alert('Please enter URLs to analyze');
            return;
        }

        const urls = urlsText.split('\n').map(u => u.trim()).filter(u => u);

        if (urls.length === 0) {
            alert('No valid URLs found');
            return;
        }

        batchLoading.classList.remove('hidden');
        batchResult.classList.add('hidden');
        batchAnalyzeBtn.disabled = true;

        try {
            const response = await fetch('/api/batch-analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ urls: urls })
            });

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            displayBatchResults(data);
        } catch (error) {
            batchResult.innerHTML = `
                <div class="result suspicious">
                    <h2>❌ Error</h2>
                    <p>${error.message}</p>
                </div>
            `;
            batchResult.classList.remove('hidden');
        } finally {
            batchLoading.classList.add('hidden');
            batchAnalyzeBtn.disabled = false;
        }
    }

    function displayBatchResults(data) {
        let html = `
            <div class="batch-summary">
                <div class="summary-card">
                    <h3>${data.summary.total}</h3>
                    <p>Total URLs</p>
                </div>
                <div class="summary-card" style="border-left: 3px solid var(--success-color);">
                    <h3 style="color: var(--success-color);">${data.summary.safe}</h3>
                    <p>Safe</p>
                </div>
                <div class="summary-card" style="border-left: 3px solid var(--danger-color);">
                    <h3 style="color: var(--danger-color);">${data.summary.suspicious}</h3>
                    <p>Suspicious</p>
                </div>
            </div>
            <div class="batch-results">
                <h3 style="margin-bottom: 15px;">Detailed Results:</h3>
        `;

        data.results.forEach(item => {
            const badge = item.verdict === 'safe' 
                ? '<span class="url-badge safe">✓ Safe</span>'
                : '<span class="url-badge suspicious">⚠ Suspicious</span>';
            
            const confidence = item.confidence ? ` (${(item.confidence * 100).toFixed(0)}%)` : '';
            
            html += `
                <div class="url-item ${item.verdict}">
                    <div class="url-text">${escapeHtml(item.url)}</div>
                    ${badge}
                </div>
            `;
        });

        html += '</div>';

        batchResult.innerHTML = html;
        batchResult.classList.remove('hidden');
    }

    async function loadModelInfo() {
        const modelStats = document.getElementById('model-stats');
        
        try {
            const response = await fetch('/api/model-info');
            const data = await response.json();

            if (data.status === 'ready') {
                modelStats.innerHTML = `
                    <h3>Model Statistics</h3>
                    <div class="stat-grid">
                        <div class="stat-item">
                            <div class="stat-label">Status</div>
                            <div class="stat-value" style="color: var(--success-color);">✓ Ready</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">Model Type</div>
                            <div class="stat-value">${data.model_type}</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">Features</div>
                            <div class="stat-value">${data.features_count}</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">Model Size</div>
                            <div class="stat-value">${data.model_size_mb} MB</div>
                        </div>
                    </div>
                `;
            } else {
                modelStats.innerHTML = `
                    <h3>Model Statistics</h3>
                    <p style="color: var(--warning-color);">⚠️ ${data.message}</p>
                `;
            }
        } catch (error) {
            modelStats.innerHTML = `
                <h3>Model Statistics</h3>
                <p style="color: var(--danger-color);">❌ Failed to load model information</p>
            `;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});

/* ──────────────────────────────────────────────
   QR Scanner Module
   Handles: file upload, drag-and-drop, QR decode
   via /api/scan-qr, then reuses /api/analyze
   for URL analysis with the existing ML pipeline.
   ────────────────────────────────────────────── */
(function initQRScanner() {
    const dropZone       = document.getElementById('qr-drop-zone');
    const fileInput      = document.getElementById('qr-file-input');
    const previewContainer = document.getElementById('qr-preview-container');
    const previewImg     = document.getElementById('qr-preview-img');
    const clearBtn       = document.getElementById('qr-clear-btn');
    const scanBtn        = document.getElementById('qr-scan-btn');
    const qrLoading      = document.getElementById('qr-loading');
    const qrLoadingText  = document.getElementById('qr-loading-text');
    const qrResult       = document.getElementById('qr-result');
    const qrAnalysisResult = document.getElementById('qr-analysis-result');

    // Currently selected file
    let selectedFile = null;

    // ── File selection helpers ──

    function setFile(file) {
        if (!file) return;
        const allowed = ['image/png', 'image/jpeg', 'image/jpg'];
        if (!allowed.includes(file.type)) {
            showQRError('Invalid file type. Please upload PNG, JPG, or JPEG.');
            return;
        }
        selectedFile = file;
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.classList.remove('hidden');
        };
        reader.readAsDataURL(file);
        scanBtn.disabled = false;
        // Clear previous results when a new image is chosen
        qrResult.innerHTML = '';
        qrResult.classList.add('hidden');
        qrAnalysisResult.innerHTML = '';
        qrAnalysisResult.classList.add('hidden');
    }

    function clearFile() {
        selectedFile = null;
        fileInput.value = '';
        previewImg.src = '';
        previewContainer.classList.add('hidden');
        scanBtn.disabled = true;
        qrResult.innerHTML = '';
        qrResult.classList.add('hidden');
        qrAnalysisResult.innerHTML = '';
        qrAnalysisResult.classList.add('hidden');
    }

    // ── Event listeners for upload area ──

    // Click on drop zone opens file picker
    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) setFile(fileInput.files[0]);
    });

    // Drag-and-drop support
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) setFile(file);
    });

    clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearFile();
    });

    // ── Scan QR button ──

    scanBtn.addEventListener('click', scanQRCode);

    async function scanQRCode() {
        if (!selectedFile) return;

        // Show "Scanning QR Code..." loading state
        setQRLoading(true, 'Scanning QR Code...');
        qrResult.innerHTML = '';
        qrResult.classList.add('hidden');
        qrAnalysisResult.innerHTML = '';
        qrAnalysisResult.classList.add('hidden');
        scanBtn.disabled = true;

        try {
            // Build multipart form data with the image
            const formData = new FormData();
            formData.append('image', selectedFile);

            // Update loading text
            setQRLoading(true, 'Extracting URL...');

            const response = await fetch('/api/scan-qr', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.error) {
                showQRError(data.error);
                return;
            }

            // QR decoded successfully
            if (!data.is_url) {
                // QR contains plain text, not a URL
                showQRNonURL(data.qr_content);
                return;
            }

            // QR contains a URL — display it and offer analysis
            showQRDetected(data.qr_content);

        } catch (err) {
            showQRError('QR decoding failed. Please try a clearer image.');
        } finally {
            setQRLoading(false);
            scanBtn.disabled = false;
        }
    }

    // ── Display helpers ──

    function setQRLoading(show, text) {
        if (show) {
            qrLoadingText.textContent = text || 'Processing...';
            qrLoading.classList.remove('hidden');
        } else {
            qrLoading.classList.add('hidden');
        }
    }

    // Show error card
    function showQRError(message) {
        qrResult.innerHTML = `
            <div class="qr-error-card">
                <h3>❌ Error</h3>
                <p>${escapeHtmlQR(message)}</p>
            </div>`;
        qrResult.classList.remove('hidden');
    }

    // Show info card when QR has text but not a URL
    function showQRNonURL(content) {
        qrResult.innerHTML = `
            <div class="qr-info-card">
                <h3>📋 QR Code Detected</h3>
                <p>QR code detected, but it does not contain a URL.</p>
                <div class="qr-url-display" style="margin-top:10px;">${escapeHtmlQR(content)}</div>
            </div>`;
        qrResult.classList.remove('hidden');
    }

    // Show detected URL card with "Analyze URL" button
    function showQRDetected(url) {
        qrResult.innerHTML = `
            <div class="qr-detected-card">
                <h3>✅ QR Code Detected</h3>
                <p style="color:var(--text-muted);margin-bottom:8px;">Extracted URL:</p>
                <div class="qr-url-display">${escapeHtmlQR(url)}</div>
                <button id="qr-analyze-btn" class="primary-btn">
                    <span class="btn-text">Analyze URL</span>
                    <span class="btn-icon">🔍</span>
                </button>
            </div>`;
        qrResult.classList.remove('hidden');

        // Wire up the Analyze URL button
        document.getElementById('qr-analyze-btn').addEventListener('click', () => {
            analyzeQRUrl(url);
        });
    }

    // ── Analyze the extracted URL using the existing /api/analyze endpoint ──

    async function analyzeQRUrl(url) {
        const analyzeBtn = document.getElementById('qr-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = true;

        setQRLoading(true, 'Analyzing URL...');
        qrAnalysisResult.innerHTML = '';
        qrAnalysisResult.classList.add('hidden');

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (data.error) throw new Error(data.error);

            // Reuse the existing displayResult function from the main script
            // but render into qr-analysis-result instead of #result
            renderQRAnalysisResult(data);

        } catch (err) {
            qrAnalysisResult.innerHTML = `
                <div class="result suspicious">
                    <h2>❌ Analysis Error</h2>
                    <p>${escapeHtmlQR(err.message)}</p>
                </div>`;
            qrAnalysisResult.classList.remove('hidden');
        } finally {
            setQRLoading(false);
            if (analyzeBtn) analyzeBtn.disabled = false;
        }
    }

    // Renders the analysis result card (mirrors displayResult logic)
    // and appends a QR-specific security warning for unsafe URLs.
    function renderQRAnalysisResult(data) {
        const isSafe = data.verdict === 'safe';
        const icon = isSafe ? '✅' : '🚨';
        const verdictText = isSafe ? 'SAFE / LEGITIMATE' : 'SUSPICIOUS / MALICIOUS';
        const confidence = (data.confidence * 100).toFixed(1);

        let html = `
            <div class="verdict">
                <div class="verdict-icon">${icon}</div>
                <div class="verdict-text">
                    <h2>${verdictText}</h2>
                    <p class="confidence">Confidence: ${confidence}%</p>
                </div>
            </div>
            <div class="url-display">
                <strong>URL:</strong> ${escapeHtmlQR(data.url)}
            </div>`;

        if (!isSafe && data.reasons && data.reasons.length > 0) {
            html += `
                <div class="reasons">
                    <h3>⚠️ Warning Signs Detected:</h3>
                    <ul>
                        ${data.reasons.map(r => `<li>${escapeHtmlQR(r)}</li>`).join('')}
                    </ul>
                </div>`;
        } else if (isSafe) {
            html += `
                <div class="reasons">
                    <p style="color:var(--success-color);font-weight:600;">
                        ✓ No suspicious patterns detected<br>
                        ✓ URL appears to follow normal conventions
                    </p>
                </div>`;
        }

        if (data.features) {
            html += `
                <div class="features">
                    <div class="feature-item">
                        <div class="feature-label">URL Length</div>
                        <div class="feature-value">${data.features.url_length}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">HTTPS</div>
                        <div class="feature-value">${data.features.has_https ? '✓ Yes' : '✗ No'}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">IP Address</div>
                        <div class="feature-value">${data.features.has_ip ? '⚠️ Yes' : '✓ No'}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Suspicious Keywords</div>
                        <div class="feature-value">${data.features.suspicious_keywords}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Dots</div>
                        <div class="feature-value">${data.features.num_dots}</div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-label">Hyphens</div>
                        <div class="feature-value">${data.features.num_hyphens}</div>
                    </div>
                </div>`;
        }

        // QR-specific security warning for unsafe URLs
        if (!isSafe) {
            html += `
                <div class="qr-warning-banner">
                    ⚠️ This QR code leads to a potentially unsafe URL.
                    Do not open the link or provide credentials or sensitive information.
                </div>`;
        }

        qrAnalysisResult.innerHTML = html;
        qrAnalysisResult.className = `result ${data.verdict}`;
        qrAnalysisResult.classList.remove('hidden');
    }

    // Local HTML escape (avoids dependency on outer scope's escapeHtml)
    function escapeHtmlQR(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
})();
