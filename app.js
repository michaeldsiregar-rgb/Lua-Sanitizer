document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const confirmCard = document.getElementById('confirmCard');
    const loadedFileName = document.getElementById('loadedFileName');
    const loadedFileSize = document.getElementById('loadedFileSize');
    const confirmScanBtn = document.getElementById('confirmScanBtn');
    const cancelFileBtn = document.getElementById('cancelFileBtn');

    // Dashboard Elements
    const resultsDashboard = document.getElementById('resultsDashboard');
    const tierCard = document.getElementById('tierCard');
    const tierIcon = document.getElementById('tierIcon');
    const tierTitle = document.getElementById('tierTitle');
    const tierDesc = document.getElementById('tierDesc');
    const statPatterns = document.getElementById('statPatterns');
    const statUrls = document.getElementById('statUrls');
    const statObfuscated = document.getElementById('statObfuscated');
    const findingsList = document.getElementById('findingsList');
    const downloadCleanBtn = document.getElementById('downloadCleanBtn');

    // Modal Alert Elements
    const modalOverlay = document.getElementById('modalOverlay');
    const modalFileName = document.getElementById('modalFileName');
    const patternCount = document.getElementById('patternCount');
    const urlCount = document.getElementById('urlCount');
    const urlSection = document.getElementById('urlSection');
    const detectedUrlText = document.getElementById('detectedUrlText');
    const copyUrlBtn = document.getElementById('copyUrlBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');

    let pendingFileContent = '';
    let cleanedFileContent = '';
    let currentFileName = 'script.lua';
    let detectedUrl = '';

    const DANGEROUS_RULES = [
        { pattern: /httpGet|httpPost|httpRequest|asyncHttpRequest|performHttpRequest/gi, severity: 'High', name: 'Fungsi Exfiltration Data (HTTP Request)' },
        { pattern: /discord\.com\/api\/webhooks/gi, severity: 'High', name: 'Discord Webhook URL (Penampung Data Stealer)' },
        { pattern: /onKey|KeyPress|KeyRelease|vkeys|getKeystate/gi, severity: 'High', name: 'Keyboard Hooking / Key Interception' },
        { pattern: /io\.open|io\.input|io\.output/gi, severity: 'Medium', name: 'Akses Pembacaan File Lokal / Sistem' },
        { pattern: /loadstring|load\s*\(/gi, severity: 'Medium', name: 'Dynamic Code Execution' },
        { pattern: /getfenv|setfenv/gi, severity: 'Low', name: 'Environment Hooking / Manipulation' }
    ];

    const URL_PATTERN = /(https?:\/\/[^\s"'`()]+)/gi;

    // Deobfuscator Otomatis untuk Mengurai Kode Terenkripsi
    function deobfuscateLua(code) {
        let decoded = code;
        let isObfuscated = false;

        if (/(\\(\d{1,3}))+/g.test(decoded) || /string\.char\s*\(/gi.test(decoded) || /(\\x[0-9a-fA-F]{2})+/g.test(decoded)) {
            isObfuscated = true;
        }

        // Decode Escape \104\101\108...
        decoded = decoded.replace(/(\\(\d{1,3}))+/g, (match) => {
            try {
                return match.split('\\').filter(Boolean).map(n => String.fromCharCode(parseInt(n, 10))).join('');
            } catch (e) { return match; }
        });

        // Decode string.char(...)
        decoded = decoded.replace(/string\.char\s*\(\s*([\d\s,]+)\s*\)/gi, (match, group) => {
            try {
                return '"' + group.split(',').map(n => String.fromCharCode(parseInt(n.trim(), 10))).join('') + '"';
            } catch (e) { return match; }
        });

        // Decode Hex \x68\x65...
        decoded = decoded.replace(/(\\x[0-9a-fA-F]{2})+/g, (match) => {
            try {
                return match.split('\\x').filter(Boolean).map(h => String.fromCharCode(parseInt(h, 16))).join('');
            } catch (e) { return match; }
        });

        return { decoded, isObfuscated };
    }

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) stageFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) stageFile(e.target.files[0]);
    });

    function stageFile(file) {
        currentFileName = file.name;
        loadedFileName.textContent = file.name;
        loadedFileSize.textContent = (file.size / 1024).toFixed(2) + ' KB';

        const reader = new FileReader();
        reader.onload = (e) => {
            pendingFileContent = e.target.result;
            confirmCard.style.display = 'flex';
            resultsDashboard.style.display = 'none';
        };
        reader.readAsText(file);
    }

    cancelFileBtn.addEventListener('click', () => {
        pendingFileContent = '';
        fileInput.value = '';
        confirmCard.style.display = 'none';
    });

    confirmScanBtn.addEventListener('click', () => {
        confirmCard.style.display = 'none';
        resultsDashboard.style.display = 'flex';
        analyzeCode();
    });

    function analyzeCode() {
        const { decoded, isObfuscated } = deobfuscateLua(pendingFileContent);
        const lines = decoded.split('\n');

        let detections = [];
        let urlsFound = [];

        // Pindai Aturan Berbahaya per Baris
        lines.forEach((lineText, index) => {
            DANGEROUS_RULES.forEach(rule => {
                if (rule.pattern.test(lineText)) {
                    detections.push({
                        line: index + 1,
                        name: rule.name,
                        severity: rule.severity
                    });
                }
            });
        });

        // Pindai URL
        const urlMatches = decoded.match(URL_PATTERN);
        if (urlMatches) {
            urlsFound = [...new Set(urlMatches)];
        }

        // Tentukan Tier Risiko
        let tier = 0;
        let hasHighSev = detections.some(d => d.severity === 'High');
        let hasMedSev = detections.some(d => d.severity === 'Medium');

        if (hasHighSev || urlsFound.length > 0) {
            tier = 3; // Critical / High Risk
        } else if (hasMedSev || isObfuscated) {
            tier = 2; // Medium Risk
        } else if (detections.length > 0) {
            tier = 1; // Low Risk
        }

        // Update UI Tier Dashboard
        updateTierUI(tier, detections.length, urlsFound.length, isObfuscated);

        // Populate Findings List
        findingsList.innerHTML = '';
        if (detections.length === 0 && urlsFound.length === 0) {
            findingsList.innerHTML = '<li class="sev-low"><i class="fa-solid fa-circle-check"></i> Tidak ada indikator ancaman yang terdeteksi.</li>';
        } else {
            detections.forEach(item => {
                const li = document.createElement('li');
                li.className = item.severity === 'High' ? 'sev-high' : (item.severity === 'Medium' ? 'sev-medium' : 'sev-low');
                li.innerHTML = `<strong>Baris ${item.line}:</strong> [${item.severity}] ${item.name}`;
                findingsList.appendChild(li);
            });
            urlsFound.forEach(u => {
                const li = document.createElement('li');
                li.className = 'sev-high';
                li.innerHTML = `<strong>URL Terdeteksi:</strong> ${u}`;
                findingsList.appendChild(li);
            });
        }

        // ==========================================
        // FITUR PEMBERSIHAN TOTAL (100% CLEAN SANITIZER)
        // ==========================================
        let cleanLines = lines.map(line => {
            let processedLine = line;

            // 1. Hapus/Netralkan semua URL
            if (URL_PATTERN.test(processedLine)) {
                processedLine = processedLine.replace(URL_PATTERN, '"https://sanitized-safe-url.local"');
            }

            // 2. Cek apakah ada pola berbahaya
            let isDangerous = DANGEROUS_RULES.some(r => r.pattern.test(processedLine));

            if (isDangerous) {
                // Hapus total baris berbahaya dan ganti dengan penanda komentar netral
                return `-- [CLEANED BY LUA GUARD: REMOVED THREAT]`;
            }

            return processedLine;
        });

        cleanedFileContent = cleanLines.join('\n');
        downloadCleanBtn.disabled = false;

        // Tampilkan Modal Popup Jika Ada Ancaman
        if (tier >= 2) {
            showModalAlert(detections.length, urlsFound);
        }
    }

    function updateTierUI(tier, patternCountVal, urlCountVal, isObf) {
        tierCard.className = `tier-card tier-${tier}`;
        statPatterns.textContent = patternCountVal;
        statUrls.textContent = urlCountVal;
        statObfuscated.textContent = isObf ? 'Ya' : 'Tidak';

        if (tier === 3) {
            tierIcon.innerHTML = '<i class="fa-solid fa-skull-crossbones"></i>';
            tierTitle.textContent = 'Tier 3 - Bahaya Tinggi (Critical)';
            tierDesc.textContent = 'Skrip ini sangat berpotensi mengandung Keylogger, Webhook Stealer, atau exfiltration data.';
        } else if (tier === 2) {
            tierIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
            tierTitle.textContent = 'Tier 2 - Risiko Sedang (Suspicious)';
            tierDesc.textContent = 'Terdeteksi enkripsi/obfuscation atau akses sistem file yang perlu diwaspadai.';
        } else if (tier === 1) {
            tierIcon.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i>';
            tierTitle.textContent = 'Tier 1 - Risiko Rendah (Low)';
            tierDesc.textContent = 'Terdapat beberapa fungsi biasa yang perlu perhatian ringan.';
        } else {
            tierIcon.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
            tierTitle.textContent = 'Tier 0 - Aman (Clean)';
            tierDesc.textContent = 'Skrip bersih dan tidak mengandung pola keylogger yang terdeteksi.';
        }
    }

    function showModalAlert(patternsCount, urls) {
        modalFileName.textContent = currentFileName;
        patternCount.textContent = patternsCount;
        urlCount.textContent = urls.length;

        if (urls.length > 0) {
            detectedUrl = urls[0];
            detectedUrlText.textContent = detectedUrl;
            urlSection.style.display = 'block';
        } else {
            urlSection.style.display = 'none';
        }

        modalOverlay.style.display = 'flex';
    }

    closeModalBtn.addEventListener('click', () => {
        modalOverlay.style.display = 'none';
    });

    copyUrlBtn.addEventListener('click', () => {
        if (detectedUrl) {
            navigator.clipboard.writeText(detectedUrl);
            copyUrlBtn.innerHTML = '<i class="fa-solid fa-check"></i> Tersalin!';
            setTimeout(() => {
                copyUrlBtn.innerHTML = '<i class="fa-solid fa-copy"></i> Salin URL';
            }, 2000);
        }
    });

    downloadCleanBtn.addEventListener('click', () => {
        const blob = new Blob([cleanedFileContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = currentFileName.replace('.lua', '_cleaned.lua');
        a.click();
        URL.revokeObjectURL(url);
    });
});
