document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const confirmCard = document.getElementById('confirmCard');
    const loadedFileName = document.getElementById('loadedFileName');
    const loadedFileSize = document.getElementById('loadedFileSize');
    const confirmScanBtn = document.getElementById('confirmScanBtn');
    const cancelFileBtn = document.getElementById('cancelFileBtn');

    const workspace = document.getElementById('workspace');
    const rawCode = document.getElementById('rawCode');
    const cleanCode = document.getElementById('cleanCode');
    const scanBtn = document.getElementById('scanBtn');
    const cleanBtn = document.getElementById('cleanBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const reportSection = document.getElementById('reportSection');
    const statusBadge = document.getElementById('statusBadge');
    const logList = document.getElementById('logList');

    let pendingFileContent = '';
    let fileName = 'cleaned_script.lua';

    const DANGEROUS_PATTERNS = [
        { pattern: /httpGet|httpPost|httpRequest|asyncHttpRequest|performHttpRequest/gi, severity: 'High', name: 'HTTP Request (Pengiriman data ke Webhook/Server luar)' },
        { pattern: /discord\.com\/api\/webhooks/gi, severity: 'High', name: 'Discord Webhook URL (Biasa digunakan penampung data keylogger)' },
        { pattern: /io\.open|io\.input|io\.output/gi, severity: 'High', name: 'Akses Sistem File (Membaca file sensitif lokal)' },
        { pattern: /loadstring|load\s*\(/gi, severity: 'Medium', name: 'Dynamic Code Execution (Eksekusi kode tersembunyi/obfuscated)' },
        { pattern: /getfenv|setfenv/gi, severity: 'Medium', name: 'Environment Manipulation (Bypass proteksi/Hooks)' },
        { pattern: /string\.char\s*\(\s*\d+/gi, severity: 'Medium', name: 'String Obfuscation (Penggunaan ASCII code tersembunyi)' },
        { pattern: /onKey|KeyPress|KeyRelease|vkeys|getKeystate/gi, severity: 'High', name: 'Key Interception / Hook Keyboard (Sifat Utama Keylogger)' }
    ];

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            stageFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            stageFile(e.target.files[0]);
        }
    });

    // Menyiapkan File & Menampilkan Kartu Konfirmasi (Belum Diproses)
    function stageFile(file) {
        if (!file.name.endsWith('.lua') && !file.name.endsWith('.txt')) {
            alert('Silakan unggah file berformat .lua!');
            return;
        }

        fileName = file.name.replace('.lua', '_cleaned.lua');
        loadedFileName.textContent = file.name;
        loadedFileSize.textContent = (file.size / 1024).toFixed(2) + ' KB';

        const reader = new FileReader();
        reader.onload = (e) => {
            pendingFileContent = e.target.result;
            // Tampilkan kartu konfirmasi, sembunyikan workspace & laporan lama
            confirmCard.style.display = 'flex';
            workspace.style.display = 'none';
            reportSection.style.display = 'none';
        };
        reader.readAsText(file);
    }

    // Ketika Tombol "Konfirmasi & Pindai Lua" Ditekan
    confirmScanBtn.addEventListener('click', () => {
        rawCode.value = pendingFileContent;
        confirmCard.style.display = 'none';
        workspace.style.display = 'grid';
        analyzeCode();
    });

    // Batal Pilihan File
    cancelFileBtn.addEventListener('click', () => {
        pendingFileContent = '';
        fileInput.value = '';
        confirmCard.style.display = 'none';
    });

    scanBtn.addEventListener('click', analyzeCode);

    function analyzeCode() {
        const code = rawCode.value;
        const lines = code.split('\n');
        logList.innerHTML = '';
        let detections = [];

        lines.forEach((lineText, index) => {
            DANGEROUS_PATTERNS.forEach(rule => {
                if (rule.pattern.test(lineText)) {
                    detections.push({
                        line: index + 1,
                        text: lineText.trim(),
                        rule: rule.name,
                        severity: rule.severity
                    });
                }
            });
        });

        reportSection.style.display = 'block';

        if (detections.length === 0) {
            statusBadge.className = 'status-badge safe';
            statusBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Skrip Bersih: Tidak ditemukan pola keylogger/stealer standar.';
        } else {
            statusBadge.className = 'status-badge danger';
            statusBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Terdeteksi ${detections.length} Potensi Bahaya!`;
            
            detections.forEach(item => {
                const li = document.createElement('li');
                li.className = item.severity === 'High' ? 'threat-high' : 'threat-medium';
                li.innerHTML = `<i class="fa-solid fa-bug"></i> <strong>Baris ${item.line}:</strong> [${item.severity}] ${item.rule} <br> <code>${escapeHtml(item.text)}</code>`;
                logList.appendChild(li);
            });
        }
    }

    cleanBtn.addEventListener('click', () => {
        let code = rawCode.value;
        let lines = code.split('\n');
        let cleanedLines = lines.map(line => {
            let isDangerous = DANGEROUS_PATTERNS.some(rule => rule.pattern.test(line));
            if (isDangerous) {
                return `-- [SECURITY SANITIZED] -- ` + line;
            }
            return line;
        });

        cleanCode.value = cleanedLines.join('\n');
        downloadBtn.disabled = false;
    });

    downloadBtn.addEventListener('click', () => {
        const blob = new Blob([cleanCode.value], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(url);
    });

    function escapeHtml(text) {
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
});
