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
    let currentFileName = 'script.lua';
    let detectedUrl = '';

    const DANGEROUS_PATTERNS = [
        /httpGet|httpPost|httpRequest|asyncHttpRequest|performHttpRequest/gi,
        /discord\.com\/api\/webhooks/gi,
        /io\.open|io\.input|io\.output/gi,
        /loadstring|load\s*\(/gi,
        /getfenv|setfenv/gi,
        /onKey|KeyPress|KeyRelease|vkeys|getKeystate/gi
    ];

    const URL_PATTERN = /(https?:\/\/[^\s"'`()]+)/gi;

    // Deobfuscator Otomatis untuk Mengurai Kode Enkripsi (ASCII/Hex/Escape)
    function deobfuscateLua(code) {
        let decoded = code;
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
        return decoded;
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
            workspace.style.display = 'none';
        };
        reader.readAsText(file);
    }

    cancelFileBtn.addEventListener('click', () => {
        pendingFileContent = '';
        fileInput.value = '';
        confirmCard.style.display = 'none';
    });

    confirmScanBtn.addEventListener('click', () => {
        // Dekripsi enkripsi jika ada
        const decoded = deobfuscateLua(pendingFileContent);
        rawCode.value = decoded;
        confirmCard.style.display = 'none';
        workspace.style.display = 'grid';
        analyzeCode();
    });

    scanBtn.addEventListener('click', analyzeCode);

    function analyzeCode() {
        const code = rawCode.value;
        let matchedPatterns = 0;
        let urlsFound = [];

        // Hitung pola mencurigakan
        DANGEROUS_PATTERNS.forEach(pattern => {
            const matches = code.match(pattern);
            if (matches) matchedPatterns += matches.length;
        });

        // Cari URL mencurigakan
        const urlMatches = code.match(URL_PATTERN);
        if (urlMatches) {
            urlsFound = [...new Set(urlMatches)];
        }

        if (matchedPatterns > 0 || urlsFound.length > 0) {
            showModalAlert(matchedPatterns, urlsFound);
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

    cleanBtn.addEventListener('click', () => {
        let lines = rawCode.value.split('\n');
        let cleaned = lines.map(line => {
            let isDangerous = DANGEROUS_PATTERNS.some(p => p.test(line)) || URL_PATTERN.test(line);
            return isDangerous ? `-- [SANITY REMOVED] -- ` + line : line;
        });
        cleanCode.value = cleaned.join('\n');
        downloadBtn.disabled = false;
    });

    downloadBtn.addEventListener('click', () => {
        const blob = new Blob([cleanCode.value], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = currentFileName.replace('.lua', '_cleaned.lua');
        a.click();
        URL.revokeObjectURL(url);
    });
});
