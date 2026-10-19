document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const filePreview = document.getElementById('filePreview');
    const fileNameText = document.getElementById('fileNameText');
    const fileSizeText = document.getElementById('fileSizeText');
    
    const scanBtn = document.getElementById('scanBtn');
    const scanIcon = document.getElementById('scanIcon');
    const scanBtnText = document.getElementById('scanBtnText');
    const downloadCleanBtn = document.getElementById('downloadCleanBtn');

    const modalOverlay = document.getElementById('modalOverlay');
    const modalIcon = document.getElementById('modalIcon');
    const modalTitle = document.getElementById('modalTitle');
    const modalFileName = document.getElementById('modalFileName');
    const modalDesc = document.getElementById('modalDesc');
    const patternCount = document.getElementById('patternCount');
    const urlCount = document.getElementById('urlCount');
    const urlSection = document.getElementById('urlSection');
    const detectedUrlText = document.getElementById('detectedUrlText');
    const copyUrlBtn = document.getElementById('copyUrlBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');

    let rawFileContent = '';
    let cleanedFileContent = '';
    let currentFileName = '';
    let detectedUrl = '';

    const DANGEROUS_PATTERNS = [
        /httpGet|httpPost|httpRequest|asyncHttpRequest|performHttpRequest/gi,
        /discord\.com\/api\/webhooks/gi,
        /onKey|KeyPress|KeyRelease|vkeys|getKeystate/gi,
        /io\.open|io\.input|io\.output/gi,
        /loadstring|load\s*\(/gi,
        /getfenv|setfenv/gi
    ];

    const URL_PATTERN = /(https?:\/\/[^\s"'`()]+)/gi;

    function deobfuscateLua(code) {
        let decoded = code;

        decoded = decoded.replace(/(\\(\d{1,3}))+/g, (match) => {
            try {
                return match.split('\\').filter(Boolean).map(n => String.fromCharCode(parseInt(n, 10))).join('');
            } catch (e) { return match; }
        });

        decoded = decoded.replace(/string\.char\s*\(\s*([\d\s,]+)\s*\)/gi, (match, group) => {
            try {
                return '"' + group.split(',').map(n => String.fromCharCode(parseInt(n.trim(), 10))).join('') + '"';
            } catch (e) { return match; }
        });

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
        if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleFile(e.target.files[0]);
    });

    function handleFile(file) {
        currentFileName = file.name;
        fileNameText.textContent = file.name;
        fileSizeText.textContent = (file.size / 1024).toFixed(2) + ' KB';

        const reader = new FileReader();
        reader.onload = (e) => {
            rawFileContent = e.target.result;
            filePreview.style.display = 'block';
            scanBtn.disabled = false;
            downloadCleanBtn.style.display = 'none';
        };
        reader.readAsText(file);
    }

    scanBtn.addEventListener('click', () => {
        scanBtn.disabled = true;
        scanIcon.className = 'fa-solid fa-spinner fa-spin';
        scanBtnText.textContent = 'Memeriksa file...';

        setTimeout(() => {
            analyzeAndSanitize();
            scanIcon.className = 'fa-solid fa-magnifying-glass';
            scanBtnText.textContent = 'Periksa File';
            scanBtn.disabled = false;
        }, 1200);
    });

    function analyzeAndSanitize() {
        const decodedCode = deobfuscateLua(rawFileContent);
        const lines = decodedCode.split('\n');

        let patternMatchesCount = 0;
        let urlsFound = [];

        DANGEROUS_PATTERNS.forEach(pattern => {
            const matches = decodedCode.match(pattern);
            if (matches) patternMatchesCount += matches.length;
        });

        const urlMatches = decodedCode.match(URL_PATTERN);
        if (urlMatches) {
            urlsFound = [...new Set(urlMatches)];
        }

        let cleanedLines = lines.map(line => {
            let lineStr = line;
            if (URL_PATTERN.test(lineStr)) {
                lineStr = lineStr.replace(URL_PATTERN, '"https://sanitized-safe-url.local"');
            }
            let isDangerous = DANGEROUS_PATTERNS.some(p => p.test(lineStr));
            return isDangerous ? '' : lineStr;
        });

        cleanedFileContent = cleanedLines.filter(line => line.trim() !== '').join('\n');
        downloadCleanBtn.style.display = 'flex';

        showResultModal(patternMatchesCount, urlsFound);
    }

    function showResultModal(patterns, urls) {
        modalFileName.textContent = currentFileName;

        if (patterns > 0 || urls.length > 0) {
            modalIcon.className = 'modal-icon red';
            modalIcon.innerHTML = '<i class="fa-solid fa-skull-crossbones"></i>';
            modalTitle.textContent = 'Keylogger Terdeteksi!';
            modalDesc.style.display = 'block';
            patternCount.textContent = patterns;
            urlCount.textContent = urls.length;

            if (urls.length > 0) {
                detectedUrl = urls[0];
                detectedUrlText.textContent = detectedUrl;
                urlSection.style.display = 'block';
            } else {
                urlSection.style.display = 'none';
            }

            closeModalBtn.className = 'btn-modal-close';
            closeModalBtn.textContent = 'Mengerti';
        } else {
            modalIcon.className = 'modal-icon green';
            modalIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
            modalTitle.textContent = 'File Bersih & Aman!';
            modalDesc.style.display = 'none';
            urlSection.style.display = 'none';

            closeModalBtn.className = 'btn-modal-close safe';
            closeModalBtn.textContent = 'Tutup';
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
