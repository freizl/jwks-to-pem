class JWKSConverter {
    constructor() {
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const convertBtn = document.getElementById('convertBtn');
        const clearAll = document.getElementById('clearAll');
        const copyPem = document.getElementById('copyPem');
        const downloadPem = document.getElementById('downloadPem');

        convertBtn.addEventListener('click', () => this.convertJWKS());
        clearAll.addEventListener('click', () => this.clearAll());
        copyPem.addEventListener('click', () => this.copyPem());
        downloadPem.addEventListener('click', () => this.downloadPem());

        // Auto-convert on input change (with debouncing)
        const jwksInput = document.getElementById('jwksInput');
        let timeout;
        jwksInput.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                if (jwksInput.value.trim()) {
                    this.convertJWKS();
                }
            }, 1000);
        });
    }

    clearAll() {
        document.getElementById('jwksInput').value = '';
        document.getElementById('output').innerHTML = '';
    }

    async copyPem() {
        const output = document.getElementById('output');
        const pemText = output.textContent;

        if (!pemText || pemText.includes('error') || pemText.includes('Please enter')) {
            this.showToast('No PEM key to copy', true);
            return;
        }

        try {
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(pemText);
                this.showToast('PEM key copied to clipboard');
            } else {
                this.fallbackCopyToClipboard(pemText);
            }
        } catch (error) {
            this.fallbackCopyToClipboard(pemText);
        }
    }

    downloadPem() {
        const output = document.getElementById('output');
        const pemText = output.textContent;

        if (!pemText || pemText.includes('error') || pemText.includes('Please enter')) {
            this.showToast('No PEM key to download', true);
            return;
        }

        const timestamp = new Date().toISOString().split('T')[0];
        const blob = new Blob([pemText], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `jwk_${timestamp}.pem`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast('PEM file downloaded');
    }

    showToast(message, isError = false) {
        // Find the download button to show message next to it
        const downloadBtn = document.getElementById('downloadPem');
        if (!downloadBtn) return;

        // Remove any existing message
        const existingMsg = document.getElementById('toast-message');
        if (existingMsg) {
            existingMsg.remove();
        }

        // Create simple message element
        const msg = document.createElement('span');
        msg.id = 'toast-message';
        msg.style.cssText = `
            margin-left: 10px;
            color: ${isError ? '#dc3545' : '#28a745'};
            font-family: monospace;
            font-size: 12px;
        `;
        msg.textContent = message;

        // Insert after download button
        downloadBtn.parentNode.insertBefore(msg, downloadBtn.nextSibling);

        // Auto-dismiss after 2 seconds
        setTimeout(() => {
            if (msg.parentNode) {
                msg.remove();
            }
        }, 2000);
    }

    convertJWKS() {
        const input = document.getElementById('jwksInput').value.trim();
        const output = document.getElementById('output');

        if (!input) {
            output.innerHTML = '<div class="error">Please enter a JWK JSON</div>';
            return;
        }

        try {
            const jwkData = JSON.parse(input);

            // Support single key only - if it's a JWKS, take the first key
            const key = jwkData.keys ? jwkData.keys[0] : jwkData;

            if (!key || typeof key !== 'object') {
                throw new Error('Invalid JWK format - expected single key object');
            }

            try {
                const pem = this.jwkToPem(key);
                output.innerHTML = pem;
                this.showToast('Successfully converted key to PEM format');
            } catch (error) {
                output.innerHTML = `<div class="error">Failed to convert: ${error.message}</div>`;
                this.showToast('Conversion failed', true);
            }
        } catch (error) {
            output.innerHTML = `<div class="error">Invalid JSON: ${error.message}</div>`;
            this.showToast('Failed to parse JSON input', true);
        }
    }

    jwkToPem(jwk) {
        switch (jwk.kty) {
            case 'RSA':
                return this.rsaJwkToPem(jwk);
            case 'EC':
                return this.ecJwkToPem(jwk);
            default:
                throw new Error(`Unsupported key type: ${jwk.kty}`);
        }
    }

    rsaJwkToPem(jwk) {
        if (!jwk.n || !jwk.e) {
            throw new Error('RSA key missing required parameters (n, e)');
        }

        // Convert base64url to regular base64
        const n = this.base64urlToBase64(jwk.n);
        const e = this.base64urlToBase64(jwk.e);

        // Convert to binary
        const nBytes = this.base64ToBytes(n);
        const eBytes = this.base64ToBytes(e);

        // Build ASN.1 DER structure for RSA public key
        const publicKeyInfo = this.buildRSAPublicKeyInfo(nBytes, eBytes);

        // Convert to PEM
        const base64Key = this.bytesToBase64(publicKeyInfo);
        const pemLines = base64Key.match(/.{1,64}/g);

        return '-----BEGIN PUBLIC KEY-----\n' +
               pemLines.join('\n') + '\n' +
               '-----END PUBLIC KEY-----';
    }

    ecJwkToPem(jwk) {
        if (!jwk.x || !jwk.y || !jwk.crv) {
            throw new Error('EC key missing required parameters (x, y, crv)');
        }

        const curve = jwk.crv;
        const curveOid = this.getCurveOID(curve);

        if (!curveOid) {
            throw new Error(`Unsupported curve: ${curve}`);
        }

        // Convert coordinates from base64url to bytes
        const x = this.base64ToBytes(this.base64urlToBase64(jwk.x));
        const y = this.base64ToBytes(this.base64urlToBase64(jwk.y));

        // Build uncompressed point (0x04 + x + y)
        const publicKey = new Uint8Array(1 + x.length + y.length);
        publicKey[0] = 0x04; // Uncompressed point indicator
        publicKey.set(x, 1);
        publicKey.set(y, 1 + x.length);

        // Build ASN.1 DER structure for EC public key
        const publicKeyInfo = this.buildECPublicKeyInfo(publicKey, curveOid);

        // Convert to PEM
        const base64Key = this.bytesToBase64(publicKeyInfo);
        const pemLines = base64Key.match(/.{1,64}/g);

        return '-----BEGIN PUBLIC KEY-----\n' +
               pemLines.join('\n') + '\n' +
               '-----END PUBLIC KEY-----';
    }

    getCurveOID(curve) {
        const curveOIDs = {
            'P-256': [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], // secp256r1
            'P-384': [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], // secp384r1
            'P-521': [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]  // secp521r1
        };
        return curveOIDs[curve];
    }

    buildRSAPublicKeyInfo(nBytes, eBytes) {
        // Build RSAPublicKey sequence (n, e)
        const nInteger = this.buildDERInteger(nBytes);
        const eInteger = this.buildDERInteger(eBytes);
        const rsaPublicKey = this.buildDERSequence([nInteger, eInteger]);

        // RSA algorithm identifier
        const rsaOID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // rsaEncryption
        const nullParam = [0x05, 0x00];
        const algorithmId = this.buildDERSequence([new Uint8Array(rsaOID), new Uint8Array(nullParam)]);

        // PublicKeyInfo
        const publicKeyBitString = this.buildDERBitString(rsaPublicKey);
        return this.buildDERSequence([algorithmId, publicKeyBitString]);
    }

    buildECPublicKeyInfo(publicKey, curveOid) {
        // EC algorithm identifier
        const ecOID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // id-ecPublicKey
        const algorithmId = this.buildDERSequence([new Uint8Array(ecOID), new Uint8Array(curveOid)]);

        // PublicKeyInfo
        const publicKeyBitString = this.buildDERBitString(publicKey);
        return this.buildDERSequence([algorithmId, publicKeyBitString]);
    }

    buildDERInteger(bytes) {
        // Add leading zero if first bit is set (to ensure positive integer)
        const needsLeadingZero = bytes[0] & 0x80;
        const contentLength = bytes.length + (needsLeadingZero ? 1 : 0);
        const lengthBytes = this.encodeDERLength(contentLength);

        const result = new Uint8Array(1 + lengthBytes.length + contentLength);
        result[0] = 0x02; // INTEGER tag
        result.set(lengthBytes, 1);

        let offset = 1 + lengthBytes.length;
        if (needsLeadingZero) {
            result[offset] = 0x00;
            offset++;
        }
        result.set(bytes, offset);

        return result;
    }

    buildDERBitString(bytes) {
        // BIT STRING needs proper length encoding for large content
        const contentLength = bytes.length + 1; // +1 for the unused bits byte
        const lengthBytes = this.encodeDERLength(contentLength);

        const result = new Uint8Array(1 + lengthBytes.length + contentLength);
        result[0] = 0x03; // BIT STRING tag
        result.set(lengthBytes, 1);
        result[1 + lengthBytes.length] = 0x00; // No unused bits
        result.set(bytes, 1 + lengthBytes.length + 1);

        return result;
    }

    buildDERSequence(elements) {
        const totalLength = elements.reduce((sum, el) => sum + el.length, 0);
        const lengthBytes = this.encodeDERLength(totalLength);

        const result = new Uint8Array(1 + lengthBytes.length + totalLength);
        result[0] = 0x30; // SEQUENCE tag
        result.set(lengthBytes, 1);

        let offset = 1 + lengthBytes.length;
        for (const element of elements) {
            result.set(element, offset);
            offset += element.length;
        }

        return result;
    }

    encodeDERLength(length) {
        if (length < 0x80) {
            // Short form: length fits in 7 bits
            return new Uint8Array([length]);
        }

        // Long form: first byte has high bit set + number of length bytes
        const lengthBytes = [];
        let temp = length;
        while (temp > 0) {
            lengthBytes.unshift(temp & 0xff);
            temp >>= 8;
        }

        const result = new Uint8Array(1 + lengthBytes.length);
        result[0] = 0x80 | lengthBytes.length; // High bit set + number of bytes
        result.set(lengthBytes, 1);
        return result;
    }

    getKeyTypeDisplay(jwk) {
        const types = {
            'RSA': 'RSA',
            'EC': `EC (${jwk.crv || 'Unknown'})`
        };
        return types[jwk.kty] || jwk.kty;
    }

    base64urlToBase64(str) {
        // Remove any whitespace
        str = str.replace(/\s/g, '');

        // Add padding if needed
        const padLength = (4 - (str.length % 4)) % 4;
        str += '='.repeat(padLength);

        // Replace URL-safe characters with standard base64 characters
        return str.replace(/-/g, '+').replace(/_/g, '/');
    }

    base64ToBytes(base64) {
        try {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        } catch (error) {
            throw new Error(`Invalid base64 encoding: ${error.message}`);
        }
    }

    bytesToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            document.execCommand('copy');
            this.showToast('PEM key copied to clipboard');
        } catch (error) {
            this.showToast('Failed to copy to clipboard', true);
        }

        document.body.removeChild(textArea);
    }
}

// Initialize the converter when the page loads
const jwksConverter = new JWKSConverter();
