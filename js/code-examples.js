// 初始化代码示例标签切换
function initCodeTabs() {
    const codeTabs = document.querySelectorAll('nav.flex button');
    const codeBlock = document.querySelector('.code-block pre code');

    if (!codeTabs.length || !codeBlock) {
        console.warn('Code tabs or code block not found');
        return;
    }

    // 为代码标签添加点击事件
    codeTabs.forEach(tab => {
        tab.addEventListener('click', function () {
            // 移除其他标签的活动状态
            codeTabs.forEach(t => {
                t.classList.remove('border-primary-500', 'text-primary-400');
                t.classList.add('border-transparent', 'text-gray-400');
            });

            // 设置当前标签为活动状态
            this.classList.remove('border-transparent', 'text-gray-400');
            this.classList.add('border-primary-500', 'text-primary-400');

            // 获取所选编程语言
            const language = this.querySelector('span').textContent.toLowerCase();

            // 更新代码示例
            const currentLang = document.getElementById('language-select').value;
            updateCodeExamples(currentLang, language);
        });
    });

    // 初始化时触发第一个标签的点击
    if (codeTabs.length > 0) {
        codeTabs[0].click();
    }
}

// 获取本地化的评论文本
function getCommentTexts(lang, mode, keyLength, outputFormat) {
    return {
        title: {
            en: `AES-${mode} Encryption`,
            zh: `AES-${mode} 加密`,
            fr: `Chiffrement AES-${mode}`,
            ja: `AES-${mode} 暗号化`,
            de: `AES-${mode} Verschlüsselung`,
            ko: `AES-${mode} 암호화`
        },
        encrypt: {
            en: `Encrypt text using AES-${mode} mode`,
            zh: `使用AES-${mode}模式加密文本`,
            fr: `Chiffrer le texte en utilisant le mode AES-${mode}`,
            ja: `AES-${mode}モードでテキストを暗号化`,
            de: `Text mit AES-${mode}-Modus verschlüsseln`,
            ko: `AES-${mode} 모드를 사용하여 텍스트 암호화`
        },
        decrypt: {
            en: `Decrypt text using AES-${mode} mode`,
            zh: `使用AES-${mode}模式解密文本`,
            fr: `Déchiffrer le texte en utilisant le mode AES-${mode}`,
            ja: `AES-${mode}モードでテキストを復号化`,
            de: `Text mit AES-${mode}-Modus entschlüsseln`,
            ko: `AES-${mode} 모드를 사용하여 텍스트 복호화`
        },
        params: {
            en: "Parameters:",
            zh: "参数:",
            fr: "Paramètres:",
            ja: "パラメータ:",
            de: "Parameter:",
            ko: "매개변수:"
        },
        plaintext: {
            en: "plaintext: Text to encrypt",
            zh: "plaintext: 要加密的文本",
            fr: "plaintext: Texte à chiffrer",
            ja: "plaintext: 暗号化するテキスト",
            de: "plaintext: Zu verschlüsselnder Text",
            ko: "plaintext: 암호화할 텍스트"
        },
        ciphertext: {
            en: `ciphertext: ${outputFormat.toUpperCase()} encoded encrypted text`,
            zh: `ciphertext: ${outputFormat.toUpperCase()}编码的加密文本`,
            fr: `ciphertext: Texte chiffré encodé en ${outputFormat.toUpperCase()}`,
            ja: `ciphertext: ${outputFormat.toUpperCase()}エンコードされた暗号化テキスト`,
            de: `ciphertext: ${outputFormat.toUpperCase()}-codierter verschlüsselter Text`,
            ko: `ciphertext: ${outputFormat.toUpperCase()}로 인코딩된 암호화된 텍스트`
        },
        key: {
            en: `key: Encryption key (${keyLength / 8} bytes for AES-${keyLength})`,
            zh: `key: 加密密钥 (AES-${keyLength}需要${keyLength / 8}字节)`,
            fr: `key: Clé de chiffrement (${keyLength / 8} octets pour AES-${keyLength})`,
            ja: `key: 暗号化キー (AES-${keyLength}の場合は${keyLength / 8}バイト)`,
            de: `key: Verschlüsselungsschlüssel (${keyLength / 8} Bytes für AES-${keyLength})`,
            ko: `key: 암호화 키 (AES-${keyLength}의 경우 ${keyLength / 8}바이트)`
        },
        iv: {
            en: "iv: Initialization vector (16 bytes)",
            zh: "iv: 初始化向量 (16字节)",
            fr: "iv: Vecteur d'initialisation (16 octets)",
            ja: "iv: 初期化ベクトル (16バイト)",
            de: "iv: Initialisierungsvektor (16 Bytes)",
            ko: "iv: 초기화 벡터 (16바이트)"
        },
        returns: {
            en: "Returns:",
            zh: "返回:",
            fr: "Retourne:",
            ja: "戻り値:",
            de: "Rückgabe:",
            ko: "반환값:"
        },
        returnEncrypt: {
            en: `${outputFormat.toUpperCase()} encoded encrypted string`,
            zh: `${outputFormat.toUpperCase()}编码的加密字符串`,
            fr: `Chaîne chiffrée encodée en ${outputFormat.toUpperCase()}`,
            ja: `${outputFormat.toUpperCase()}エンコードされた暗号化文字列`,
            de: `${outputFormat.toUpperCase()}-codierte verschlüsselte Zeichenfolge`,
            ko: `${outputFormat.toUpperCase()}로 인코딩된 암호화된 문자열`
        },
        returnDecrypt: {
            en: "Decrypted string",
            zh: "解密后的字符串",
            fr: "Chaîne déchiffrée",
            ja: "復号化された文字列",
            de: "Entschlüsselte Zeichenfolge",
            ko: "복호화된 문자열"
        },
        example: {
            en: "Example usage",
            zh: "示例用法",
            fr: "Exemple d'utilisation",
            ja: "使用例",
            de: "Beispielverwendung",
            ko: "사용 예시"
        }
    };
}

// 获取本地化的示例文本
function getExampleText(lang) {
    return {
        en: "This is sensitive data to encrypt",
        zh: "这是需要加密的敏感数据",
        fr: "Ce sont des données sensibles à chiffrer",
        ja: "これは暗号化する必要のある機密データです",
        de: "Dies sind zu verschlüsselnde sensible Daten",
        ko: "이것은 암호화해야 하는 민감한 데이터입니다"
    }[lang] || "This is sensitive data to encrypt";
}

// 获取本地化的结果输出文本
function getResultText(lang, type) {
    const texts = {
        encrypted: {
            en: "Encrypted result: ",
            zh: "加密结果: ",
            fr: "Résultat chiffré: ",
            ja: "暗号化結果: ",
            de: "Verschlüsseltes Ergebnis: ",
            ko: "암호화 결과: "
        },
        decrypted: {
            en: "Decrypted result: ",
            zh: "解密结果: ",
            fr: "Résultat déchiffré: ",
            ja: "復号化結果: ",
            de: "Entschlüsseltes Ergebnis: ",
            ko: "복호화 결과: "
        }
    };

    return texts[type][lang] || texts[type]['en'];
}

// 在代码示例更新函数中支持更多参数
function updateCodeExamples(lang, codeLang) {
    const codeBlock = document.querySelector('.code-block pre code');
    if (!codeBlock) return;

    // 获取当前加密参数
    const encryptionMode = document.getElementById('encryption-mode').value;
    const paddingMode = document.getElementById('padding-mode').value;
    const keyLength = document.getElementById('key-length').value;
    const outputFormat = document.getElementById('output-format').value;

    let code = '';

    // 根据所选语言生成代码
    switch (codeLang) {
        case 'python':
            code = generatePythonCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'javascript':
            code = generateJavaScriptCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'java':
            code = generateJavaCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'go':
            code = generateGoCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'rust':
            code = generateRustCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'csharp':
            code = generateCSharpCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        case 'php':
            code = generatePHPCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
            break;
        default:
            code = generatePythonCode(lang, encryptionMode, paddingMode, keyLength, outputFormat);
    }

    // 更新代码块内容
    codeBlock.textContent = code;
    codeBlock.className = `language-${codeLang} text-gray-300`;
}

// 根据加密参数生成Python代码示例
function generatePythonCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 根据选择的输出格式设置代码
    let outputFormatCode = '';
    if (outputFormat === 'hex') {
        outputFormatCode = '.hex()';
    } else if (outputFormat === 'binary') {
        outputFormatCode = '.decode("latin-1")';
    } else {
        // 默认base64
        outputFormatCode = '.decode("utf-8")';
    }

    // 根据选择的填充模式设置代码
    let paddingImport = 'from Crypto.Util.Padding import pad, unpad';
    let paddingCode = `pad(plaintext_bytes, AES.block_size)`;
    let unpaddingCode = `unpad(decrypted_data, AES.block_size)`;

    if (paddingMode === 'no-padding') {
        paddingImport = `# ${commentTexts.noPadding}`;
        paddingCode = 'plaintext_bytes + (b"\\0" * (16 - (len(plaintext_bytes) % 16)) if len(plaintext_bytes) % 16 != 0 else b"")';
        unpaddingCode = 'decrypted_data.rstrip(b"\\0")';
    } else if (paddingMode === 'pkcs5') {
        paddingCode = `pad(plaintext_bytes, AES.block_size)`;
        unpaddingCode = `unpad(decrypted_data, AES.block_size)`;
    } else if (paddingMode === 'iso10126') {
        paddingImport = 'from Crypto.Util.Padding import pad, unpad';
        paddingCode = `pad(plaintext_bytes, AES.block_size, style='iso10126')`;
        unpaddingCode = `unpad(decrypted_data, AES.block_size, style='iso10126')`;
    }

    // 构建Python代码
    return `from Crypto.Cipher import AES
${paddingImport}
import base64
${outputFormat === 'hex' ? 'import binascii' : ''}

def encrypt_aes_${encryptionMode.toLowerCase()}(plaintext, key${needsIV ? ', iv' : ''}):
    """
    ${commentTexts.usingMode}
    
    ${commentTexts.params}:
        plaintext (str): ${commentTexts.plaintext}
        key (bytes): ${commentTexts.key}
        ${needsIV ? `iv (bytes): ${commentTexts.iv}` : ''}
        
    ${commentTexts.returns}:
        str: ${commentTexts.encodedOutput}
    """
    # ${commentTexts.convertToBytes}
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = ${paddingCode}
    
    # ${commentTexts.createCipher}
    ${encryptionMode === 'ECB'
            ? `cipher = AES.new(key, AES.MODE_${encryptionMode})`
            : encryptionMode === 'GCM'
                ? `cipher = AES.new(key, AES.MODE_${encryptionMode}, nonce=iv)`
                : `cipher = AES.new(key, AES.MODE_${encryptionMode}, iv)`}
    
    # ${commentTexts.encryptData}
    ${encryptionMode === 'GCM'
            ? `ciphertext, tag = cipher.encrypt_and_digest(padded_data)`
            : `ciphertext = cipher.encrypt(padded_data)`}
    
    # ${commentTexts.convertToFormat}
    ${outputFormat === 'base64'
            ? 'return base64.b64encode(ciphertext).decode("utf-8")'
            : outputFormat === 'hex'
                ? 'return binascii.hexlify(ciphertext).decode("utf-8")'
                : 'return ciphertext.decode("latin-1")'}

def decrypt_aes_${encryptionMode.toLowerCase()}(ciphertext, key${needsIV ? ', iv' : ''}):
    """
    ${commentTexts.usingMode.replace(/加密/g, '解密')}
    
    ${commentTexts.params}:
        ciphertext (str): ${commentTexts.encodedOutput}
        key (bytes): ${commentTexts.key}
        ${needsIV ? `iv (bytes): ${commentTexts.iv}` : ''}
        
    ${commentTexts.returns}:
        str: ${commentTexts.plaintext}
    """
    # ${commentTexts.decodeCiphertext}
    ${outputFormat === 'base64'
            ? 'ciphertext_bytes = base64.b64decode(ciphertext)'
            : outputFormat === 'hex'
                ? 'ciphertext_bytes = binascii.unhexlify(ciphertext)'
                : 'ciphertext_bytes = ciphertext.encode("latin-1")'}
    
    # ${commentTexts.createCipher}
    ${encryptionMode === 'ECB'
            ? `cipher = AES.new(key, AES.MODE_${encryptionMode})`
            : encryptionMode === 'GCM'
                ? `cipher = AES.new(key, AES.MODE_${encryptionMode}, nonce=iv)`
                : `cipher = AES.new(key, AES.MODE_${encryptionMode}, iv)`}
    
    # ${commentTexts.decryptAndUnpad}
    ${encryptionMode === 'GCM'
            ? `decrypted_data = cipher.decrypt(ciphertext_bytes)`
            : `decrypted_data = cipher.decrypt(ciphertext_bytes)`}
    unpadded_data = ${unpaddingCode}
    
    # ${commentTexts.convertToString}
    return unpadded_data.decode('utf-8')

# ${commentTexts.exampleUsage}
key = b'${'0'.repeat(keyLength / 8)}'  # ${commentTexts.bitKey}
${needsIV ? `iv = b'${'0'.repeat(16)}'  # ${commentTexts.byteIv}` : ''}

# ${commentTexts.encryptExample}
plaintext = "${exampleText}"
encrypted = encrypt_aes_${encryptionMode.toLowerCase()}(plaintext, key${needsIV ? ', iv' : ''})
print(f"${encryptedResult}{encrypted}")

# ${commentTexts.decryptExample}
decrypted = decrypt_aes_${encryptionMode.toLowerCase()}(encrypted, key${needsIV ? ', iv' : ''})
print(f"${decryptedResult}{decrypted}")`;
}

// 生成JavaScript AES加密代码示例
function generateJavaScriptCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 根据加密模式设置CryptoJS配置
    const modeMap = {
        'CBC': 'CryptoJS.mode.CBC',
        'ECB': 'CryptoJS.mode.ECB',
        'CFB': 'CryptoJS.mode.CFB',
        'OFB': 'CryptoJS.mode.OFB',
        'CTR': 'CryptoJS.mode.CTR',
        'GCM': 'CryptoJS.mode.GCM'
    };
    const mode = modeMap[encryptionMode] || 'CryptoJS.mode.CBC';

    // 根据填充模式设置CryptoJS配置
    const paddingMap = {
        'pkcs7': 'CryptoJS.pad.Pkcs7',
        'pkcs5': 'CryptoJS.pad.Pkcs7', // PKCS5和PKCS7在JS中相同
        'iso10126': 'CryptoJS.pad.Iso10126',
        'ansix923': 'CryptoJS.pad.AnsiX923',
        'no-padding': 'CryptoJS.pad.NoPadding'
    };
    const padding = paddingMap[paddingMode] || 'CryptoJS.pad.Pkcs7';

    // 根据输出格式设置转换
    let outputFormatCode = '';
    if (outputFormat === 'hex') {
        outputFormatCode = '.toString(CryptoJS.enc.Hex)';
    } else if (outputFormat === 'binary') {
        outputFormatCode = '.toString(CryptoJS.enc.Latin1)';
    } else {
        // 默认base64
        outputFormatCode = '.toString(CryptoJS.enc.Base64)';
    }

    // 构建JavaScript代码
    return `/**
 * ${commentTexts.usingMode}
 * 
 * @param {string} plaintext - ${commentTexts.plaintext}
 * @param {string} key - ${commentTexts.key}
 * ${needsIV ? `* @param {string} iv - ${commentTexts.iv}\n` : ''}* @returns {string} - ${commentTexts.encodedOutput}
 */
function encryptAes${encryptionMode}(plaintext, key${needsIV ? ', iv' : ''}) {
    // ${commentTexts.createCipher}
    const keyBytes = CryptoJS.enc.Utf8.parse(key);
    ${needsIV ? `const ivBytes = CryptoJS.enc.Utf8.parse(iv);` : ''}

    // ${commentTexts.encryptData}
    const encrypted = CryptoJS.AES.encrypt(
        plaintext, 
        keyBytes, 
        {
            mode: ${mode},
            padding: ${padding},
            ${needsIV ? 'iv: ivBytes,' : ''}
            keySize: ${keyLength / 32} // 密钥大小，128位=4，192位=6，256位=8
        }
    );

    // ${commentTexts.convertToFormat}
    return encrypted${outputFormatCode};
}

/**
 * ${commentTexts.usingMode.replace(/加密/g, '解密')}
 * 
 * @param {string} ciphertext - ${commentTexts.encodedOutput}
 * @param {string} key - ${commentTexts.key}
 * ${needsIV ? `* @param {string} iv - ${commentTexts.iv}\n` : ''}* @returns {string} - ${commentTexts.plaintext}
 */
function decryptAes${encryptionMode}(ciphertext, key${needsIV ? ', iv' : ''}) {
    // ${commentTexts.createCipher}
    const keyBytes = CryptoJS.enc.Utf8.parse(key);
    ${needsIV ? `const ivBytes = CryptoJS.enc.Utf8.parse(iv);` : ''}

    // ${commentTexts.decodeCiphertext}
    let cipherParams = null;
    ${outputFormat === 'base64'
            ? 'cipherParams = { ciphertext: CryptoJS.enc.Base64.parse(ciphertext) };'
            : outputFormat === 'hex'
                ? 'cipherParams = { ciphertext: CryptoJS.enc.Hex.parse(ciphertext) };'
                : 'cipherParams = { ciphertext: CryptoJS.enc.Latin1.parse(ciphertext) };'}

    // ${commentTexts.decryptAndUnpad}
    const decrypted = CryptoJS.AES.decrypt(
        cipherParams, 
        keyBytes, 
        {
            mode: ${mode},
            padding: ${padding},
            ${needsIV ? 'iv: ivBytes,' : ''}
            keySize: ${keyLength / 32} // 密钥大小，128位=4，192位=6，256位=8
        }
    );

    // ${commentTexts.convertToString}
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// ${commentTexts.exampleUsage}
// 注意：在实际使用中，应生成随机密钥和IV，并使用加密方法安全存储
const key = "${'0'.repeat(keyLength / 8)}"; // ${commentTexts.bitKey}
${needsIV ? `const iv = "${'0'.repeat(16)}"; // ${commentTexts.byteIv}` : ''}

// ${commentTexts.encryptExample}
const plaintext = "${exampleText}";
const encrypted = encryptAes${encryptionMode}(plaintext, key${needsIV ? ', iv' : ''});
console.log("${encryptedResult}" + encrypted);

// ${commentTexts.decryptExample}
const decrypted = decryptAes${encryptionMode}(encrypted, key${needsIV ? ', iv' : ''});
console.log("${decryptedResult}" + decrypted);`;
}

// 生成Java AES加密代码示例
function generateJavaCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 获取Java中使用的填充模式字符串
    const paddingMap = {
        'pkcs7': 'PKCS5Padding', // Java中使用PKCS5Padding实现PKCS7
        'pkcs5': 'PKCS5Padding',
        'iso10126': 'ISO10126Padding',
        'ansix923': 'ISO10126Padding', // Java没有直接支持ANSI X.923，使用近似替代
        'no-padding': 'NoPadding'
    };
    const paddingString = paddingMap[paddingMode] || 'PKCS5Padding';

    // 将Java中AES的加密模式名称
    const modeMap = {
        'CBC': 'CBC',
        'ECB': 'ECB',
        'CFB': 'CFB',
        'OFB': 'OFB',
        'CTR': 'CTR',
        'GCM': 'GCM'
    };
    const javaMode = modeMap[encryptionMode] || 'CBC';

    // 构建完整的变换字符串
    const transformation = `AES/${javaMode}/${paddingString}`;

    // 构建Java代码
    return `import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ${commentTexts.usingMode}
 */
public class AES${encryptionMode}Util {

    /**
     * ${commentTexts.encryptData}
     * 
     * @param plaintext ${commentTexts.plaintext}
     * @param key ${commentTexts.key}
     * ${needsIV ? `* @param iv ${commentTexts.iv}\n` : ''}* @return ${commentTexts.encodedOutput}
     * @throws Exception 如果加密过程中发生错误
     */
    public static String encrypt(String plaintext, String key${needsIV ? ', String iv' : ''}) throws Exception {
        // ${commentTexts.convertToBytes}
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        
        // 确保密钥长度正确
        byte[] keyBytesFixed = new byte[${keyLength / 8}];
        System.arraycopy(keyBytes, 0, keyBytesFixed, 0, Math.min(keyBytes.length, keyBytesFixed.length));
        
        // ${commentTexts.createCipher}
        Key secretKey = new SecretKeySpec(keyBytesFixed, "AES");
        Cipher cipher = Cipher.getInstance("${transformation}");
        
        ${needsIV ? `// 初始化向量
        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytesFixed = new byte[16]; // AES块大小为16字节
        System.arraycopy(ivBytes, 0, ivBytesFixed, 0, Math.min(ivBytes.length, ivBytesFixed.length));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytesFixed);
        
        // 初始化加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);`
            : `// 初始化加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);`}
        
        // ${commentTexts.encryptData}
        byte[] encryptedBytes = cipher.doFinal(plaintextBytes);
        
        // ${commentTexts.convertToFormat}
        ${outputFormat === 'base64'
            ? 'return Base64.getEncoder().encodeToString(encryptedBytes);'
            : outputFormat === 'hex'
                ? `StringBuilder hexString = new StringBuilder(2 * encryptedBytes.length);
        for (byte b : encryptedBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();`
                : 'return new String(encryptedBytes, StandardCharsets.ISO_8859_1); // 二进制输出'
        }
    }
    
    /**
     * ${commentTexts.usingMode.replace(/加密/g, '解密')}
     * 
     * @param ciphertext ${commentTexts.encodedOutput}
     * @param key ${commentTexts.key}
     * ${needsIV ? `* @param iv ${commentTexts.iv}\n` : ''}* @return ${commentTexts.plaintext}
     * @throws Exception 如果解密过程中发生错误
     */
    public static String decrypt(String ciphertext, String key${needsIV ? ', String iv' : ''}) throws Exception {
        // ${commentTexts.decodeCiphertext}
        byte[] ciphertextBytes;
        ${outputFormat === 'base64'
            ? 'ciphertextBytes = Base64.getDecoder().decode(ciphertext);'
            : outputFormat === 'hex'
                ? `
        // 将十六进制字符串转换为字节数组
        ciphertextBytes = new byte[ciphertext.length() / 2];
        for (int i = 0; i < ciphertextBytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(ciphertext.substring(index, index + 2), 16);
            ciphertextBytes[i] = (byte) j;
        }`
                : `
        // 直接将字符串转换为字节
        ciphertextBytes = ciphertext.getBytes(StandardCharsets.ISO_8859_1); // 二进制输入`}
        
        // 准备密钥
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytesFixed = new byte[${keyLength / 8}];
        System.arraycopy(keyBytes, 0, keyBytesFixed, 0, Math.min(keyBytes.length, keyBytesFixed.length));
        Key secretKey = new SecretKeySpec(keyBytesFixed, "AES");
        
        // ${commentTexts.createCipher}
        Cipher cipher = Cipher.getInstance("${transformation}");
        
        ${needsIV ? `// 初始化向量
        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytesFixed = new byte[16]; // AES块大小为16字节
        System.arraycopy(ivBytes, 0, ivBytesFixed, 0, Math.min(ivBytes.length, ivBytesFixed.length));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytesFixed);
        
        // 初始化解密模式
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);`
            : `// 初始化解密模式
        cipher.init(Cipher.DECRYPT_MODE, secretKey);`}
        
        // ${commentTexts.decryptAndUnpad}
        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
        
        // ${commentTexts.convertToString}
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    
    /**
     * ${commentTexts.exampleUsage}
     */
    public static void main(String[] args) {
        try {
            // ${commentTexts.bitKey}
            String key = "${'0'.repeat(keyLength / 8)}";
            ${needsIV ? `// ${commentTexts.byteIv}
            String iv = "${'0'.repeat(16)}";` : ''}
            
            // ${commentTexts.encryptExample}
            String plaintext = "${exampleText}";
            String encrypted = encrypt(plaintext, key${needsIV ? ', iv' : ''});
            System.out.println("${encryptedResult}" + encrypted);
            
            // ${commentTexts.decryptExample}
            String decrypted = decrypt(encrypted, key${needsIV ? ', iv' : ''});
            System.out.println("${decryptedResult}" + decrypted);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}`;
}

// 生成Go语言AES加密代码示例
function generateGoCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充",
        errorHandling: "错误处理"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 根据加密模式选择不同的依赖和实现
    let dependencies = '';
    let imports = '';

    // 设置依赖和导入
    if (encryptionMode === 'GCM') {
        dependencies = `aes-gcm = "0.10.1"
base64 = "0.13.0"
${outputFormat === 'hex' ? 'hex = "0.4.3"\n' : ''}`;
        imports = `use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes128Gcm, Aes192Gcm, Aes256Gcm, Nonce
};
use std::str;`;
    } else {
        dependencies = `aes = "0.8.2"
block-modes = "0.9.0"
${needsIV ? 'block-padding = "0.3.2"\n' : ''}base64 = "0.13.0"
${outputFormat === 'hex' ? 'hex = "0.4.3"\n' : ''}`;

        imports = `use aes::{Aes128, Aes192, Aes256};
use block_modes::{BlockMode, Cbc, Ecb, ${encryptionMode === 'CFB' ? 'Cfb, ' : ''}${encryptionMode === 'OFB' ? 'Ofb, ' : ''}${encryptionMode === 'CTR' ? 'Ctr, ' : ''}block_padding::${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}};\n`;

        if (encryptionMode === 'CBC') {
            imports += `type Aes128Cbc = Cbc<Aes128, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes192Cbc = Cbc<Aes192, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes256Cbc = Cbc<Aes256, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;`;
        } else if (encryptionMode === 'ECB') {
            imports += `type Aes128Ecb = Ecb<Aes128, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes192Ecb = Ecb<Aes192, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes256Ecb = Ecb<Aes256, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;`;
        } else if (encryptionMode === 'CFB') {
            imports += `type Aes128Cfb = Cfb<Aes128, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes192Cfb = Cfb<Aes192, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes256Cfb = Cfb<Aes256, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;`;
        } else if (encryptionMode === 'OFB') {
            imports += `type Aes128Ofb = Ofb<Aes128, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes192Ofb = Ofb<Aes192, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes256Ofb = Ofb<Aes256, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;`;
        } else if (encryptionMode === 'CTR') {
            imports += `type Aes128Ctr = Ctr<Aes128, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes192Ctr = Ctr<Aes192, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;
type Aes256Ctr = Ctr<Aes256, ${paddingMode === 'pkcs7' || paddingMode === 'pkcs5' ? 'Pkcs7' : paddingMode === 'no-padding' ? 'NoPadding' : 'Iso10126'}>;`;
        }
    }

    if (outputFormat === 'base64') {
        imports += `\nuse base64::{encode, decode};`;
    } else if (outputFormat === 'hex') {
        imports += `\nuse hex::{encode as hex_encode, decode as hex_decode};`;
    }

    // 构建Cargo.toml
    const cargoToml = `[package]
name = "aes_encryption_example"
version = "0.1.0"
edition = "2021"

[dependencies]
${dependencies}`;

    // 构建主要代码
    let mainCode = `//! ${commentTexts.usingMode}
//! 
//! ${commentTexts.exampleUsage}

${imports}
use std::error::Error;

/// ${commentTexts.usingMode}
///
/// ${commentTexts.params}:
/// * plaintext - ${commentTexts.plaintext}
/// * key - ${commentTexts.key}
${needsIV ? `/// * iv - ${commentTexts.iv}\n` : ''}///
/// ${commentTexts.returns} ${commentTexts.encodedOutput}
pub fn encrypt(plaintext: &str, key: &[u8]${needsIV ? ', iv: &[u8]' : ''}) -> Result<String, Box<dyn Error>> {
    // ${commentTexts.convertToBytes}
    let plaintext_bytes = plaintext.as_bytes();
    
    // ${commentTexts.createCipher}`;

    // 根据加密模式实现不同的加密逻辑
    if (encryptionMode === 'GCM') {
        mainCode += `
    let cipher = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)?,
        24 => Aes192Gcm::new_from_slice(key)?,
        32 => Aes256Gcm::new_from_slice(key)?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    // 创建随机数（nonce）
    let nonce = Nonce::from_slice(&iv[..12]); // GCM需要12字节的nonce
    
    // ${commentTexts.encryptData}
    let ciphertext = cipher.encrypt(nonce, plaintext_bytes.as_ref())
        .map_err(|err| format!("Encryption failed: {}", err))?;`;
    } else {
        mainCode += `
    // 确保密钥长度正确
    if key.len() != ${keyLength / 8} {
        return Err("Invalid key length. Must be ${keyLength / 8} bytes".into());
    }
    ${needsIV ? `
    // 确保IV长度正确
    if iv.len() != 16 {
        return Err("Invalid IV length. Must be 16 bytes".into());
    }` : ''}
    
    // ${commentTexts.encryptData}`;

        if (encryptionMode === 'CBC') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);`;
        } else if (encryptionMode === 'ECB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ecb::new_from_slices(key, &[])?,
        24 => Aes192Ecb::new_from_slices(key, &[])?,
        32 => Aes256Ecb::new_from_slices(key, &[])?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);`;
        } else if (encryptionMode === 'CFB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);`;
        } else if (encryptionMode === 'OFB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);`;
        } else if (encryptionMode === 'CTR') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);`;
        }
    }

    // 添加输出格式转换
    mainCode += `
    
    // ${commentTexts.convertToFormat}
    `;

    if (outputFormat === 'base64') {
        mainCode += `Ok(encode(&ciphertext))`;
    } else if (outputFormat === 'hex') {
        mainCode += `Ok(hex_encode(&ciphertext))`;
    } else { // 二进制
        mainCode += `Ok(String::from_utf8_lossy(&ciphertext).into_owned())`;
    }

    // 添加解密函数
    mainCode += `
}

/// ${commentTexts.usingMode.replace(/加密/g, '解密')}
///
/// ${commentTexts.params}:
/// * ciphertext - ${commentTexts.encodedOutput}
/// * key - ${commentTexts.key}
${needsIV ? `/// * iv - ${commentTexts.iv}\n` : ''}///
/// ${commentTexts.returns} ${commentTexts.plaintext}
pub fn decrypt(ciphertext: &str, key: &[u8]${needsIV ? ', iv: &[u8]' : ''}) -> Result<String, Box<dyn Error>> {
    // ${commentTexts.decodeCiphertext}
    ${outputFormat === 'base64'
            ? 'let ciphertext_bytes = decode(ciphertext)?;'
            : outputFormat === 'hex'
                ? 'let ciphertext_bytes = hex_decode(ciphertext)?;'
                : 'let ciphertext_bytes = ciphertext.as_bytes();'}
    
    // ${commentTexts.createCipher}`;

    // 根据加密模式实现不同的解密逻辑
    if (encryptionMode === 'GCM') {
        mainCode += `
    let cipher = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)?,
        24 => Aes192Gcm::new_from_slice(key)?,
        32 => Aes256Gcm::new_from_slice(key)?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    // 使用相同的随机数（nonce）
    let nonce = Nonce::from_slice(&iv[..12]); // GCM需要12字节的nonce
    
    // ${commentTexts.decryptAndUnpad}
    let plaintext = cipher.decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|err| format!("Decryption failed: {}", err))?;`;
    } else {
        mainCode += `
    // 确保密钥长度正确
    if key.len() != ${keyLength / 8} {
        return Err("Invalid key length. Must be ${keyLength / 8} bytes".into());
    }
    ${needsIV ? `
    // 确保IV长度正确
    if iv.len() != 16 {
        return Err("Invalid IV length. Must be 16 bytes".into());
    }` : ''}
    
    // ${commentTexts.decryptAndUnpad}`;

        if (encryptionMode === 'CBC') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Cbc::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;`;
        } else if (encryptionMode === 'ECB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ecb::new_from_slices(key, &[])?,
        24 => Aes192Ecb::new_from_slices(key, &[])?,
        32 => Aes256Ecb::new_from_slices(key, &[])?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;`;
        } else if (encryptionMode === 'CFB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Cfb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;`;
        } else if (encryptionMode === 'OFB') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Ofb::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;`;
        } else if (encryptionMode === 'CTR') {
            mainCode += `
    let cipher = match key.len() {
        16 => Aes128Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        24 => Aes192Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        32 => Aes256Ctr::new_from_slices(key, ${needsIV ? 'iv' : '&[0u8; 16]'})?,
        _ => return Err("Invalid key length. Must be 16, 24, or 32 bytes".into())
    };
    
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;`;
        }
    }

    // 处理填充
    if (needsPadding && encryptionMode !== 'CTR' && encryptionMode !== 'GCM') {
        mainCode += `
    
    // 去除PKCS7填充
    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return Err(err.into())
    }`;
    } else if (paddingMode === 'no-padding' && encryptionMode !== 'CTR' && encryptionMode !== 'GCM') {
        mainCode += `
    
    // 去除空字节填充
    plaintext = bytes.TrimRight(plaintext, "\\x00")`;
    }

    mainCode += `
    
    // ${commentTexts.convertToString}
    Ok(String::from_utf8(plaintext)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    // ${commentTexts.exampleUsage}
    let key = ${keyLength === 128 ? '[0u8; 16]' : keyLength === 192 ? '[0u8; 24]' : '[0u8; 32]'}; // ${commentTexts.bitKey}
    ${needsIV ? `let iv = [0u8; 16]; // ${commentTexts.byteIv}` : ''}
    
    // ${commentTexts.encryptExample}
    let plaintext = "${exampleText}";
    let encrypted = encrypt(plaintext, &key${needsIV ? ', &iv' : ''})?;
    println!("${encryptedResult}{}", encrypted);
    
    // ${commentTexts.decryptExample}
    let decrypted = decrypt(&encrypted, &key${needsIV ? ', &iv' : ''})?;
    println!("${decryptedResult}{}", decrypted);
    
    Ok(())
}`;

    // 返回Cargo.toml和主要代码
    return `// Cargo.toml
/*
${cargoToml}
*/

// src/main.rs
${mainCode}`;
}

// 生成Python代码、JavaScript代码、Java代码等函数，保持与原文件相同
// 这里每个函数的实现都很长，所以我只列出了函数名，实际实现需要与原文件一致
function generateCSharpCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 设置C#中的加密模式和填充方式
    const csharpCipherModes = {
        'CBC': 'CipherMode.CBC',
        'ECB': 'CipherMode.ECB',
        'CFB': 'CipherMode.CFB',
        'OFB': 'CipherMode.OFB', // 注意：C#可能不直接支持OFB
        'CTR': 'CipherMode.CTS', // 注意：C#没有CTR，用CTS代替
        'GCM': 'CipherMode.CBC' // 注意：C#没有内置的GCM支持，我们使用CBC代替
    };

    const csharpPaddingModes = {
        'pkcs7': 'PaddingMode.PKCS7',
        'pkcs5': 'PaddingMode.PKCS7', // PKCS5等同于PKCS7
        'iso10126': 'PaddingMode.ISO10126',
        'ansix923': 'PaddingMode.ANSIX923',
        'no-padding': 'PaddingMode.None'
    };

    const cipherMode = csharpCipherModes[encryptionMode] || 'CipherMode.CBC';
    const paddingType = csharpPaddingModes[paddingMode] || 'PaddingMode.PKCS7';

    // 构建C#代码
    return `using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// ${commentTexts.usingMode}
/// </summary>
public class AES${encryptionMode}Util
{
    /// <summary>
    /// ${commentTexts.encryptData}
    /// </summary>
    /// <param name="plaintext">${commentTexts.plaintext}</param>
    /// <param name="key">${commentTexts.key}</param>
    ${needsIV ? `/// <param name="iv">${commentTexts.iv}</param>` : ''}
    /// <returns>${commentTexts.encodedOutput}</returns>
    public static string Encrypt(string plaintext, byte[] key${needsIV ? ', byte[] iv' : ''})
    {
        // ${commentTexts.convertToBytes}
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        
        // 验证密钥长度
        if (key.Length != ${keyLength / 8})
        {
            throw new ArgumentException($"Key must be ${keyLength / 8} bytes for AES-${keyLength}");
        }
        
        ${needsIV ? `// 验证IV长度
        if (iv.Length != 16)
        {
            throw new ArgumentException("IV must be 16 bytes");
        }
        ` : ''}
        // ${commentTexts.createCipher}
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = ${keyLength};
            aes.Key = key;
            ${needsIV ? 'aes.IV = iv;' : '// ECB模式不需要IV'}
            aes.Mode = ${cipherMode};
            aes.Padding = ${paddingType};
            
            // ${commentTexts.encryptData}
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
                
                // ${commentTexts.convertToFormat}
                byte[] cipherBytes = memoryStream.ToArray();
                ${outputFormat === 'base64'
            ? 'return Convert.ToBase64String(cipherBytes);'
            : outputFormat === 'hex'
                ? `
                // 将字节数组转换为十六进制字符串
                StringBuilder hex = new StringBuilder(cipherBytes.Length * 2);
                foreach (byte b in cipherBytes)
                {
                    hex.AppendFormat("{0:x2}", b);
                }
                return hex.ToString();`
                : `
                // 直接将字节转换为字符串
                return Encoding.Latin1.GetString(cipherBytes);`}
            }
        }
    }
    
    /// <summary>
    /// ${commentTexts.usingMode.replace(/加密/g, '解密')}
    /// </summary>
    /// <param name="ciphertext">${commentTexts.encodedOutput}</param>
    /// <param name="key">${commentTexts.key}</param>
    ${needsIV ? `/// <param name="iv">${commentTexts.iv}</param>` : ''}
    /// <returns>${commentTexts.plaintext}</returns>
    public static string Decrypt(string ciphertext, byte[] key${needsIV ? ', byte[] iv' : ''})
    {
        // ${commentTexts.decodeCiphertext}
        byte[] cipherBytes;
        ${outputFormat === 'base64'
            ? 'cipherBytes = Convert.FromBase64String(ciphertext);'
            : outputFormat === 'hex'
                ? `
        // 将十六进制字符串转换为字节数组
        cipherBytes = new byte[ciphertext.Length / 2];
        for (int i = 0; i < cipherBytes.Length; i++)
        {
            cipherBytes[i] = Convert.ToByte(ciphertext.Substring(i * 2, 2), 16);
        }`
                : `
        // 直接将字符串转换为字节
        cipherBytes = Encoding.Latin1.GetBytes(ciphertext);`}
        
        // 验证密钥长度
        if (key.Length != ${keyLength / 8})
        {
            throw new ArgumentException($"Key must be ${keyLength / 8} bytes for AES-${keyLength}");
        }
        
        ${needsIV ? `// 验证IV长度
        if (iv.Length != 16)
        {
            throw new ArgumentException("IV must be 16 bytes");
        }
        ` : ''}
        // ${commentTexts.decryptAndUnpad}
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = ${keyLength};
            aes.Key = key;
            ${needsIV ? 'aes.IV = iv;' : '// ECB模式不需要IV'}
            aes.Mode = ${cipherMode};
            aes.Padding = ${paddingType};
            
            using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
            {
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream plainMemory = new MemoryStream())
                        {
                            byte[] buffer = new byte[1024];
                            int count;
                            while ((count = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                plainMemory.Write(buffer, 0, count);
                            }
                            
                            // ${commentTexts.convertToString}
                            byte[] plainBytes = plainMemory.ToArray();
                            return Encoding.UTF8.GetString(plainBytes);
                        }
                    }
                }
            }
        }
    }
    
    /// <summary>
    /// ${commentTexts.exampleUsage}
    /// </summary>
    public static void Main()
    {
        try
        {
            // ${commentTexts.bitKey}
            byte[] key = new byte[${keyLength / 8}];
            ${needsIV ? `// ${commentTexts.byteIv}
            byte[] iv = new byte[16];` : ''}
            
            // ${commentTexts.encryptExample}
            string plaintext = "${exampleText}";
            string encrypted = Encrypt(plaintext, key${needsIV ? ', iv' : ''});
            Console.WriteLine("${encryptedResult}" + encrypted);
            
            // ${commentTexts.decryptExample}
            string decrypted = Decrypt(encrypted, key${needsIV ? ', iv' : ''});
            Console.WriteLine("${decryptedResult}" + decrypted);
        }
        catch (Exception ex)
        {
            Console.WriteLine("错误: " + ex.Message);
        }
    }
}`;
}

function generatePHPCode(lang, encryptionMode, paddingMode, keyLength, outputFormat) {
    // 根据语言获取本地化文本
    const exampleText = translations[lang].enterText || "This is sensitive data to be encrypted";
    const encryptedResult = translations[lang].encryptedResult || "Encrypted: ";
    const decryptedResult = translations[lang].decryptedResult || "Decrypted: ";

    // 替换翻译文本中的变量占位符
    function replaceVars(text) {
        return text
            .replace(/\${mode}/g, encryptionMode)
            .replace(/\${keySize}/g, keyLength / 8)
            .replace(/\${keyLength}/g, keyLength)
            .replace(/\${format}/g, outputFormat === 'base64'
                ? 'Base64'
                : outputFormat === 'hex'
                    ? (lang === 'zh' ? '十六进制' : 'Hexadecimal')
                    : (lang === 'zh' ? '二进制' : 'Binary'));
    }

    // 多语言注释文本
    const commentTexts = {
        usingMode: replaceVars(translations[lang].usingMode || `使用AES-${encryptionMode}模式加密文本`),
        params: translations[lang].params || "参数",
        plaintext: translations[lang].plaintextParam || "要加密的文本",
        key: replaceVars(translations[lang].keyParam || `密钥 (${keyLength / 8} 字节，对应AES-${keyLength})`),
        iv: translations[lang].ivParam || "初始化向量 (16 字节)",
        returns: translations[lang].returns || "返回",
        encodedOutput: replaceVars(translations[lang].encodedOutput ||
            `${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的加密文本`),
        convertToBytes: translations[lang].convertToBytes || "将文本转换为字节并填充",
        createCipher: replaceVars(translations[lang].createCipher || `创建AES密码对象，使用${encryptionMode}模式`),
        encryptData: translations[lang].encryptData || "加密数据",
        convertToFormat: replaceVars(translations[lang].convertToFormat ||
            `转换为${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}格式`),
        decodeCiphertext: replaceVars(translations[lang].decodeCiphertext ||
            `将${outputFormat === 'base64' ? 'Base64' : outputFormat === 'hex' ? '十六进制' : '二进制'}编码的密文转换为字节`),
        decryptAndUnpad: translations[lang].decryptAndUnpad || "解密并去除填充",
        convertToString: translations[lang].convertToString || "将解密后的字节转换为字符串",
        exampleUsage: translations[lang].exampleUsage || "示例使用",
        bitKey: replaceVars(translations[lang].bitKey || `${keyLength}位密钥`),
        byteIv: translations[lang].byteIv || "16字节初始化向量",
        encryptExample: translations[lang].encryptExample || "加密示例",
        decryptExample: translations[lang].decryptExample || "解密示例",
        noPadding: translations[lang].noPadding || "不使用填充"
    };

    // 确定是否需要IV
    const needsIV = ['CBC', 'CFB', 'OFB', 'CTR', 'GCM'].includes(encryptionMode);

    // 获取PHP加密方法字符串
    const phpMethod = encryptionMode === 'GCM'
        ? 'aes-' + keyLength + '-gcm'
        : 'aes-' + keyLength + '-' + encryptionMode.toLowerCase();

    // 处理填充（PHP在openssl_encrypt中处理）
    const padding = paddingMode === 'no-padding' ? 'OPENSSL_ZERO_PADDING' : '0';

    // 构建PHP代码
    return `<?php
/**
 * ${commentTexts.usingMode}
 *
 * ${commentTexts.params}:
 * @param string $plaintext ${commentTexts.plaintext}
 * @param string $key ${commentTexts.key}
 * ${needsIV ? `* @param string $iv ${commentTexts.iv}\n` : ''}* @return string ${commentTexts.encodedOutput}
 */
function aes${encryptionMode}Encrypt($plaintext, $key${needsIV ? ', $iv' : ''}) {
    // ${commentTexts.convertToBytes}
    $key = str_pad($key, ${keyLength / 8}, '\\0', STR_PAD_RIGHT);
    
    ${needsIV ? `// 确保IV长度为16字节
    $iv = str_pad($iv, 16, '\\0', STR_PAD_RIGHT);
    ` : ''}
    // ${commentTexts.createCipher}
    $method = '${phpMethod}';
    
    // ${commentTexts.encryptData}
    ${paddingMode === 'no-padding' ?
            `// 使用无填充模式，需要手动填充到块大小
    $blockSize = 16; // AES块大小为16字节
    $pad = $blockSize - (strlen($plaintext) % $blockSize);
    if ($pad < $blockSize) {
        $plaintext = str_pad($plaintext, strlen($plaintext) + $pad, "\\0");
    }
    ` : ''}
    $options = ${padding};
    ${encryptionMode === 'GCM' ?
            `$tag = ''; // 存储认证标签
    $aad = ''; // 附加验证数据（可选）
    $ciphertext = openssl_encrypt($plaintext, $method, $key, $options, $iv, $tag, $aad, 16);` :
            `$ciphertext = openssl_encrypt($plaintext, $method, $key, $options${needsIV ? ', $iv' : ''});`}
    
    // ${commentTexts.convertToFormat}
    ${outputFormat === 'base64' ?
            '// 默认已经是Base64格式，不需要额外转换' :
            outputFormat === 'hex' ?
                '$ciphertext = bin2hex(base64_decode($ciphertext));' :
                '$ciphertext = base64_decode($ciphertext); // 转为二进制'}
    
    return $ciphertext;
}

/**
 * ${commentTexts.usingMode.replace(/加密/g, '解密')}
 *
 * ${commentTexts.params}:
 * @param string $ciphertext ${commentTexts.encodedOutput}
 * @param string $key ${commentTexts.key}
 * ${needsIV ? `* @param string $iv ${commentTexts.iv}\n` : ''}* @return string ${commentTexts.plaintext}
 */
function aes${encryptionMode}Decrypt($ciphertext, $key${needsIV ? ', $iv' : ''}) {
    // ${commentTexts.decodeCiphertext}
    ${outputFormat === 'base64' ?
            '// 输入已经是Base64格式，不需要转换' :
            outputFormat === 'hex' ?
                '$ciphertext = base64_encode(hex2bin($ciphertext));' :
                '$ciphertext = base64_encode($ciphertext); // 转回base64以便解密'}
    
    // ${commentTexts.createCipher}
    $key = str_pad($key, ${keyLength / 8}, '\\0', STR_PAD_RIGHT);
    ${needsIV ? `
    // 确保IV长度为16字节
    $iv = str_pad($iv, 16, '\\0', STR_PAD_RIGHT);` : ''}
    
    $method = '${phpMethod}';
    $options = ${padding};
    
    // ${commentTexts.decryptAndUnpad}
    ${encryptionMode === 'GCM' ?
            `$tag = ''; // 应该从加密过程中获取认证标签
    $aad = ''; // 附加验证数据（可选）
    $plaintext = openssl_decrypt($ciphertext, $method, $key, $options, $iv, $tag, $aad);` :
            `$plaintext = openssl_decrypt($ciphertext, $method, $key, $options${needsIV ? ', $iv' : ''});`}
    
    // 如果使用了零填充，则需要移除尾部的空字节
    ${paddingMode === 'no-padding' ?
            `$plaintext = rtrim($plaintext, "\\0");` : ''}
    
    return $plaintext;
}

// ${commentTexts.exampleUsage}
// ${commentTexts.bitKey}
$key = '${new Array(keyLength / 8 + 1).join('0')}';
${needsIV ? `// ${commentTexts.byteIv}
$iv = '${new Array(17).join('0')}';` : ''}

// ${commentTexts.encryptExample}
$plaintext = "${exampleText}";
$encrypted = aes${encryptionMode}Encrypt($plaintext, $key${needsIV ? ', $iv' : ''});
echo "${encryptedResult}" . $encrypted . PHP_EOL;

// ${commentTexts.decryptExample}
$decrypted = aes${encryptionMode}Decrypt($encrypted, $key${needsIV ? ', $iv' : ''});
echo "${decryptedResult}" . $decrypted . PHP_EOL;
?>`;
} 