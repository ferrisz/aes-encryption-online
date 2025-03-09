document.addEventListener('DOMContentLoaded', function () {
    // 语言切换功能
    initLanguageSelector();

    // 主题切换功能
    initThemeToggle();

    // 复制按钮功能
    initCopyButtons();

    // 加密解密核心功能
    initCryptoFunctions();

    // 初始化代码示例标签切换
    initCodeTabs();

    // 更新加密信息区域
    updateEncryptionInfo();

    // 添加参数下拉菜单的change事件
    document.getElementById('encryption-mode').addEventListener('change', updateEncryptionInfo);
    document.getElementById('padding-mode').addEventListener('change', updateEncryptionInfo);
    document.getElementById('key-length').addEventListener('change', updateEncryptionInfo);
    document.getElementById('output-format').addEventListener('change', updateEncryptionInfo);
});

// 更新加密信息区域
function updateEncryptionInfo() {
    const encryptionModeSelect = document.getElementById('encryption-mode');
    const paddingModeSelect = document.getElementById('padding-mode');
    const keyLengthSelect = document.getElementById('key-length');
    const outputFormatSelect = document.getElementById('output-format');

    if (!encryptionModeSelect || !paddingModeSelect || !keyLengthSelect || !outputFormatSelect) {
        console.warn('One or more encryption parameter selects not found');
        return;
    }

    const infoContainers = document.querySelectorAll('.grid.grid-cols-2.gap-4 .text-sm');

    if (infoContainers.length >= 4) {
        // 使用选中选项的文本内容
        infoContainers[0].textContent = encryptionModeSelect.options[encryptionModeSelect.selectedIndex].textContent;
        infoContainers[1].textContent = paddingModeSelect.options[paddingModeSelect.selectedIndex].textContent;
        infoContainers[2].textContent = keyLengthSelect.options[keyLengthSelect.selectedIndex].textContent;
        infoContainers[3].textContent = outputFormatSelect.options[outputFormatSelect.selectedIndex].textContent;
    }
}

// 初始化语言选择器功能
function initLanguageSelector() {
    const languageSelect = document.getElementById('language-select');

    // 加载保存的语言偏好或使用浏览器语言
    let savedLang = localStorage.getItem('preferred-language');
    if (!savedLang) {
        // 尝试检测浏览器语言
        const browserLang = navigator.language || navigator.userLanguage;
        const shortLang = browserLang.split('-')[0];

        // 检查我们是否支持该语言
        if (translations[shortLang]) {
            savedLang = shortLang;
        } else {
            // 默认为英语
            savedLang = 'en';
        }
    }

    // 设置语言选择器以匹配保存的偏好
    languageSelect.value = savedLang;

    // 应用保存的语言
    updateLanguage(savedLang);

    // 为语言更改添加事件监听器
    languageSelect.addEventListener('change', function () {
        updateLanguage(this.value);
    });
}

// 更新所有文本元素为选定的语言
function updateLanguage(lang) {
    // 更新页面标题
    document.title = translations[lang].title;

    // 更新带有data-i18n属性的所有文本元素
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (translations[lang][key]) {
            element.textContent = translations[lang][key];
        }
    });

    // 更新占位符
    document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
        const key = element.getAttribute('data-i18n-placeholder');
        if (translations[lang][key]) {
            element.placeholder = translations[lang][key];
        }
    });

    // 更新下拉菜单选项
    document.querySelectorAll('select option[data-i18n]').forEach(option => {
        const key = option.getAttribute('data-i18n');
        if (translations[lang][key]) {
            option.textContent = translations[lang][key];
        }
    });

    // 保存语言偏好
    localStorage.setItem('preferred-language', lang);

    // 更新代码示例中的注释语言
    updateCodeExamples(lang);

    // 更新加密信息区域（如果存在）
    updateEncryptionInfo();
}

// 实现主题切换
function initThemeToggle() {
    const themeToggleBtn = document.querySelector('button i.fa-moon').parentElement;
    const htmlElement = document.documentElement;

    // 检查已保存的主题
    const savedTheme = localStorage.getItem('color-theme');

    // 如果用户之前选择了主题，应用该主题
    if (savedTheme) {
        htmlElement.classList.toggle('dark', savedTheme === 'dark');
        updateThemeIcon(savedTheme === 'dark');
    } else {
        // 如果用户未选择主题，默认使用深色模式
        htmlElement.classList.add('dark');
        updateThemeIcon(true);
    }

    themeToggleBtn.addEventListener('click', function () {
        // 切换深色模式
        const isDarkMode = htmlElement.classList.toggle('dark');

        // 更新图标
        updateThemeIcon(isDarkMode);

        // 保存用户偏好
        localStorage.setItem('color-theme', isDarkMode ? 'dark' : 'light');
    });

    function updateThemeIcon(isDarkMode) {
        const icon = themeToggleBtn.querySelector('i');
        icon.className = isDarkMode ? 'fas fa-moon text-yellow-300' : 'fas fa-sun text-orange-400';
    }
}

// 初始化复制按钮功能
function initCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn, button:has(i.fa-copy)');

    copyButtons.forEach(button => {
        button.addEventListener('click', function () {
            let textToCopy;

            // 确定要复制的文本
            if (this.closest('.code-block')) {
                // 复制代码
                textToCopy = this.closest('.code-block').querySelector('code').textContent;
            } else {
                // 复制输出结果
                const resultArea = document.querySelector('.bg-dark-900 pre code');
                if (resultArea) {
                    textToCopy = resultArea.textContent;
                }
            }

            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalHTML = this.innerHTML;
                    const lang = document.getElementById('language-select').value;

                    // 显示复制成功状态
                    this.innerHTML = `<i class="fas fa-check mr-1"></i><span>${translations[lang].copied}</span>`;
                    this.classList.add('bg-green-800', 'text-green-200');
                    this.classList.remove('bg-gray-800', 'text-gray-300', 'bg-dark-700', 'text-gray-400');

                    // 2秒后恢复原始状态
                    setTimeout(() => {
                        this.innerHTML = originalHTML;
                        this.classList.remove('bg-green-800', 'text-green-200');
                        if (this.classList.contains('copy-btn')) {
                            this.classList.add('bg-gray-800', 'text-gray-300');
                        } else {
                            this.classList.add('bg-dark-700', 'text-gray-400');
                        }
                    }, 2000);
                });
            }
        });
    });
}

// 初始化加密解密功能
function initCryptoFunctions() {
    const encryptBtn = document.querySelector('button:has([data-i18n="encrypt"])');
    const decryptBtn = document.querySelector('button:has([data-i18n="decrypt"])');
    const inputTextarea = document.querySelector('textarea');
    const outputElement = document.querySelector('.bg-dark-900 pre code');
    const clearBtn = document.querySelector('button:has([data-i18n="clear"])');
    const exampleBtn = document.querySelector('button:has([data-i18n="example"])');
    const resetBtn = document.querySelector('button:has([data-i18n="reset"])');
    const randomKeyBtns = document.querySelectorAll('input[type="text"] + button:has(i.fa-random)');

    // 示例文本
    const examples = {
        en: "This is an example of sensitive data that needs to be encrypted.",
        zh: "这是一个需要加密的敏感数据示例。",
        fr: "Voici un exemple de données sensibles qui doivent être chiffrées.",
        ja: "これは暗号化する必要のある機密データの例です。",
        de: "Dies ist ein Beispiel für sensible Daten, die verschlüsselt werden müssen.",
        ko: "이것은 암호화가 필요한 민감한 데이터의 예입니다."
    };

    // 示例按钮
    exampleBtn.addEventListener('click', function () {
        const lang = document.getElementById('language-select').value;
        inputTextarea.value = examples[lang] || examples.en;
    });

    // 清除按钮
    clearBtn.addEventListener('click', function () {
        inputTextarea.value = '';
    });

    // 重置按钮
    resetBtn.addEventListener('click', function () {
        // 重置所有选择和输入
        document.querySelectorAll('select').forEach(select => {
            select.selectedIndex = 0;
        });
        document.querySelectorAll('input[type="text"]').forEach(input => {
            input.value = '';
        });
    });

    // 随机生成密钥和IV
    randomKeyBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            const input = this.previousElementSibling;
            const isIV = input.getAttribute('data-i18n-placeholder') === 'enterIv';

            if (isIV) {
                // 生成16字节的随机IV
                input.value = generateRandomString(16);
            } else {
                // 生成密钥，长度基于选择
                const keyLengthSelect = document.querySelector('select:has(option[value="128"])');
                const keyLength = keyLengthSelect ? parseInt(keyLengthSelect.value) / 8 : 32; // 默认256位
                input.value = generateRandomString(keyLength);
            }
        });
    });

    // 加密按钮
    encryptBtn.addEventListener('click', function () {
        const plaintext = inputTextarea.value.trim();
        if (!plaintext) {
            alert(translations[document.getElementById('language-select').value].enterText);
            return;
        }

        try {
            // 实际应用中，这里会调用真正的加密函数
            // 这里只是一个演示，简单模拟加密结果
            const mockEncryptedText = btoa(plaintext);
            outputElement.textContent = mockEncryptedText;

            // 更新信息区
            updateEncryptionInfo();
        } catch (error) {
            alert('Encryption error: ' + error.message);
        }
    });

    // 解密按钮
    decryptBtn.addEventListener('click', function () {
        const ciphertext = inputTextarea.value.trim();
        if (!ciphertext) {
            alert(translations[document.getElementById('language-select').value].enterText);
            return;
        }

        try {
            // 实际应用中，这里会调用真正的解密函数
            // 这里只是一个演示，简单模拟解密结果
            let mockDecryptedText;
            try {
                mockDecryptedText = atob(ciphertext);
            } catch {
                throw new Error('Invalid Base64 input');
            }
            outputElement.textContent = mockDecryptedText;

            // 更新信息区
            updateEncryptionInfo();
        } catch (error) {
            alert('Decryption error: ' + error.message);
        }
    });

    // 生成随机字符串
    function generateRandomString(length) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }

    // 当加密参数改变时，更新代码示例
    const encryptionModeSelect = document.getElementById('encryption-mode');
    const paddingModeSelect = document.getElementById('padding-mode');
    const keyLengthSelect = document.getElementById('key-length');
    const outputFormatSelect = document.getElementById('output-format');

    [encryptionModeSelect, paddingModeSelect, keyLengthSelect, outputFormatSelect].forEach(select => {
        if (select) {
            select.addEventListener('change', function () {
                const activeTab = document.querySelector('nav.flex button.border-primary-500');
                if (activeTab) {
                    const language = activeTab.querySelector('span').textContent.toLowerCase();
                    updateCodeExamples(document.getElementById('language-select').value, language);
                }
            });
        }
    });
}

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

            // 根据当前加密参数和语言更新代码示例
            updateCodeExamples(document.getElementById('language-select').value, language);
        });
    });

    // 初始化时触发第一个标签的点击
    if (codeTabs.length > 0) {
        codeTabs[0].click();
    }
}

// 更新代码示例中的注释语言
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

// 获取本地化的注释文本
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

// 生成 Go 代码示例
function generateGoCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    return `package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "bytes"
)

// ${comments.encrypt[lang]}
func encryptAes${mode}(plaintext string, key []byte${needsIV ? ', iv []byte' : ''}) (string, error) {
    // Check key length
    if len(key) != ${keyLength / 8} {
        return "", fmt.Errorf("key must be exactly ${keyLength / 8} bytes for AES-${keyLength}")
    }
    
    ${needsIV ? `// Check IV length
    if len(iv) != aes.BlockSize {
        return "", fmt.Errorf("IV must be exactly %d bytes", aes.BlockSize)
    }` : ''}
    
    // Convert plaintext to bytes
    plaintextBytes := []byte(plaintext)
    
    // Create new cipher block
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    
    // Padding
    ${padding === 'NO_PADDING' ?
            `// For no padding, plaintext must be a multiple of the block size
    if len(plaintextBytes) % aes.BlockSize != 0 {
        return "", errors.New("plaintext length must be multiple of block size when using no padding")
    }
    paddedPlaintext := plaintextBytes` :
            `// Add PKCS7 padding
    paddedPlaintext := addPKCS7Padding(plaintextBytes, aes.BlockSize)`}
    
    // Encrypt based on mode
    var ciphertext []byte
    ${mode === 'ECB' ?
            `// ECB mode encryption (note: ECB is not secure for most applications)
    ciphertext = make([]byte, len(paddedPlaintext))
    for bs, be := 0, block.BlockSize(); bs < len(paddedPlaintext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
        block.Encrypt(ciphertext[bs:be], paddedPlaintext[bs:be])
    }` : mode === 'CBC' ?
                `// CBC mode encryption
    ciphertext = make([]byte, len(paddedPlaintext))
    cbc := cipher.NewCBCEncrypter(block, iv)
    cbc.CryptBlocks(ciphertext, paddedPlaintext)` : mode === 'CFB' ?
                    `// CFB mode encryption
    ciphertext = make([]byte, len(paddedPlaintext))
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext, paddedPlaintext)` :
                    `// Other mode encryption (simplified example)
    ciphertext = make([]byte, len(paddedPlaintext))
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(ciphertext, paddedPlaintext)`}
    
    // Convert to output format
    ${outputFormat === 'base64' ?
            `return base64.StdEncoding.EncodeToString(ciphertext), nil` :
            `return hex.EncodeToString(ciphertext), nil`}
}

// ${comments.decrypt[lang]}
func decryptAes${mode}(ciphertext string, key []byte${needsIV ? ', iv []byte' : ''}) (string, error) {
    // Check key length
    if len(key) != ${keyLength / 8} {
        return "", fmt.Errorf("key must be exactly ${keyLength / 8} bytes for AES-${keyLength}")
    }
    
    ${needsIV ? `// Check IV length
    if len(iv) != aes.BlockSize {
        return "", fmt.Errorf("IV must be exactly %d bytes", aes.BlockSize)
    }` : ''}
    
    // Decode from format
    var encryptedBytes []byte
    var err error
    ${outputFormat === 'base64' ?
            `encryptedBytes, err = base64.StdEncoding.DecodeString(ciphertext)` :
            `encryptedBytes, err = hex.DecodeString(ciphertext)`}
    if err != nil {
        return "", err
    }
    
    // Create new cipher block
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    
    // Block size check
    if len(encryptedBytes) % aes.BlockSize != 0 {
        return "", errors.New("ciphertext is not a multiple of the block size")
    }
    
    // Decrypt based on mode
    var plaintext []byte
    ${mode === 'ECB' ?
            `// ECB mode
    // Process each block
    let mut decrypted_data = Vec::new();
    for chunk in encrypted_data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }
    
    // Remove padding if needed
    ${padding === 'NO_PADDING' ?
                '// No padding to remove' :
                `// Remove PKCS7 padding
        let padding_len = *decrypted_data.last().unwrap_or(&0) as usize;
        if padding_len > 0 && padding_len <= 16 {
            decrypted_data.truncate(decrypted_data.len() - padding_len);
        }`}` :
            `// ${mode} mode
    let decrypted_data = ${mode}::new(&cipher, iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_data)?;`}
    
    // Convert to string
    Ok(String::from_utf8(decrypted_data)?)
}

${padding !== 'NO_PADDING' ?
            `// Add PKCS7 padding
func addPKCS7Padding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padtext...)
}

// Remove PKCS7 padding
func removePKCS7Padding(data []byte, blockSize int) ([]byte, error) {
    length := len(data)
    if length == 0 {
        return nil, errors.New("invalid padding: data is empty")
    }
    
    padLength := int(data[length-1])
    if padLength > blockSize || padLength == 0 {
        return nil, errors.New("invalid padding size")
    }
    
    // Check all padding bytes
    for i := length - padLength; i < length; i++ {
        if data[i] != byte(padLength) {
            return nil, errors.New("invalid padding bytes")
        }
    }
    
    return data[:length-padLength], nil
}` : ''}

func main() {
    // Example usage
    // Generate random key${needsIV ? ' and IV' : ''}
    key := make([]byte, ${keyLength / 8})
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        fmt.Println("Error generating key:", err)
        return
    }
    
    ${needsIV ? `iv := make([]byte, aes.BlockSize)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        fmt.Println("Error generating IV:", err)
        return
    }` : ''}
    
    plaintext := "${exampleText}"
    
    // Encrypt
    encrypted, err := encryptAes${mode}(plaintext, key${needsIV ? ', iv' : ''})
    if err != nil {
        fmt.Println("Error encrypting:", err)
        return
    }
    fmt.Println("${encryptedResult}{$encrypted}")
    
    // Decrypt
    decrypted, err := decryptAes${mode}(encrypted, key${needsIV ? ', iv' : ''})
    if err != nil {
        fmt.Println("Error decrypting:", err)
        return
    }
    fmt.Println("${decryptedResult}{$decrypted}")
}`;
}

// 生成 Rust 代码示例
function generateRustCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    return `// ${comments.title[lang]}
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::Aes${keyLength == 128 ? '128' : keyLength == 192 ? '192' : '256'};
${mode !== 'ECB' ? `use aes::cipher::{block_padding::Pkcs7, BlockMode, BlockModeEncrypt, BlockModeDecrypt};
use ${mode.toLowerCase()}::${mode};` : ''}
${outputFormat === 'base64' ? 'use base64::{encode, decode};' : 'use hex::{encode as hex_encode, decode as hex_decode};'}
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Generate random key
    let key = rand::random::<[u8; ${keyLength / 8}]>();
    ${needsIV ? `// Generate random IV
    let iv = rand::random::<[u8; 16]>();` : ''}
    
    let plaintext = "${exampleText}";
    
    // Encrypt
    let encrypted = encrypt_aes_${mode.toLowerCase()}(plaintext, &key${needsIV ? ', &iv' : ''})?;
    println!("${encryptedResult}{$encrypted}");
    
    // Decrypt
    let decrypted = decrypt_aes_${mode.toLowerCase()}(&encrypted, &key${needsIV ? ', &iv' : ''})?;
    println!("${decryptedResult}{$decrypted}");
    
    Ok(())
}

// ${comments.encrypt[lang]}
fn encrypt_aes_${mode.toLowerCase()}(plaintext: &str, key: &[u8; ${keyLength / 8}]${needsIV ? ', iv: &[u8; 16]' : ''}) -> Result<String, Box<dyn Error>> {
    // Convert plaintext to bytes
    let plaintext_bytes = plaintext.as_bytes();
    
    // Initialize cipher
    let cipher = Aes${keyLength == 128 ? '128' : keyLength == 192 ? '192' : '256'}::new(key.into());
    
    ${mode === 'ECB' ?
            `// ECB mode (note: ECB is not secure for most applications)
    // Add padding
    let mut padded_data = Vec::new();
    ${padding === 'NO_PADDING' ?
                `// Ensure data is a multiple of block size
        if plaintext_bytes.len() % 16 != 0 {
            return Err("Data length must be a multiple of 16 bytes for no padding".into());
        }
        padded_data.extend_from_slice(plaintext_bytes);` :
                `// Add PKCS7 padding
        for chunk in plaintext_bytes.chunks(16) {
            let mut block = [0u8; 16];
            let padding_len = 16 - chunk.len();
            
            for (i, &byte) in chunk.iter().enumerate() {
                block[i] = byte;
            }
            
            // Fill the rest with padding
            for i in chunk.len()..16 {
                block[i] = padding_len as u8;
            }
            
            padded_data.extend_from_slice(&block);
        }`}
    
    // Process each block
    let mut encrypted_data = Vec::new();
    for chunk in padded_data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }` :
            `// ${mode} mode
    let encrypted_data = ${mode}::new(&cipher, iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext_bytes);`}
    
    // Convert to ${outputFormat.toUpperCase()}
    ${outputFormat === 'base64' ?
            'Ok(encode(encrypted_data))' :
            'Ok(hex_encode(encrypted_data))'}
}

// ${comments.decrypt[lang]}
fn decrypt_aes_${mode.toLowerCase()}(ciphertext: &str, key: &[u8; ${keyLength / 8}]${needsIV ? ', iv: &[u8; 16]' : ''}) -> Result<String, Box<dyn Error>> {
    // Decode ${outputFormat.toUpperCase()}
    ${outputFormat === 'base64' ?
            'let encrypted_data = decode(ciphertext)?;' :
            'let encrypted_data = hex_decode(ciphertext)?;'}
    
    // Initialize cipher
    let cipher = Aes${keyLength == 128 ? '128' : keyLength == 192 ? '192' : '256'}::new(key.into());
    
    ${mode === 'ECB' ?
            `// ECB mode
    // Process each block
    let mut decrypted_data = Vec::new();
    for chunk in encrypted_data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }
    
    // Remove padding if needed
    ${padding === 'NO_PADDING' ?
                '// No padding to remove' :
                `// Remove PKCS7 padding
        let padding_len = *decrypted_data.last().unwrap_or(&0) as usize;
        if padding_len > 0 && padding_len <= 16 {
            decrypted_data.truncate(decrypted_data.len() - padding_len);
        }`}` :
            `// ${mode} mode
    let decrypted_data = ${mode}::new(&cipher, iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_data)?;`}
    
    // Convert to string
    Ok(String::from_utf8(decrypted_data)?)
}
`;
}

// 生成 C# 代码示例
function generateCSharpCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    // C# 填充模式
    const paddingName = padding === 'PKCS7' || padding === 'PKCS5' ? 'PKCS7' :
        padding === 'ISO10126' ? 'ISO10126' :
            padding === 'ANSIX923' ? 'ANSIX923' :
                padding === 'NO_PADDING' ? 'None' : 'PKCS7';

    return `using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesEncryptionExample
{
    /// <summary>
    /// ${comments.title[lang]}
    /// </summary>
    public class AesEncryption
    {
        /// <summary>
        /// ${comments.encrypt[lang]}
        /// </summary>
        public static string Encrypt(string plaintext, byte[] key${needsIV ? ', byte[] iv' : ''})
        {
            // Validate key length
            if (key.Length != ${keyLength / 8})
                throw new ArgumentException($"Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
            
            ${needsIV ? `// Validate IV length
            if (iv.Length != 16)
                throw new ArgumentException("IV must be exactly 16 bytes");` : ''}
            
            // Convert plaintext to bytes
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            
            // Create AES instance
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = ${keyLength};
                aes.Key = key;
                ${needsIV ? `aes.IV = iv;` : ''}
                aes.Mode = CipherMode.${mode};
                aes.Padding = PaddingMode.${paddingName};
                
                // Create encryptor
                ICryptoTransform encryptor = aes.CreateEncryptor();
                
                // Encrypt
                byte[] encrypted;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    encrypted = ms.ToArray();
                }
                
                // Convert to ${outputFormat}
                ${outputFormat === 'base64' ?
            `return Convert.ToBase64String(encrypted);` :
            `return BitConverter.ToString(encrypted).Replace("-", "").ToLower();`}
            }
        }
        
        /// <summary>
        /// ${comments.decrypt[lang]}
        /// </summary>
        public static string Decrypt(string ciphertext, byte[] key${needsIV ? ', byte[] iv' : ''})
        {
            // Validate key length
            if (key.Length != ${keyLength / 8})
                throw new ArgumentException($"Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
            
            ${needsIV ? `// Validate IV length
            if (iv.Length != 16)
                throw new ArgumentException("IV must be exactly 16 bytes");` : ''}
            
            // Convert from ${outputFormat}
            byte[] ciphertextBytes = ${outputFormat === 'base64' ?
            `Convert.FromBase64String(ciphertext);` :
            `HexStringToByteArray(ciphertext);`}
            
            // Create AES instance
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = ${keyLength};
                aes.Key = key;
                ${needsIV ? `aes.IV = iv;` : ''}
                aes.Mode = CipherMode.${mode};
                aes.Padding = PaddingMode.${paddingName};
                
                // Create decryptor
                ICryptoTransform decryptor = aes.CreateDecryptor();
                
                // Decrypt
                byte[] decrypted;
                using (MemoryStream ms = new MemoryStream(ciphertextBytes))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream output = new MemoryStream())
                        {
                            cs.CopyTo(output);
                            decrypted = output.ToArray();
                        }
                    }
                }
                
                // Convert to string
                return Encoding.UTF8.GetString(decrypted);
            }
        }
        
        ${outputFormat === 'hex' ? `
        // Helper to convert hex string to byte array
        private static byte[] HexStringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }` : ''}
        
        // Example usage
        public static void Main()
        {
            // Generate random key${needsIV ? ' and IV' : ''}
            byte[] key = new byte[${keyLength / 8}];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);
            
            ${needsIV ? `byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(iv);` : ''}
            
            string plaintext = "${exampleText}";
            
            // Encrypt
            string encrypted = Encrypt(plaintext, key${needsIV ? ', iv' : ''});
            Console.WriteLine("${encryptedResult}{$encrypted}");
            
            // Decrypt
            string decrypted = Decrypt(encrypted, key${needsIV ? ', iv' : ''});
            Console.WriteLine("${decryptedResult}{$decrypted}");
        }
    }
}`;
}

// 生成 PHP 代码示例
function generatePHPCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    // PHP中的加密方法名称
    const methodName = `aes-${keyLength}-${mode.toLowerCase()}`;

    return `<?php
/**
 * ${comments.title[lang]}
 */

/**
 * ${comments.encrypt[lang]}
 */
function encryptAes${mode}($plaintext, $key${needsIV ? ', $iv' : ''}) {
    // Validate key length
    if (strlen($key) != ${keyLength / 8}) {
        throw new Exception("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
    }
    
    ${needsIV ? `// Validate IV length
    if (strlen($iv) != 16) {
        throw new Exception("IV must be exactly 16 bytes");
    }` : ''}
    
    // Set up encryption method
    $method = '${methodName}';
    
    // Handle padding
    ${padding === 'NO_PADDING' ?
            `// For no padding, ensure data is block size multiple
    $block = 16;
    $pad = $block - (strlen($plaintext) % $block);
    if ($pad < $block) {
        $plaintext .= str_repeat("\\0", $pad);
    }
    
    // Encrypt with OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
    $encrypted = openssl_encrypt(
        $plaintext,
        $method,
        $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
        ${needsIV ? '$iv' : '""'}
    );` :
            `// Encrypt with default PKCS7 padding
    $encrypted = openssl_encrypt(
        $plaintext,
        $method,
        $key,
        OPENSSL_RAW_DATA,
        ${needsIV ? '$iv' : '""'}
    );`}
    
    if ($encrypted === false) {
        throw new Exception("Encryption failed: " . openssl_error_string());
    }
    
    // Format output
    ${outputFormat === 'base64' ?
            `return base64_encode($encrypted);` :
            `return bin2hex($encrypted);`}
}

/**
 * ${comments.decrypt[lang]}
 */
function decryptAes${mode}($ciphertext, $key${needsIV ? ', $iv' : ''}) {
    // Validate key length
    if (strlen($key) != ${keyLength / 8}) {
        throw new Exception("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
    }
    
    ${needsIV ? `// Validate IV length
    if (strlen($iv) != 16) {
        throw new Exception("IV must be exactly 16 bytes");
    }` : ''}
    
    // Set up decryption method
    $method = '${methodName}';
    
    // Decode input
    ${outputFormat === 'base64' ?
            `$encryptedRaw = base64_decode($ciphertext);` :
            `$encryptedRaw = hex2bin($ciphertext);`}
    
    // Decrypt
    ${padding === 'NO_PADDING' ?
            `$decrypted = openssl_decrypt(
        $encryptedRaw,
        $method,
        $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
        ${needsIV ? '$iv' : '""'}
    );
    
    // Remove null padding
    $decrypted = rtrim($decrypted, "\\0");` :
            `$decrypted = openssl_decrypt(
        $encryptedRaw,
        $method,
        $key,
        OPENSSL_RAW_DATA,
        ${needsIV ? '$iv' : '""'}
    );`}
    
    if ($decrypted === false) {
        throw new Exception("Decryption failed: " . openssl_error_string());
    }
    
    return $decrypted;
}

// Example usage
try {
    // Generate random key${needsIV ? ' and IV' : ''}
    $key = random_bytes(${keyLength / 8});
    ${needsIV ? `$iv = random_bytes(16);` : ''}
    
    $plaintext = "${exampleText}";
    
    // Encrypt
    $encrypted = encryptAes${mode}($plaintext, $key${needsIV ? ', $iv' : ''});
    echo "${encryptedResult}{$encrypted}\n";
    
    // Decrypt
    $decrypted = decryptAes${mode}($encrypted, $key${needsIV ? ', $iv' : ''});
    echo "${decryptedResult}{$decrypted}\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
`;
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