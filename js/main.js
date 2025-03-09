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

    // 初始一次加密信息区域
    updateEncryptionInfo();

    // 添加参数下拉菜单的change事件
    document.getElementById('encryption-mode').addEventListener('change', updateEncryptionInfo);
    document.getElementById('padding-mode').addEventListener('change', updateEncryptionInfo);
    document.getElementById('key-length').addEventListener('change', updateEncryptionInfo);
    document.getElementById('output-format').addEventListener('change', updateEncryptionInfo);
});

// 更新加密信息区域的全局函数
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

// 为Go语言提供简单的占位符实现
function generateGoPlaceholder(lang, mode, keyLength) {
    const comments = {
        en: `// AES-${mode} Encryption in Go\n// Using ${keyLength}-bit key\n// This is a placeholder. Full implementation coming soon.`,
        zh: `// Go语言中的AES-${mode}加密\n// 使用${keyLength}位密钥\n// 这是占位代码，完整实现即将推出。`,
        fr: `// Chiffrement AES-${mode} en Go\n// Utilisant une clé de ${keyLength} bits\n// Ceci est un espace réservé. Implémentation complète à venir.`,
        ja: `// GoでのAES-${mode}暗号化\n// ${keyLength}ビットキーを使用\n// これはプレースホルダーです。完全な実装はまもなく公開されます。`,
        de: `// AES-${mode} Verschlüsselung in Go\n// Mit ${keyLength}-Bit-Schlüssel\n// Dies ist ein Platzhalter. Vollständige Implementierung kommt bald.`,
        ko: `// Go에서의 AES-${mode} 암호화\n// ${keyLength}비트 키 사용\n// 이것은 자리 표시자입니다. 전체 구현이 곧 제공됩니다.`
    };

    return `${comments[lang] || comments['en']}

package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
)

// Full implementation of AES-${mode} encryption for Go will be added soon
// Check back later for the complete code example
`;
}

// 为Rust语言提供简单的占位符实现
function generateRustPlaceholder(lang, mode, keyLength) {
    const comments = {
        en: `// AES-${mode} Encryption in Rust\n// Using ${keyLength}-bit key\n// This is a placeholder. Full implementation coming soon.`,
        zh: `// Rust语言中的AES-${mode}加密\n// 使用${keyLength}位密钥\n// 这是占位代码，完整实现即将推出。`,
        fr: `// Chiffrement AES-${mode} en Rust\n// Utilisant une clé de ${keyLength} bits\n// Ceci est un espace réservé. Implémentation complète à venir.`,
        ja: `// RustでのAES-${mode}暗号化\n// ${keyLength}ビットキーを使用\n// これはプレースホルダーです。完全な実装はまもなく公開されます。`,
        de: `// AES-${mode} Verschlüsselung in Rust\n// Mit ${keyLength}-Bit-Schlüssel\n// Dies ist ein Platzhalter. Vollständige Implementierung kommt bald.`,
        ko: `// Rust에서의 AES-${mode} 암호화\n// ${keyLength}비트 키 사용\n// 이것은 자리 표시자입니다. 전체 구현이 곧 제공됩니다.`
    };

    return `${comments[lang] || comments['en']}

use aes::{Aes128, Aes192, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

// Full implementation of AES-${mode} encryption for Rust will be added soon
// Check back later for the complete code example
`;
}

// 添加Python代码生成函数
function generatePythonCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const paddingMethod = padding === 'PKCS7' || padding === 'PKCS5' ? 'PKCS7' :
        padding === 'NO_PADDING' ? 'None' : 'PKCS7';

    return `"""
${comments.title[lang]}
"""

from Crypto.Cipher import AES
import base64
import os
import binascii

def encrypt_aes_${mode.toLowerCase()}(plaintext, key${needsIV ? ', iv' : ''}):
    """
    ${comments.encrypt[lang]}
    
    ${comments.params[lang]}
        ${comments.plaintext[lang]}
        ${comments.key[lang]}
        ${needsIV ? `${comments.iv[lang]}\n` : ''}
    ${comments.returns[lang]}
        ${comments.returnEncrypt[lang]}
    """
    # 确保密钥长度正确
    if len(key) != ${keyLength / 8}:
        raise ValueError(f"Key must be exactly ${keyLength / 8} bytes long for AES-${keyLength}")
    ${needsIV ? `
    # 确保IV长度正确
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes long")` : ''}
    
    # 将明文转换为字节并填充
    plaintext_bytes = plaintext.encode('utf-8')
    ${paddingMethod === 'None' ? `
    # 无填充模式下，数据长度必须是16的倍数
    remainder = len(plaintext_bytes) % 16
    if remainder != 0:
        plaintext_bytes += b'\\0' * (16 - remainder)` :
            `
    # 使用PKCS7填充
    block_size = 16
    padding_length = block_size - (len(plaintext_bytes) % block_size)
    plaintext_bytes += bytes([padding_length]) * padding_length`}
    
    # 创建AES密码对象
    ${needsIV ?
            `cipher = AES.new(key, AES.MODE_${mode}, iv)` :
            `cipher = AES.new(key, AES.MODE_${mode})`}
    
    # 加密
    ciphertext = cipher.encrypt(plaintext_bytes)
    
    # 返回Base64编码或十六进制编码的密文
    ${outputFormat === 'base64' ?
            `return base64.b64encode(ciphertext).decode('utf-8')` :
            `return ciphertext.hex()`}

def decrypt_aes_${mode.toLowerCase()}(ciphertext, key${needsIV ? ', iv' : ''}):
    """
    ${comments.decrypt[lang]}
    
    ${comments.params[lang]}
        ${comments.ciphertext[lang]}
        ${comments.key[lang]}
        ${needsIV ? `${comments.iv[lang]}\n` : ''}
    ${comments.returns[lang]}
        ${comments.returnDecrypt[lang]}
    """
    # 确保密钥长度正确
    if len(key) != ${keyLength / 8}:
        raise ValueError(f"Key must be exactly ${keyLength / 8} bytes long for AES-${keyLength}")
    ${needsIV ? `
    # 确保IV长度正确
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes long")` : ''}
    
    # 解码密文
    ${outputFormat === 'base64' ?
            `ciphertext_bytes = base64.b64decode(ciphertext)` :
            `ciphertext_bytes = bytes.fromhex(ciphertext)`}
    
    # 创建AES密码对象
    ${needsIV ?
            `cipher = AES.new(key, AES.MODE_${mode}, iv)` :
            `cipher = AES.new(key, AES.MODE_${mode})`}
    
    # 解密
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    
    # 移除填充
    ${paddingMethod === 'None' ? `
    # 无填充模式下，需要手动移除尾部的空字节
    decrypted_bytes = decrypted_bytes.rstrip(b'\\0')` :
            `
    # 移除PKCS7填充
    padding_length = decrypted_bytes[-1]
    if padding_length > 16:
        raise ValueError("Invalid padding")
    if decrypted_bytes[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid padding")
    decrypted_bytes = decrypted_bytes[:-padding_length]`}
    
    # 返回解密后的文本
    return decrypted_bytes.decode('utf-8')

# ${comments.example[lang]}
key = os.urandom(${keyLength / 8})  # ${keyLength} bits key
${needsIV ? `iv = os.urandom(16)  # 16 bytes IV` : ''}

# 加密示例
plaintext = "这是要加密的敏感数据"
encrypted = encrypt_aes_${mode.toLowerCase()}(plaintext, key${needsIV ? ', iv' : ''})
print(f"加密结果: {encrypted}")

# 解密示例
decrypted = decrypt_aes_${mode.toLowerCase()}(encrypted, key${needsIV ? ', iv' : ''})
print(f"解密结果: {decrypted}")`;
}

// 生成 JavaScript 代码示例
function generateJavaScriptCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const paddingMethod = padding === 'PKCS7' ? 'pkcs7' :
        padding === 'PKCS5' ? 'pkcs5' :
            padding === 'NO_PADDING' ? 'nopadding' : 'pkcs7';

    return `// ${comments.title[lang]}

// ${comments.import[lang]} (using CryptoJS)
const CryptoJS = require('crypto-js');

/**
 * ${comments.encrypt[lang]}
 * 
 * @param {string} plaintext - ${comments.plaintext[lang]}
 * @param {string} key - ${comments.key[lang]}
 * ${needsIV ? `* @param {string} iv - ${comments.iv[lang]}\n` : ''}* @return {string} ${comments.returnEncrypt[lang]}
 */
function encryptAES${mode}(plaintext, key${needsIV ? ', iv' : ''}) {
    // 将密钥转换为CryptoJS格式
    const cryptoKey = CryptoJS.enc.Utf8.parse(key);
    ${needsIV ? `
    // 将IV转换为CryptoJS格式
    const cryptoIV = CryptoJS.enc.Utf8.parse(iv);` : ''}
    
    // 加密配置
    const options = {
        mode: CryptoJS.mode.${mode},
        padding: CryptoJS.pad.${paddingMethod === 'nopadding' ? 'NoPadding' : 'Pkcs7'},
        ${needsIV ? `iv: cryptoIV,` : ''}
    };
    
    // 加密
    const encrypted = CryptoJS.AES.encrypt(plaintext, cryptoKey, options);
    
    // 返回指定格式的输出
    return ${outputFormat === 'base64' ? 'encrypted.toString()' : 'encrypted.ciphertext.toString()'};
}

/**
 * ${comments.decrypt[lang]}
 * 
 * @param {string} ciphertext - ${comments.ciphertext[lang]}
 * @param {string} key - ${comments.key[lang]}
 * ${needsIV ? `* @param {string} iv - ${comments.iv[lang]}\n` : ''}* @return {string} ${comments.returnDecrypt[lang]}
 */
function decryptAES${mode}(ciphertext, key${needsIV ? ', iv' : ''}) {
    // 将密钥转换为CryptoJS格式
    const cryptoKey = CryptoJS.enc.Utf8.parse(key);
    ${needsIV ? `
    // 将IV转换为CryptoJS格式
    const cryptoIV = CryptoJS.enc.Utf8.parse(iv);` : ''}
    
    // 解密配置
    const options = {
        mode: CryptoJS.mode.${mode},
        padding: CryptoJS.pad.${paddingMethod === 'nopadding' ? 'NoPadding' : 'Pkcs7'},
        ${needsIV ? `iv: cryptoIV,` : ''}
    };
    
    // 准备密文
    ${outputFormat === 'base64' ?
            `// Base64格式直接使用
    const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Base64.parse(ciphertext)
    });` :
            `// Hex格式需要转换
    const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(ciphertext)
    });`}
    
    // 解密
    const decrypted = CryptoJS.AES.decrypt(cipherParams, cryptoKey, options);
    
    // 转换为UTF-8字符串并返回
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// ${comments.example[lang]}
// 生成${keyLength / 8}字节的随机密钥
function generateRandomKey(length) {
    return Array.from(
        { length },
        () => String.fromCharCode(Math.floor(Math.random() * 256))
    ).join('');
}

const key = generateRandomKey(${keyLength / 8});
${needsIV ? `const iv = generateRandomKey(16);` : ''}

// 加密示例
const plaintext = "这是要加密的敏感数据";
const encrypted = encryptAES${mode}(plaintext, key${needsIV ? ', iv' : ''});
console.log("加密结果:", encrypted);

// 解密示例
const decrypted = decryptAES${mode}(encrypted, key${needsIV ? ', iv' : ''});
console.log("解密结果:", decrypted);`;
}

// 生成 Java 代码示例
function generateJavaCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const paddingName = padding === 'PKCS7' || padding === 'PKCS5' ? 'PKCS5Padding' :
        padding === 'ISO10126' ? 'ISO10126Padding' :
            padding === 'NO_PADDING' ? 'NoPadding' : 'PKCS5Padding';

    return `import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
${needsIV ? `import javax.crypto.spec.IvParameterSpec;` : ''}
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

/**
 * ${comments.title[lang]}
 */
public class AESEncryption {
    
    /**
     * ${comments.encrypt[lang]}
     * 
     * @param plaintext ${comments.plaintext[lang]}
     * @param key ${comments.key[lang]}
     * ${needsIV ? `* @param iv ${comments.iv[lang]}\n` : ''}* @return ${comments.returnEncrypt[lang]}
     * @throws Exception 加密异常
     */
    public static String encrypt(String plaintext, String key${needsIV ? ', String iv' : ''}) throws Exception {
        // 确保密钥长度正确
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != ${keyLength / 8}) {
            throw new IllegalArgumentException("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        
        ${needsIV ? `// 初始化向量
        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        if (ivBytes.length != 16) {
            throw new IllegalArgumentException("IV must be exactly 16 bytes");
        }
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);` : ''}
        
        // 初始化加密器
        Cipher cipher = Cipher.getInstance("AES/${mode}/${paddingName}");
        ${needsIV ?
            `cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);` :
            `cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);`}
        
        // 加密
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // 转换为${outputFormat.toUpperCase()}
        ${outputFormat === 'base64' ?
            `return Base64.getEncoder().encodeToString(encrypted);` :
            `return HexFormat.of().formatHex(encrypted);`}
    }
    
    /**
     * ${comments.decrypt[lang]}
     * 
     * @param ciphertext ${comments.ciphertext[lang]}
     * @param key ${comments.key[lang]}
     * ${needsIV ? `* @param iv ${comments.iv[lang]}\n` : ''}* @return ${comments.returnDecrypt[lang]}
     * @throws Exception 解密异常
     */
    public static String decrypt(String ciphertext, String key${needsIV ? ', String iv' : ''}) throws Exception {
        // 确保密钥长度正确
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != ${keyLength / 8}) {
            throw new IllegalArgumentException("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}");
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        
        ${needsIV ? `// 初始化向量
        byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
        if (ivBytes.length != 16) {
            throw new IllegalArgumentException("IV must be exactly 16 bytes");
        }
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);` : ''}
        
        // 初始化解密器
        Cipher cipher = Cipher.getInstance("AES/${mode}/${paddingName}");
        ${needsIV ?
            `cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);` :
            `cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);`}
        
        // 解密
        ${outputFormat === 'base64' ?
            `byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));` :
            `byte[] decrypted = cipher.doFinal(HexFormat.of().parseHex(ciphertext));`}
        
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
    public static void main(String[] args) {
        try {
            // 示例密钥
            String key = generateRandomString(${keyLength / 8}); // ${keyLength}位密钥
            ${needsIV ? `String iv = generateRandomString(16);  // 16字节IV` : ''}
            
            // 加密示例
            String plaintext = "这是要加密的敏感数据";
            String encrypted = encrypt(plaintext, key${needsIV ? ', iv' : ''});
            System.out.println("加密结果: " + encrypted);
            
            // 解密示例
            String decrypted = decrypt(encrypted, key${needsIV ? ', iv' : ''});
            System.out.println("解密结果: " + decrypted);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 生成随机字符串
    private static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char)(Math.random() * 256));
        }
        return sb.toString();
    }
}`;
}

// 获取翻译的注释文本
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
        import: {
            en: "Import required libraries",
            zh: "导入所需库",
            fr: "Importer les bibliothèques requises",
            ja: "必要なライブラリをインポート",
            de: "Erforderliche Bibliotheken importieren",
            ko: "필요한 라이브러리 가져오기"
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
            zh: "返回值:",
            fr: "Retourne:",
            ja: "戻り値:",
            de: "Rückgabe:",
            ko: "반환값:"
        },
        returnEncrypt: {
            en: `${outputFormat.toUpperCase()} encoded encrypted data`,
            zh: `${outputFormat.toUpperCase()}编码的加密数据`,
            fr: `données chiffrées encodées en ${outputFormat.toUpperCase()}`,
            ja: `${outputFormat.toUpperCase()}エンコードされた暗号化データ`,
            de: `${outputFormat.toUpperCase()}-codierte verschlüsselte Daten`,
            ko: `${outputFormat.toUpperCase()} 인코딩된 암호화 데이터`
        },
        returnDecrypt: {
            en: "Decrypted text",
            zh: "解密后的文本",
            fr: "Texte déchiffré",
            ja: "復号化されたテキスト",
            de: "Entschlüsselter Text",
            ko: "복호화된 텍스트"
        },
        example: {
            en: "Example usage",
            zh: "使用示例",
            fr: "Exemple d'utilisation",
            ja: "使用例",
            de: "Verwendungsbeispiel",
            ko: "사용 예"
        }
    };
}

// 生成 PHP 代码示例
function generatePHPCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    // PHP中的OpenSSL填充模式
    const opensslPadding = padding === 'NO_PADDING' ? 'OPENSSL_ZERO_PADDING' : 'OPENSSL_PKCS1_PADDING';

    // PHP中的加密方法
    const cipherMethod = `aes-${keyLength}-${mode.toLowerCase()}`;

    return `<?php
/**
 * ${comments.title[lang]}
 * 
 * PHP implementation using OpenSSL
 */

/**
 * ${comments.encrypt[lang]}
 * 
 * @param string $plaintext ${comments.plaintext[lang]}
 * @param string $key ${comments.key[lang]}
 * ${needsIV ? `* @param string $iv ${comments.iv[lang]}\n` : ''}* @return string ${comments.returnEncrypt[lang]}
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
    
    // PKCS7 padding is handled automatically by OpenSSL
    ${padding === 'NO_PADDING' ?
            `// For no padding, data length must be a multiple of 16
    $paddingLength = 16 - (strlen($plaintext) % 16);
    if ($paddingLength < 16) {
        $plaintext .= str_repeat("\\0", $paddingLength);
    }` : ''}
    
    // Encrypt using OpenSSL
    $encrypted = openssl_encrypt(
        $plaintext,
        '${cipherMethod}',
        $key,
        ${padding === 'NO_PADDING' ? 'OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING' : 'OPENSSL_RAW_DATA'},
        ${needsIV ? '$iv' : "''"}
    );
    
    if ($encrypted === false) {
        throw new Exception("Encryption failed: " . openssl_error_string());
    }
    
    // Convert to ${outputFormat.toUpperCase()}
    ${outputFormat === 'base64' ?
            `return base64_encode($encrypted);` :
            `return bin2hex($encrypted);`}
}

/**
 * ${comments.decrypt[lang]}
 * 
 * @param string $ciphertext ${comments.ciphertext[lang]}
 * @param string $key ${comments.key[lang]}
 * ${needsIV ? `* @param string $iv ${comments.iv[lang]}\n` : ''}* @return string ${comments.returnDecrypt[lang]}
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
    
    // Convert from ${outputFormat.toUpperCase()} to binary
    ${outputFormat === 'base64' ?
            `$encryptedData = base64_decode($ciphertext);` :
            `$encryptedData = hex2bin($ciphertext);`}
    
    // Decrypt using OpenSSL
    $decrypted = openssl_decrypt(
        $encryptedData,
        '${cipherMethod}',
        $key,
        ${padding === 'NO_PADDING' ? 'OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING' : 'OPENSSL_RAW_DATA'},
        ${needsIV ? '$iv' : "''"}
    );
    
    if ($decrypted === false) {
        throw new Exception("Decryption failed: " . openssl_error_string());
    }
    
    ${padding === 'NO_PADDING' ?
            `// For no padding, we need to manually remove null bytes
    $decrypted = rtrim($decrypted, "\\0");` : ''}
    
    return $decrypted;
}

/**
 * Generate a random string of specified length
 */
function generateRandomBytes($length) {
    return random_bytes($length);
}

// ${comments.example[lang]}
try {
    // Generate random key${needsIV ? ' and IV' : ''}
    $key = generateRandomBytes(${keyLength / 8});
    ${needsIV ? `$iv = generateRandomBytes(16);` : ''}
    
    // Example text
    $plaintext = "${exampleText}";
    
    // Encrypt
    $encrypted = encryptAes${mode}($plaintext, $key${needsIV ? ', $iv' : ''});
    echo "${encryptedResult}" . $encrypted . "\\n";
    
    // Decrypt
    $decrypted = decryptAes${mode}($encrypted, $key${needsIV ? ', $iv' : ''});
    echo "${decryptedResult}" . $decrypted . "\\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\\n";
}`;
}

// 生成 Rust 代码示例
function generateRustCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const exampleText = getExampleText(lang);
    const encryptedResult = getResultText(lang, 'encrypted');
    const decryptedResult = getResultText(lang, 'decrypted');

    // Rust特定的代码生成逻辑
    const rustMode = mode.toLowerCase();
    const rustPaddingCrate = padding === 'NO_PADDING' ? '' : 'block-padding = "0.3"';

    return `// ${comments.title[lang]}
use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockEncrypt, 
    generic_array::GenericArray, 
    NewBlockCipher
};
${mode !== 'ECB' ? `use aes::cipher::{StreamCipher, StreamCipherSeek};` : ''}
use aes::{Aes128, Aes192, Aes256};
${mode === 'CBC' ? `use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Padding;` : ''}
${padding !== 'NO_PADDING' ? `use block_padding::{Pkcs7, Zeropad};` : ''}
${outputFormat === 'base64' ? `use base64::{encode, decode};` : `use hex::{encode, decode};`}
use std::str;

// ${comments.encrypt[lang]}
fn encrypt_aes_${rustMode}(plaintext: &str, key: &[u8]${needsIV ? ', iv: &[u8]' : ''}) -> Result<String, Box<dyn std::error::Error>> {
    // Verify key length
    if key.len() != ${keyLength / 8} {
        return Err(format!("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}").into());
    }
    
    ${needsIV ? `// Verify IV length
    if iv.len() != 16 {
        return Err("IV must be exactly 16 bytes".into());
    }` : ''}
    
    // Convert plaintext to bytes
    let plaintext_bytes = plaintext.as_bytes();
    
    // Initialize cipher based on key size
    ${keyLength === '128' ?
            `type Aes = Aes128;` : keyLength === '192' ?
                `type Aes = Aes192;` :
                `type Aes = Aes256;`}
    
    ${mode === 'ECB' ?
            `// ECB mode implementation
    // Create key
    let key = GenericArray::from_slice(key);
    let cipher = Aes::new(&key);
    
    // Add padding
    ${padding === 'NO_PADDING' ?
                `// No padding - ensure data is a multiple of block size
    if plaintext_bytes.len() % 16 != 0 {
        return Err("For no padding, data length must be a multiple of 16 bytes".into());
    }
    let mut padded_data = plaintext_bytes.to_vec();` :
                `// Add PKCS7 padding
    let mut padded_data = Vec::with_capacity(plaintext_bytes.len() + 16);
    padded_data.extend_from_slice(plaintext_bytes);
    let block_size = 16;
    let padding_size = block_size - (plaintext_bytes.len() % block_size);
    padded_data.extend(std::iter::repeat(padding_size as u8).take(padding_size));`}
    
    // Encrypt in ECB mode
    let mut blocks = Vec::new();
    for chunk in padded_data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        blocks.extend_from_slice(&block);
    }` :
            mode === 'CBC' ?
                `// CBC mode implementation
    // Setup cipher
    type Cipher = Cbc<Aes, ${padding === 'NO_PADDING' ? 'Zeropad' : 'Pkcs7'}>;
    let cipher = Cipher::new_from_slices(key, iv)?;
    
    // Encrypt
    let blocks = cipher.encrypt_vec(plaintext_bytes);` :
                `// Stream cipher mode implementation
    // This is a simplified example and may need adjustments
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    
    // Initialize cipher
    let mut cipher = ${rustMode}::new(&key, &iv);
    
    // Encrypt
    let mut blocks = plaintext_bytes.to_vec();
    cipher.encrypt(&mut blocks);`}
    
    // Convert to ${outputFormat.toUpperCase()} format
    ${outputFormat === 'base64' ?
            `Ok(encode(&blocks))` :
            `Ok(encode(&blocks))`}
}

// ${comments.decrypt[lang]}
fn decrypt_aes_${rustMode}(ciphertext: &str, key: &[u8]${needsIV ? ', iv: &[u8]' : ''}) -> Result<String, Box<dyn std::error::Error>> {
    // Verify key length
    if key.len() != ${keyLength / 8} {
        return Err(format!("Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}").into());
    }
    
    ${needsIV ? `// Verify IV length
    if iv.len() != 16 {
        return Err("IV must be exactly 16 bytes".into());
    }` : ''}
    
    // Decode from ${outputFormat.toUpperCase()}
    let ciphertext_bytes = decode(ciphertext)?;
    
    // Initialize cipher based on key size
    ${keyLength === '128' ?
            `type Aes = Aes128;` : keyLength === '192' ?
                `type Aes = Aes192;` :
                `type Aes = Aes256;`}
    
    ${mode === 'ECB' ?
            `// ECB mode decryption
    // Create key
    let key = GenericArray::from_slice(key);
    let cipher = Aes::new(&key);
    
    // Decrypt blocks
    let mut plaintext = Vec::new();
    for chunk in ciphertext_bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }
    
    // Remove padding
    ${padding === 'NO_PADDING' ?
                `// No padding - trim trailing zeros if needed
    let mut plaintext = plaintext.to_vec();
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }` :
                `// Remove PKCS7 padding
    let padding_size = plaintext.last().unwrap_or(&0);
    if *padding_size as usize <= 16 {
        plaintext.truncate(plaintext.len() - *padding_size as usize);
    }`}` :
            mode === 'CBC' ?
                `// CBC mode decryption
    // Setup cipher
    type Cipher = Cbc<Aes, ${padding === 'NO_PADDING' ? 'Zeropad' : 'Pkcs7'}>;
    let cipher = Cipher::new_from_slices(key, iv)?;
    
    // Decrypt
    let plaintext = cipher.decrypt_vec(&ciphertext_bytes)?;` :
                `// Stream cipher mode decryption
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    
    // Initialize cipher
    let mut cipher = ${rustMode}::new(&key, &iv);
    
    // Decrypt
    let mut plaintext = ciphertext_bytes.to_vec();
    cipher.decrypt(&mut plaintext);`}
    
    // Convert bytes to string
    Ok(str::from_utf8(&plaintext)?.to_string())
}

// Generate random bytes
fn generate_random_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate random key${needsIV ? ' and IV' : ''}
    let key = generate_random_bytes(${keyLength / 8});
    ${needsIV ? `let iv = generate_random_bytes(16);` : ''}
    
    // Example data
    let plaintext = "${exampleText}";
    
    // Encrypt
    let encrypted = encrypt_aes_${rustMode}(&plaintext, &key${needsIV ? ', &iv' : ''})?;
    println!("${encryptedResult}{}", encrypted);
    
    // Decrypt
    let decrypted = decrypt_aes_${rustMode}(&encrypted, &key${needsIV ? ', &iv' : ''})?;
    println!("${decryptedResult}{}", decrypted);
    
    Ok(())
}`;
}

// 生成 JavaScript 代码示例
function generateJavaScriptCode(lang, mode, padding, keyLength, outputFormat) {
    const comments = getCommentTexts(lang, mode, keyLength, outputFormat);
    const needsIV = mode !== 'ECB';
    const paddingMethod = padding === 'PKCS7' ? 'pkcs7' :
        padding === 'PKCS5' ? 'pkcs5' :
            padding === 'NO_PADDING' ? 'nopadding' : 'pkcs7';

    return `// ${comments.title[lang]}

// ${comments.encrypt[lang]}
/**
 * ${comments.params[lang]}
 * @param {string} plaintext - ${comments.plaintext[lang]}
 * @param {Uint8Array} key - ${comments.key[lang]}
 * ${needsIV ? `* @param {Uint8Array} iv - ${comments.iv[lang]}\n` : ''}* @returns {string} ${comments.returnEncrypt[lang]}
 */
async function encryptAES${mode}(plaintext, key${needsIV ? ', iv' : ''}) {
    // Validate key length
    if (key.length !== ${keyLength / 8}) {
        throw new Error(\`Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}\`);
    }
    
    ${needsIV ? `// Validate IV length
    if (iv.length !== 16) {
        throw new Error('IV must be exactly 16 bytes');
    }` : ''}
    
    // Convert plaintext to bytes
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    
    // Import the key
    const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-${mode}', length: ${keyLength} },
        false,
        ['encrypt']
    );
    
    // Encrypt
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: 'AES-${mode}',
            ${needsIV ? `iv,` : ''}
            ${mode === 'GCM' ? `tagLength: 128,` : ''}
        },
        cryptoKey,
        plaintextBytes
    );
    
    // Convert to ${outputFormat.toUpperCase()}
    ${outputFormat === 'base64' ?
            `return btoa(String.fromCharCode(...new Uint8Array(encrypted)));` :
            `return Array.from(new Uint8Array(encrypted))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');`}
}

// ${comments.decrypt[lang]}
/**
 * ${comments.params[lang]}
 * @param {string} ciphertext - ${comments.ciphertext[lang]}
 * @param {Uint8Array} key - ${comments.key[lang]}
 * ${needsIV ? `* @param {Uint8Array} iv - ${comments.iv[lang]}\n` : ''}* @returns {string} ${comments.returnDecrypt[lang]}
 */
async function decryptAES${mode}(ciphertext, key${needsIV ? ', iv' : ''}) {
    // Validate key length
    if (key.length !== ${keyLength / 8}) {
        throw new Error(\`Key must be exactly ${keyLength / 8} bytes for AES-${keyLength}\`);
    }
    
    ${needsIV ? `// Validate IV length
    if (iv.length !== 16) {
        throw new Error('IV must be exactly 16 bytes');
    }` : ''}
    
    // Convert ${outputFormat.toUpperCase()} to bytes
    ${outputFormat === 'base64' ?
            `const encryptedBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));` :
            `const encryptedBytes = new Uint8Array(
        ciphertext.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );`}
    
    // Import the key
    const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-${mode}', length: ${keyLength} },
        false,
        ['decrypt']
    );
    
    // Decrypt
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'AES-${mode}',
            ${needsIV ? `iv,` : ''}
            ${mode === 'GCM' ? `tagLength: 128,` : ''}
        },
        cryptoKey,
        encryptedBytes
    );
    
    // Convert bytes to string
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

// Generate random key
function generateRandomKey(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

// ${comments.example[lang]}
// 生成${keyLength / 8}字节的随机密钥
const key = generateRandomKey(${keyLength / 8});
${needsIV ? `const iv = generateRandomKey(16);` : ''}

// 加密示例
const plaintext = "${exampleText}";
encryptAES${mode}(plaintext, key${needsIV ? ', iv' : ''})
    .then(encrypted => {
        console.log("${encryptedResult}" + encrypted);
        
        // 解密示例
        return decryptAES${mode}(encrypted, key${needsIV ? ', iv' : ''});
    })
    .then(decrypted => {
        console.log("${decryptedResult}" + decrypted);
    })
    .catch(error => {
        console.error("Error:", error);
    });`;
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