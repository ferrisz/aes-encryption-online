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
        
        // 重新更新加密信息区域
        updateEncryptionInfo();
        
        // 更新代码示例
        const activeTab = document.querySelector('nav.flex button.border-primary-500');
        if (activeTab) {
            const language = activeTab.querySelector('span').textContent.toLowerCase();
            const lang = document.getElementById('language-select').value;
            updateCodeExamples(lang, language);
        }
    });

    // 随机生成密钥和IV
    randomKeyBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            const input = this.previousElementSibling;
            const isIV = input.getAttribute('data-i18n-placeholder') === 'enterIv';
            const length = isIV ? 16 : parseInt(document.getElementById('key-length').value) / 8;
            
            input.value = generateRandomString(length);
        });
    });

    // 加密按钮
    encryptBtn.addEventListener('click', function() {
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
    decryptBtn.addEventListener('click', function() {
        const ciphertext = inputTextarea.value.trim();
        if (!ciphertext) {
            alert(translations[document.getElementById('language-select').value].enterText);
            return;
        }
        
        try {
            // 实际应用中，这里会调用真正的解密函数
            // 这里只是一个演示，简单模拟解密结果
            let decryptedText;
            try {
                decryptedText = atob(ciphertext);
            } catch (e) {
                throw new Error("Invalid Base64 input");
            }
            outputElement.textContent = decryptedText;
            
            // 更新信息区
            updateEncryptionInfo();
        } catch (error) {
            alert('Decryption error: ' + error.message);
        }
    });

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

// 生成随机字符串
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
} 