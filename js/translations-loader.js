// 新建一个专门负责加载和应用翻译的文件

// 在DOM完全加载后执行
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM fully loaded, initializing translations");
    
    // 获取当前语言或设置默认语言
    const currentLang = localStorage.getItem('preferred-language') || 'en';
    console.log("Current language:", currentLang);
    
    // 立即应用翻译
    applyTranslations(currentLang);
    
    // 监听语言选择器变化
    const languageSelect = document.getElementById('language-select');
    if (languageSelect) {
        languageSelect.value = currentLang;
        languageSelect.addEventListener('change', function() {
            console.log("Language changed to:", this.value);
            applyTranslations(this.value);
        });
    }
});

// 应用所有翻译，包括HTML内容
function applyTranslations(lang) {
    console.log("Applying translations for:", lang);
    
    if (!translations || !translations[lang]) {
        console.error("Translation data not available for:", lang);
        return;
    }
    
    // 更新页面标题
    document.title = translations[lang].title || 'AES Encryption Online';
    
    // 1. 首先处理所有特殊ID元素
    const specialIds = ['seoDescription'];
    specialIds.forEach(id => {
        const element = document.getElementById(id);
        if (element && translations[lang][id]) {
            console.log(`Updating element with ID ${id}`);
            element.innerHTML = translations[lang][id];
        }
    });
    
    // 2. 处理所有带HTML内容的元素
    const htmlElements = [
        'seoDescription',
        'secureEncryptionText',
        'easyDecryptionText',
        'noRegistrationText',
        'faqAnswer1',
        'faqAnswer2',
        'faqAnswer3'
    ];
    
    htmlElements.forEach(key => {
        if (!translations[lang][key]) return;
        
        document.querySelectorAll(`[data-i18n="${key}"]`).forEach(element => {
            console.log(`Updating HTML element with key ${key}`);
            element.innerHTML = translations[lang][key];
        });
    });
    
    // 3. 普通文本元素
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (translations[lang][key] && !htmlElements.includes(key)) {
            element.textContent = translations[lang][key];
        }
    });
    
    // 4. 输入占位符
    document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
        const key = element.getAttribute('data-i18n-placeholder');
        if (translations[lang][key]) {
            element.placeholder = translations[lang][key];
        }
    });
    
    // 保存语言偏好
    localStorage.setItem('preferred-language', lang);
    
    // 调用其他需要语言信息的函数
    if (typeof updateCodeExamples === 'function') {
        updateCodeExamples(lang);
    }
    
    if (typeof updateEncryptionInfo === 'function') {
        updateEncryptionInfo();
    }
} 