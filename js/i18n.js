// 强制更新所有包含HTML标签的翻译内容
function refreshHtmlContent() {
    const currentLang = localStorage.getItem('preferred-language') || 'en';

    // 需要HTML渲染的特殊元素IDs
    const specialElements = [
        'seoDescription'
    ];

    // 需要HTML渲染的data-i18n属性值
    const htmlAttributeKeys = [
        'seoDescription',
        'secureEncryptionText',
        'easyDecryptionText',
        'noRegistrationText',
        'faqAnswer1',
        'faqAnswer2',
        'faqAnswer3'
    ];

    // 更新特殊元素
    specialElements.forEach(id => {
        const element = document.getElementById(id);
        if (element && translations[currentLang][id]) {
            element.innerHTML = translations[currentLang][id];
        }
    });

    // 更新带有data-i18n属性的元素
    htmlAttributeKeys.forEach(key => {
        document.querySelectorAll(`[data-i18n="${key}"]`).forEach(element => {
            if (translations[currentLang][key]) {
                element.innerHTML = translations[currentLang][key];
            }
        });
    });
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

    // 强制刷新HTML内容
    setTimeout(refreshHtmlContent, 100);

    // 为语言更改添加事件监听器
    languageSelect.addEventListener('change', function () {
        updateLanguage(this.value);
        setTimeout(refreshHtmlContent, 100); // 语言更改后额外刷新
    });
}

// 更新所有文本元素为选定的语言
function updateLanguage(lang) {
    console.log("Updating language to:", lang);

    // 更新页面标题
    document.title = translations[lang].title;

    // 为包含HTML的特定元素进行特殊处理 - 移到最前面优先处理
    const seoDescriptionEl = document.getElementById('seoDescription');
    if (seoDescriptionEl && translations[lang]["seoDescription"]) {
        console.log("Updating seoDescription:", translations[lang]["seoDescription"].substring(0, 50) + "...");
        seoDescriptionEl.innerHTML = translations[lang]["seoDescription"];
    } else {
        console.warn("Could not update seoDescription", {
            element: seoDescriptionEl,
            hasTranslation: translations[lang]["seoDescription"] ? true : false
        });
    }

    // 更新带有data-i18n属性的所有文本元素
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (translations[lang][key]) {
            // 使用innerHTML而不是textContent以正确渲染HTML标签
            element.innerHTML = translations[lang][key];
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

    // 为包含HTML标签的元素添加特殊处理
    document.querySelectorAll('[data-html-i18n]').forEach(element => {
        const key = element.getAttribute('data-html-i18n');
        if (translations[lang][key]) {
            element.innerHTML = translations[lang][key];
        }
    });

    // 更新底部SEO内容区域
    const secureEncryptionTextEl = document.querySelector('[data-i18n="secureEncryptionText"]');
    const easyDecryptionTextEl = document.querySelector('[data-i18n="easyDecryptionText"]');
    const noRegistrationTextEl = document.querySelector('[data-i18n="noRegistrationText"]');

    if (secureEncryptionTextEl && translations[lang]["secureEncryptionText"]) {
        secureEncryptionTextEl.innerHTML = translations[lang]["secureEncryptionText"];
    }

    if (easyDecryptionTextEl && translations[lang]["easyDecryptionText"]) {
        easyDecryptionTextEl.innerHTML = translations[lang]["easyDecryptionText"];
    }

    if (noRegistrationTextEl && translations[lang]["noRegistrationText"]) {
        noRegistrationTextEl.innerHTML = translations[lang]["noRegistrationText"];
    }

    // 保存语言偏好
    localStorage.setItem('preferred-language', lang);

    // 更新代码示例中的注释语言
    updateCodeExamples(lang);

    // 更新加密信息区域（如果存在）
    updateEncryptionInfo();
} 