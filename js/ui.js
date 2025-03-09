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