// 主题管理
(function() {
    // DOM加载完成后运行
    document.addEventListener('DOMContentLoaded', function() {
        // 初始化主题设置
        initTheme();
        
        // 主题切换按钮绑定事件
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', toggleTheme);
        }
    });

    // 初始化主题
    function initTheme() {
        // 获取保存的主题或使用系统偏好
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        // 如果保存了主题设置则使用，否则根据系统偏好
        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
            document.documentElement.classList.add('dark');
            updateThemeIcon(true);
        } else {
            document.documentElement.classList.remove('dark');
            updateThemeIcon(false);
        }
    }

    // 切换主题
    function toggleTheme() {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateThemeIcon(isDark);
    }

    // 更新主题图标
    function updateThemeIcon(isDark) {
        const themeIcon = document.querySelector('#theme-toggle i');
        if (themeIcon) {
            if (isDark) {
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
            } else {
                themeIcon.classList.remove('fa-sun');
                themeIcon.classList.add('fa-moon');
            }
        }
    }
})(); 