(function() {
    const STORAGE_KEY = 'auraknow-theme';

    function getThemePreference() {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved) return saved;
        return 'system';
    }

    function getSystemTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        const actualTheme = theme === 'system' ? getSystemTheme() : theme;
        document.documentElement.setAttribute('data-theme', actualTheme);
        
        // Update toggles on the page
        document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-theme-value') === theme);
        });
    }

    window.setTheme = function(theme) {
        localStorage.setItem(STORAGE_KEY, theme);
        applyTheme(theme);
    };

    // Initial apply (run immediately to prevent flash)
    const initialTheme = getThemePreference();
    applyTheme(initialTheme);

    // Listen for system changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (getThemePreference() === 'system') {
            applyTheme('system');
        }
    });

    // Handle toggle clicks
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.theme-toggle-btn');
        if (btn) {
            const theme = btn.getAttribute('data-theme-value');
            if (theme) window.setTheme(theme);
        }
    });
})();
