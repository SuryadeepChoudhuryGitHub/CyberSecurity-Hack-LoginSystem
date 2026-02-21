// DOM references
const passwordInput   = document.getElementById('password');
const usernameInput   = document.getElementById('username');
const toggleBtn       = document.getElementById('toggleBtn');
const strengthMeter   = document.getElementById('strengthMeter');
const strengthLabel   = document.getElementById('strengthLabel');
const strengthScore   = document.getElementById('strengthScore');
const meterBar        = document.getElementById('meterBar');
const crackBox        = document.getElementById('crackBox');
const crackTime       = document.getElementById('crackTime');
const checksSection   = document.getElementById('checksSection');
const suggestionsBox  = document.getElementById('suggestionsBox');
const suggestionsList = document.getElementById('suggestionsList');
const shieldIndicator = document.getElementById('shieldIndicator');
const shieldIcon      = document.getElementById('shieldIcon');
const shieldLabel     = document.getElementById('shieldLabel');
const emptyState      = document.getElementById('emptyState');
const registerBtn     = document.getElementById('registerBtn');
const toast           = document.getElementById('toast');

let debounceTimer;
let allChecksPassed = false;

// ── Toggle password visibility ──────────────────────────────
toggleBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleBtn.textContent = isPassword ? '⌣' : '👁';
});

// ── Live password analysis ───────────────────────────────────
passwordInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const val = passwordInput.value;
    if (!val) {
        hideAnalysis();
        return;
    }
    debounceTimer = setTimeout(() => analyzePassword(val), 180);
});

// ── Update register button state ─────────────────────────────
usernameInput.addEventListener('input', updateRegisterBtn);

function updateRegisterBtn() {
    registerBtn.disabled = !(allChecksPassed && usernameInput.value.trim().length >= 3);
}

// ── Fetch analysis from backend ──────────────────────────────
async function analyzePassword(password) {
    try {
        const resp = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await resp.json();
        renderAnalysis(data);
    } catch (err) {
        console.error('Analysis failed:', err);
    }
}

// ── Render analysis results ──────────────────────────────────
function renderAnalysis(data) {
    // Hide empty state, show analysis panels
    emptyState.style.display      = 'none';
    strengthMeter.style.display   = 'block';
    shieldIndicator.style.display = 'flex';
    crackBox.style.display        = 'block';
    checksSection.style.display   = 'block';
    suggestionsBox.style.display  = 'block';

    // Strength bar (left panel)
    meterBar.style.width      = data.score + '%';
    meterBar.style.background = data.color;
    strengthLabel.textContent = data.strength;
    strengthLabel.style.color = data.color;
    strengthScore.textContent = `${data.score}/100`;

    // Shield emoji (right panel)
    const shields = {
        'Very Weak'  : '💀',
        'Weak'       : '⚠️',
        'Moderate'   : '🔒',
        'Strong'     : '🛡️',
        'Very Strong': '🔐'
    };
    shieldIcon.textContent  = shields[data.strength] || '🛡️';
    shieldIcon.style.color  = data.color;
    shieldLabel.textContent = data.strength;
    shieldLabel.style.color = data.color;

    // Crack time
    crackTime.textContent  = data.crack_time;
    crackTime.style.color  = data.color;

    // Requirement checks
    const checkMap = {
        length         : 'check-length',
        lowercase      : 'check-lowercase',
        uppercase      : 'check-uppercase',
        digit          : 'check-digit',
        special        : 'check-special',
        no_consecutive : 'check-no_consecutive'
    };

    let allPass = true;
    for (const [key, elId] of Object.entries(checkMap)) {
        const el     = document.getElementById(elId);
        const passed = data.checks[key];
        if (!passed) allPass = false;
        el.className = 'check-item ' + (passed ? 'pass' : 'fail');
    }
    allChecksPassed = allPass;

    // Suggestions
    if (data.suggestions.length > 0) {
        suggestionsList.innerHTML = data.suggestions
            .map(s => `<div class="suggestion-item">
                            <span class="suggestion-arrow">›</span>
                            <span>${s}</span>
                        </div>`)
            .join('');
    } else {
        suggestionsList.innerHTML = `<div class="suggestion-item">
            <span class="suggestion-arrow" style="color:var(--good)">✓</span>
            <span style="color:var(--good)">All requirements met — great password!</span>
        </div>`;
    }

    updateRegisterBtn();
}

// ── Hide all analysis panels, show empty state ────────────────
function hideAnalysis() {
    emptyState.style.display      = 'flex';
    strengthMeter.style.display   = 'none';
    shieldIndicator.style.display = 'none';
    crackBox.style.display        = 'none';
    checksSection.style.display   = 'none';
    suggestionsBox.style.display  = 'none';
    allChecksPassed = false;
    updateRegisterBtn();
}

// ── Register account ──────────────────────────────────────────
registerBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    registerBtn.disabled    = true;
    registerBtn.textContent = 'Creating Account...';

    try {
        const resp = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();

        showToast(data.message, data.success ? 'success' : 'error');

        if (data.success) {
            usernameInput.value = '';
            passwordInput.value = '';
            hideAnalysis();
        }
    } catch (err) {
        showToast('Something went wrong. Please try again.', 'error');
    } finally {
        registerBtn.textContent = 'Create Account';
        updateRegisterBtn();
    }
});

// ── Toast notification ────────────────────────────────────────
function showToast(message, type) {
    toast.textContent = message;
    toast.className   = `toast ${type}`;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3500);
}