const token = localStorage.getItem('token');
const capabilities = JSON.parse(localStorage.getItem('capabilities') || '[]');

if (!token) {
  showToast('🔐 Not logged in', 2500, 'warn');
  setTimeout(() => (window.location.href = 'index.html'), 2500);
}

if (!capabilities.includes('store')) {
  document.getElementById('secretInput').disabled = true;
}

async function storeSecret() {
  const secret = document.getElementById('secretInput').value.trim();
  if (!secret) return showToast('⚠️ Secret is empty.', 2500, 'warn');

  try {
    const res = await fetch('https://86beqm147d.execute-api.us-east-1.amazonaws.com/api/users/store', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ sensitive: secret }),
    });

    const data = await res.json();
    showToast(data.message || data.error, 3000, res.ok ? 'success' : 'error');
    document.getElementById('secretInput').value = '';
    loadSecrets();
  } catch {
    showToast('❌ Failed to store secret.', 3000, 'error');
  }
}

async function loadSecrets() {
  try {
    const res = await fetch('https://86beqm147d.execute-api.us-east-1.amazonaws.com//api/users/read', {
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();
    const grid = document.getElementById('secretsGrid');
    grid.innerHTML = '';

    (data.data || []).forEach((secret) => {
      const card = document.createElement('div');
      card.className = 'secret-card';

      const masked = document.createElement('span');
      masked.className = 'masked';
      masked.textContent = '•'.repeat(secret.data.length);

      const real = document.createElement('span');
      real.className = 'real';
      real.textContent = secret.data;
      real.style.display = 'none';

      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'toggle-btn';
      toggleBtn.innerText = '👁️';
      toggleBtn.onclick = () => {
        const isVisible = real.style.display === 'inline';
        real.style.display = isVisible ? 'none' : 'inline';
        masked.style.display = isVisible ? 'inline' : 'none';
        toggleBtn.innerText = isVisible ? '👁️' : '🙈';
      };

      const timestamp = document.createElement('div');
      timestamp.className = 'timestamp';
      timestamp.textContent = `📅 ${new Date(secret.created_at).toLocaleString()}`;

      card.append(masked, real, toggleBtn, timestamp);
      grid.appendChild(card);
    });
  } catch {
    showToast('⚠️ Could not load secrets.', 3000, 'error');
  }
}

function logout() {
  localStorage.clear();
  showToast('🚪 Logging out...', 2000, 'info');
  setTimeout(() => (window.location.href = 'index.html'), 2000);
}

loadSecrets();
