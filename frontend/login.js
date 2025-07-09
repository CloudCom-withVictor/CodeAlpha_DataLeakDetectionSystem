async function login() {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value.trim();
  const secret = document.getElementById('secret').value.trim();

  if (!email || !password) {
    showToast('⚠️ Email and password are required.', 3000, 'warn');
    return;
  }

  try {
    const res = await fetch('https://86beqm147d.execute-api.us-east-1.amazonaws.com//api/users/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || '❌ Login failed', 3000, 'error');
      return;
    }

    localStorage.setItem('token', data.token);
    localStorage.setItem('capabilities', JSON.stringify(data.capabilities));
    showToast(data.message || '✅ Login successful!', 2000, 'success');

    // Store secret if user has permission
    if (secret && data.capabilities.includes('store')) {
      const storeRes = await fetch('https://86beqm147d.execute-api.us-east-1.amazonaws.com/api/users/store', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${data.token}`
        },
        body: JSON.stringify({ sensitive: secret })
      });

      const storeData = await storeRes.json();
      if (!storeRes.ok) {
        showToast(storeData.error || '⚠️ Failed to store secret.', 3000, 'warn');
      }
    }

    // Redirect to dashboard
    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 1500);

  } catch (err) {
    console.error('Login error:', err);
    showToast('🔌 Network error. Please check your connection.', 3000, 'error');
  }
}
