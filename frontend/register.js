async function register() {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value.trim();

  if (!email || !password) {
    showToast('⚠️ Email and password are required.', 3000, 'warn');
    return;
  }

  try {
    const res = await fetch('https://86beqm147d.execute-api.us-east-1.amazonaws.com/api/users/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || '❌ Registration failed', 3000, 'error');
      return;
    }

    // ✅ Show success message
    showToast(data.message || '🎉 Registration successful!', 3000, 'success');

    // ✅ Redirect to login after a delay
    setTimeout(() => {
      window.location.href = 'index.html'; // or login.html if separated
    }, 1500);

  } catch (err) {
    console.error('Register error:', err);
    showToast('🔌 Network error. Try again later.', 3000, 'error');
  }
}
