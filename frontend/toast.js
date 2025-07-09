function showToast(message = '', duration = 3000, type = 'info') {
  let toast = document.getElementById('toast');

  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    document.body.appendChild(toast);
  }

  toast.className = `show ${type}`;
  toast.textContent = message;

  setTimeout(() => {
    toast.className = toast.className.replace(`show ${type}`, '');
  }, duration);
}
