// The dark date picker theme is a whole stylesheet; switching it off is simpler than undoing it in custom.css
document.querySelectorAll('link[href*="flatpickr.dark"]').forEach(link => link.disabled = true);
