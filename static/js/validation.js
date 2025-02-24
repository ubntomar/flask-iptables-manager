// Objeto con utilidades de validación IP
const IPValidation = {
    // Validar dirección IP individual
    isValidIP: function(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        
        return parts.every(part => {
            const num = parseInt(part, 10);
            return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
        });
    },

    // Validar máscara de red CIDR
    isValidCIDR: function(cidr) {
        const num = parseInt(cidr, 10);
        return !isNaN(num) && num >= 0 && num <= 32;
    },

    // Validar red en formato IP/CIDR
    isValidNetwork: function(network) {
        // Permitir 'any' como valor válido
        if (network.toLowerCase() === 'any') return true;
        
        // Validar formato IP/CIDR
        if (network.includes('/')) {
            const [ip, cidr] = network.split('/');
            return this.isValidIP(ip) && this.isValidCIDR(cidr);
        }
        
        // Si no tiene CIDR, validar como IP
        return this.isValidIP(network);
    },

    // Validar hostname
    isValidHostname: function(hostname) {
        const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return hostnameRegex.test(hostname) && hostname.length <= 255;
    }
};

// Función para mostrar error
function showError(input, message) {
    clearError(input);
    const div = document.createElement('div');
    div.className = 'error-message';
    div.style.color = '#dc3545';
    div.style.fontSize = '0.875rem';
    div.style.marginTop = '0.25rem';
    div.textContent = message;
    input.parentNode.insertBefore(div, input.nextSibling);
    input.classList.add('is-invalid');
}

// Función para limpiar error
function clearError(input) {
    const errorDiv = input.nextElementSibling;
    if (errorDiv && errorDiv.classList.contains('error-message')) {
        errorDiv.remove();
    }
    input.classList.remove('is-invalid');
}

// Validación de campos de red (IP/CIDR)
function validateNetworkField(input) {
    clearError(input);
    const value = input.value.trim();
    
    if (!value) {
        showError(input, 'Este campo es requerido');
        return false;
    }

    // Validar 'any' como valor especial
    if (value.toLowerCase() === 'any') return true;

    // Validar hostname
    if (IPValidation.isValidHostname(value)) return true;

    // Validar IP o red CIDR
    if (!IPValidation.isValidNetwork(value)) {
        showError(input, 'Formato inválido. Use IP (ej: 192.168.1.1), red CIDR (ej: 192.168.1.0/24), hostname o "any"');
        return false;
    }

    return true;
}

// Función principal de validación
function validateForm(form) {
    let isValid = true;

    // Limpiar errores previos
    form.querySelectorAll('.error-message').forEach(err => err.remove());
    form.querySelectorAll('.is-invalid').forEach(input => input.classList.remove('is-invalid'));

    // Obtener el tipo de formulario (NAT o Filter)
    const natType = form.querySelector('[name="nat_type"]')?.value;
    
    if (natType) {
        // Validación para formulario NAT
        if (natType === 'masquerade') {
            const destination = form.querySelector('[name="destination"]');
            if (destination && destination.value) {
                isValid = validateNetworkField(destination);
            }
        }
    } else {
        // Validación para formulario Filter
        const sourceInput = form.querySelector('[name="source"]');
        const destInput = form.querySelector('[name="destination"]');

        if (sourceInput) {
            isValid = validateNetworkField(sourceInput) && isValid;
        }
        
        if (destInput) {
            isValid = validateNetworkField(destInput) && isValid;
        }
    }

    return isValid;
}

// Inicialización cuando el DOM está listo
document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');
    if (!form) return;

    // Validación al enviar el formulario
    form.addEventListener('submit', (e) => {
        if (!validateForm(form)) {
            e.preventDefault();
        }
    });

    // Validación en tiempo real para campos de red
    const networkInputs = form.querySelectorAll('[name="source"], [name="destination"]');
    networkInputs.forEach(input => {
        input.addEventListener('input', () => {
            if (input.value.trim()) {
                validateNetworkField(input);
            } else {
                clearError(input);
            }
        });

        // Validación inicial si el campo tiene valor
        if (input.value.trim()) {
            validateNetworkField(input);
        }
    });

    // Validación específica para campos NAT si existen
    const natTypeSelect = form.querySelector('[name="nat_type"]');
    if (natTypeSelect) {
        natTypeSelect.addEventListener('change', () => {
            validateForm(form);
        });
    }
});