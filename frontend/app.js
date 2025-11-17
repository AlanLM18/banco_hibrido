// Cliente de Cifrado
let encryptionClient;

// Elementos del DOM
const paymentForm = document.getElementById('paymentForm');
const submitBtn = document.getElementById('submitBtn');
const processingIndicator = document.getElementById('processingIndicator');
const resultContainer = document.getElementById('resultContainer');
const resultContent = document.getElementById('resultContent');
const logContent = document.getElementById('logContent');
const securityBadge = document.getElementById('securityBadge');
const securityLayers = document.getElementById('securityLayers');

/**
 * Agregar entrada al log de cifrado
 */
function addLog(message, type = 'info') {
    const entry = document.createElement('p');
    entry.className = `log-entry log-${type}`;
    
    const timestamp = new Date().toLocaleTimeString();
    entry.textContent = `[${timestamp}] ${message}`;
    
    logContent.appendChild(entry);
    logContent.scrollTop = logContent.scrollHeight;
}

/**
 * Actualizar badge de seguridad
 */
function updateSecurityBadge(status, message) {
    const dot = securityBadge.querySelector('.status-dot');
    const text = securityBadge.querySelector('span:last-child');
    
    if (status === 'active') {
        dot.classList.add('active');
    } else {
        dot.classList.remove('active');
    }
    
    text.textContent = message;
}

/**
 * Cargar información de seguridad
 */
async function loadSecurityInfo() {
    try {
        const response = await fetch('http://localhost:3001/api/security-info');
        const data = await response.json();
        
        securityLayers.innerHTML = data.layers
            .map(layer => `<li>${layer}</li>`)
            .join('');
        
        addLog('✓ Información de seguridad cargada', 'success');
    } catch (error) {
        addLog('⚠ Error cargando información de seguridad', 'warning');
        securityLayers.innerHTML = '<li>⚠️ No se pudo cargar la información de seguridad</li>';
    }
}

/**
 * Formatear número de tarjeta (agregar espacios)
 */
function formatCardNumber(input) {
    let value = input.value.replace(/\s/g, '');
    let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
    input.value = formattedValue;
}

/**
 * Formatear fecha de expiración (agregar /)
 */
function formatExpiryDate(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length >= 2) {
        value = value.slice(0, 2) + '/' + value.slice(2, 4);
    }
    input.value = value;
}

/**
 * Inicializar la aplicación
 */
async function initializeApp() {
    addLog('🔄 Inicializando sistema de pago seguro...', 'info');
    
    try {
        // Inicializar cliente de cifrado
        encryptionClient = new ClientEncryptionService();
        addLog('🔑 Generando claves RSA del cliente...', 'info');
        
        const initialized = await encryptionClient.initialize();
        
        if (initialized) {
            addLog('✓ Claves del cliente generadas (RSA-2048)', 'success');
            addLog('✓ Clave pública del servidor obtenida', 'success');
            addLog('🔒 Canal de cifrado establecido', 'success');
            
            updateSecurityBadge('active', 'Cifrado activo - Conexión segura');
            
            // Habilitar formulario
            submitBtn.disabled = false;
        } else {
            throw new Error('No se pudo inicializar el cifrado');
        }
        
        // Cargar información de seguridad
        await loadSecurityInfo();
        
    } catch (error) {
        addLog('❌ Error: ' + error.message, 'error');
        updateSecurityBadge('error', 'Error en la conexión segura');
        submitBtn.disabled = true;
    }
}

/**
 * Procesar el formulario de pago
 */
async function handlePaymentSubmit(e) {
    e.preventDefault();
    
    // Deshabilitar botón y mostrar indicador
    submitBtn.disabled = true;
    processingIndicator.style.display = 'block';
    resultContainer.style.display = 'none';
    
    addLog('📤 Iniciando procesamiento de pago...', 'info');
    
    try {
        // Recopilar datos del formulario
        const formData = {
            cardNumber: document.getElementById('cardNumber').value.replace(/\s/g, ''),
            cardHolder: document.getElementById('cardHolder').value,
            expiryDate: document.getElementById('expiryDate').value,
            cvv: document.getElementById('cvv').value,
            amount: parseFloat(document.getElementById('amount').value)
        };
        
        addLog('🔒 Cifrando datos con AES-256-GCM...', 'info');
        
        // Cifrar datos del pago
        const encryptedPayment = await encryptionClient.encryptForServer(
            JSON.stringify(formData)
        );
        
        addLog('✓ Datos cifrados exitosamente', 'success');
        addLog('🔐 Cifrando clave AES con RSA-2048...', 'info');
        addLog('✓ Clave AES cifrada', 'success');
        
        // Preparar datos para enviar
        const payload = {
            encryptedPayment: encryptedPayment,
            clientPublicKey: encryptionClient.getClientPublicKey()
        };
        
        addLog('📡 Enviando datos cifrados al servidor...', 'info');
        
        // Enviar al backend
        const response = await fetch('http://localhost:3001/api/process-payment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Error del servidor: ${response.status}`);
        }
        
        const result = await response.json();
        
        addLog('✓ Respuesta recibida del servidor', 'success');
        addLog('🔓 Descifrando respuesta...', 'info');
        
        // Descifrar respuesta
        const decryptedResponse = await encryptionClient.decryptFromServer(result.data);
        const responseData = JSON.parse(decryptedResponse);
        
        addLog('✓ Respuesta descifrada exitosamente', 'success');
        
        // Mostrar resultado
        displayResult(responseData);
        
        // Limpiar formulario si fue exitoso
        if (responseData.success) {
            paymentForm.reset();
            addLog('🎉 Pago procesado exitosamente', 'success');
        }
        
    } catch (error) {
        addLog('❌ Error: ' + error.message, 'error');
        displayError(error.message);
    } finally {
        submitBtn.disabled = false;
        processingIndicator.style.display = 'none';
    }
}

/**
 * Mostrar resultado exitoso
 */
function displayResult(data) {
    resultContainer.style.display = 'block';
    
    if (data.success) {
        resultContent.innerHTML = `
            <div class="result-success">
                <div class="result-title">
                    <span>✅</span>
                    <span>${data.message}</span>
                </div>
                
                <div class="result-details">
                    <div class="detail-row">
                        <span class="detail-label">🎫 Token de Transacción:</span>
                        <span class="detail-value">${data.transaction.token}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">💵 Monto:</span>
                        <span class="detail-value">$${data.transaction.amount.toFixed(2)} ${data.transaction.currency}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">💳 Tarjeta:</span>
                        <span class="detail-value">**** **** **** ${data.transaction.cardLast4}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">👤 Titular:</span>
                        <span class="detail-value">${data.transaction.cardHolder}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">✅ Estado:</span>
                        <span class="detail-value">${data.transaction.status}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">🕐 Fecha:</span>
                        <span class="detail-value">${new Date(data.transaction.timestamp).toLocaleString()}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">🔐 Cifrado:</span>
                        <span class="detail-value">${data.security.algorithm}</span>
                    </div>
                </div>
            </div>
        `;
    } else {
        displayError(data.error || 'Error desconocido');
    }
    
    // Scroll al resultado
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Mostrar error
 */
function displayError(message) {
    resultContainer.style.display = 'block';
    
    resultContent.innerHTML = `
        <div class="result-error">
            <div class="result-title">
                <span>❌</span>
                <span>Error en el Pago</span>
            </div>
            <p style="margin-top: 10px; color: #991b1b;">
                ${message}
            </p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #b91c1c;">
                Por favor, verifica los datos e intenta nuevamente.
            </p>
        </div>
    `;
    
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Event Listeners
 */

// Formateo automático de campos
document.getElementById('cardNumber').addEventListener('input', function() {
    formatCardNumber(this);
});

document.getElementById('expiryDate').addEventListener('input', function() {
    formatExpiryDate(this);
});

// Prevenir caracteres no numéricos en CVV
document.getElementById('cvv').addEventListener('input', function() {
    this.value = this.value.replace(/\D/g, '');
});

// Solo mayúsculas en titular
document.getElementById('cardHolder').addEventListener('input', function() {
    this.value = this.value.toUpperCase();
});

// Submit del formulario
paymentForm.addEventListener('submit', handlePaymentSubmit);

// Inicializar al cargar la página
document.addEventListener('DOMContentLoaded', initializeApp);