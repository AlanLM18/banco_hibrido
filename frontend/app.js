
let encryptionClient;

const paymentForm = document.getElementById('paymentForm');
const submitBtn = document.getElementById('submitBtn');
const processingIndicator = document.getElementById('processingIndicator');
const resultContainer = document.getElementById('resultContainer');
const resultContent = document.getElementById('resultContent');
const logContent = document.getElementById('logContent');
const securityBadge = document.getElementById('securityBadge');
const securityLayers = document.getElementById('securityLayers');


function addLog(message, type = 'info', data = null) {
    const entry = document.createElement('p');
    entry.className = `log-entry log-${type}`;
    
    const timestamp = new Date().toLocaleTimeString();
    entry.innerHTML = `[${timestamp}] ${message}`;
  
    if (data) {
        const dataDiv = document.createElement('div');
        dataDiv.className = 'log-data';
        dataDiv.style.marginLeft = '20px';
        dataDiv.style.marginTop = '5px';
        dataDiv.style.fontSize = '0.85em';
        dataDiv.style.color = '#93c5fd';
        dataDiv.style.fontFamily = 'monospace';
        dataDiv.style.whiteSpace = 'pre-wrap';
        dataDiv.style.wordBreak = 'break-all';
        
        if (typeof data === 'object') {
            const preview = JSON.stringify(data, null, 2);
            if (preview.length > 500) {
                dataDiv.textContent = preview.substring(0, 500) + '...';
            } else {
                dataDiv.textContent = preview;
            }
        } else {
            dataDiv.textContent = data;
        }
        
        entry.appendChild(dataDiv);
    }
    
    logContent.appendChild(entry);
    logContent.scrollTop = logContent.scrollHeight;
}

function logEncryptedData(label, encryptedPackage) {
    addLog(` ${label}:`, 'info');
    
    const logDiv = document.createElement('div');
    logDiv.className = 'log-data';
    logDiv.style.marginLeft = '20px';
    logDiv.style.marginTop = '5px';
    logDiv.style.fontSize = '0.8em';
    logDiv.style.fontFamily = 'monospace';
    
    logDiv.innerHTML = `
        <div style="color: #fbbf24;"> Datos Cifrados (Base64):</div>
        <div style="color: #93c5fd; margin-top: 5px;">
            <strong>encryptedData:</strong> ${encryptedPackage.encryptedData.substring(0, 80)}...
            <br><span style="color: #6b7280;">(${encryptedPackage.encryptedData.length} caracteres)</span>
        </div>
        <div style="color: #93c5fd; margin-top: 5px;">
            <strong>encryptedKey:</strong> ${encryptedPackage.encryptedKey.substring(0, 80)}...
            <br><span style="color: #6b7280;">(${encryptedPackage.encryptedKey.length} caracteres)</span>
        </div>
        <div style="color: #93c5fd; margin-top: 5px;">
            <strong>iv:</strong> ${encryptedPackage.iv}
        </div>
        <div style="color: #93c5fd; margin-top: 5px;">
            <strong>authTag:</strong> ${encryptedPackage.authTag}
        </div>
        <div style="color: #93c5fd; margin-top: 5px;">
            <strong>timestamp:</strong> ${encryptedPackage.timestamp}
        </div>
    `;
    
    logContent.appendChild(logDiv);
    logContent.scrollTop = logContent.scrollHeight;
}


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


function formatCardNumber(input) {
    let value = input.value.replace(/\s/g, '');
    let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
    input.value = formattedValue;
}

function formatExpiryDate(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length >= 2) {
        value = value.slice(0, 2) + '/' + value.slice(2, 4);
    }
    input.value = value;
}


async function initializeApp() {

    if (securityLayers && securityLayers.parentElement) {
        securityLayers.parentElement.style.display = 'none';
    }
    
    try {

        encryptionClient = new ClientEncryptionService();
        
        const initialized = await encryptionClient.initialize();
        
        if (initialized) {
            
            updateSecurityBadge('active', 'Cifrado activo - Conexión segura');
            submitBtn.disabled = false;
        } else {
            throw new Error('No se pudo inicializar el cifrado');
        }
        
    } catch (error) {
        addLog('Error: ' + error.message, 'error');
        updateSecurityBadge('error', 'Error en la conexión segura');
        submitBtn.disabled = true;
    }
}


async function handlePaymentSubmit(e) {
    e.preventDefault();
    
    submitBtn.disabled = true;
    processingIndicator.style.display = 'block';
    resultContainer.style.display = 'none';
    
    
    try {
        const formData = {
            cardNumber: document.getElementById('cardNumber').value.replace(/\s/g, ''),
            cardHolder: document.getElementById('cardHolder').value,
            expiryDate: document.getElementById('expiryDate').value,
            cvv: document.getElementById('cvv').value,
            amount: parseFloat(document.getElementById('amount').value)
        };
        
        addLog('Datos del formulario recopilados', 'info');
        addLog('Tarjeta: **** **** **** ' + formData.cardNumber.slice(-4), 'info');
        addLog('Titular: ' + formData.cardHolder, 'info');
        addLog('Monto: $' + formData.amount.toFixed(2), 'info');
        
        
        const encryptedPayment = await encryptionClient.encryptForServer(
            JSON.stringify(formData)
        );
        
    
        logEncryptedData('Paquete Cifrado Generado', encryptedPayment);
        

        

        const payload = {
            encryptedPayment: encryptedPayment,
            clientPublicKey: encryptionClient.getClientPublicKey()
        };

        
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

        
        addLog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'info');
        addLog('DESCIFRADO DE RESPUESTA', 'warning');
   
        logEncryptedData('Respuesta Cifrada del Servidor', result.data);
        

        
        const decryptedResponse = await encryptionClient.decryptFromServer(result.data);
        const responseData = JSON.parse(decryptedResponse);
        
        
        addLog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'info');
        addLog('RESULTADO DE LA TRANSACCIÓN', 'warning');
        
        if (responseData.success) {
            addLog('Estado: ' + responseData.transaction.status, 'success');
            addLog('Token: ' + responseData.transaction.token, 'success');
            addLog('Monto: $' + responseData.transaction.amount.toFixed(2), 'success');
            addLog('Pago procesado exitosamente', 'success');
        }
        

        displayResult(responseData);
        

        if (responseData.success) {
            paymentForm.reset();
        }
        
    } catch (error) {
        addLog(' Error: ' + error.message, 'error');
        displayError(error.message);
    } finally {
        submitBtn.disabled = false;
        processingIndicator.style.display = 'none';
    }
}


function displayResult(data) {
    resultContainer.style.display = 'block';
    
    if (data.success) {
        resultContent.innerHTML = `
            <div class="result-success">
                <div class="result-title">
                    <span>${data.message}</span>
                </div>
                
                <div class="result-details">
                    <div class="detail-row">
                        <span class="detail-label">Token de Transacción:</span>
                        <span class="detail-value">${data.transaction.token}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Monto:</span>
                        <span class="detail-value">$${data.transaction.amount.toFixed(2)} ${data.transaction.currency}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Tarjeta:</span>
                        <span class="detail-value">**** **** **** ${data.transaction.cardLast4}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Titular:</span>
                        <span class="detail-value">${data.transaction.cardHolder}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label"Estado:</span>
                        <span class="detail-value">${data.transaction.status}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Fecha:</span>
                        <span class="detail-value">${new Date(data.transaction.timestamp).toLocaleString()}</span>
                    </div>
                </div>
            </div>
        `;
    } else {
        displayError(data.error || 'Error desconocido');
    }
    
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


function displayError(message) {
    resultContainer.style.display = 'block';
    
    resultContent.innerHTML = `
        <div class="result-error">
            <div class="result-title">
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

document.getElementById('cardNumber').addEventListener('input', function() {
    formatCardNumber(this);
});

document.getElementById('expiryDate').addEventListener('input', function() {
    formatExpiryDate(this);
});

document.getElementById('cvv').addEventListener('input', function() {
    this.value = this.value.replace(/\D/g, '');
});

document.getElementById('cardHolder').addEventListener('input', function() {
    this.value = this.value.toUpperCase();
});

paymentForm.addEventListener('submit', handlePaymentSubmit);


document.addEventListener('DOMContentLoaded', initializeApp);
