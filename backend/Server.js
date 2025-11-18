const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const SecureEncryptionService = require('./Secureencryptionservice');

const app = express();
const port = 3001;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: true
}));


app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, 
});

app.use(express.json({ limit: '10kb' }));


app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});


const encryptionService = new SecureEncryptionService();
const serverKeys = encryptionService.generateKeyPair();



function normalizeExpiryDate(date) {

  const cleaned = date.replace(/\D/g, '');
  
  if (cleaned.length === 4) {

    return cleaned.substring(0, 2) + '/' + cleaned.substring(2);
  } else if (cleaned.length === 6) {
    return cleaned.substring(0, 2) + '/' + cleaned.substring(4);
  }
  
  return date;
}

app.get('/', (req, res) => {
  res.json({
    message: 'Sistema de Pago Seguro con Cifrado Híbrido',
    status: 'online',
    encryption: 'RSA-2048 + AES-256-GCM'
  });
});

app.get('/api/public-key', (req, res) => {
  try {
    console.log('Enviando clave pública al cliente');
    res.json({
      publicKey: serverKeys.publicKey,
      message: 'Clave pública del servidor',
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Error enviando clave pública:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/process-payment', paymentLimiter, async (req, res) => {
  try {
    const { encryptedPayment, clientPublicKey } = req.body;

    console.log('Recibiendo pago cifrado...');
    console.log('Datos recibidos:', {
      hasEncryptedPayment: !!encryptedPayment,
      hasClientPublicKey: !!clientPublicKey,
      encryptedPaymentKeys: encryptedPayment ? Object.keys(encryptedPayment) : []
    });

    if (!encryptedPayment || !clientPublicKey) {
      console.log('Datos incompletos');
      return res.status(400).json({
        error: 'Datos incompletos',
        message: 'Se requiere encryptedPayment y clientPublicKey',
        received: {
          encryptedPayment: !!encryptedPayment,
          clientPublicKey: !!clientPublicKey
        }
      });
    }

    let decryptedData;
    try {
      console.log('Descifrando datos del pago...');
      decryptedData = encryptionService.decrypt(
        encryptedPayment,
        serverKeys.privateKey
      );
      console.log('Datos descifrados exitosamente');
    } catch (decryptError) {
      console.error('Error descifrando:', decryptError.message);
      return res.status(400).json({
        error: 'Error en descifrado',
        message: decryptError.message
      });
    }

    let paymentData;
    try {
      paymentData = JSON.parse(decryptedData);
      console.log('JSON parseado correctamente');
      console.log('Datos del pago:', {
        cardHolder: paymentData.cardHolder,
        cardNumber: paymentData.cardNumber ? '****' + paymentData.cardNumber.slice(-4) : 'N/A',
        expiryDate: paymentData.expiryDate,
        amount: paymentData.amount
      });
    } catch (parseError) {
      console.error('Error parseando JSON:', parseError.message);
      return res.status(400).json({
        error: 'Error parseando datos',
        message: 'Formato de datos inválido'
      });
    }

    const requiredFields = ['cardNumber', 'cardHolder', 'expiryDate', 'cvv', 'amount'];
    const missingFields = requiredFields.filter(field => !paymentData[field]);
    
    if (missingFields.length > 0) {
      console.log('Campos faltantes:', missingFields);
      return res.status(400).json({
        error: 'Campos faltantes',
        message: `Se requieren: ${missingFields.join(', ')}`
      });
    }

    const normalizedDate = normalizeExpiryDate(paymentData.expiryDate);
    console.log('Fecha normalizada:', normalizedDate);
    
    const expiryRegex = /^(0[1-9]|1[0-2])\/\d{2}$/;
    if (!expiryRegex.test(normalizedDate)) {
      console.log('Formato de fecha inválido:', normalizedDate);
      return res.status(400).json({
        error: 'Formato de fecha inválido',
        message: 'Use formato MM/YY (ejemplo: 12/25)',
        received: paymentData.expiryDate,
        normalized: normalizedDate
      });
    }

    const isValidCard = encryptionService.validateCardNumber(paymentData.cardNumber);
    if (!isValidCard) {
      console.log('Número de tarjeta inválido (Luhn)');
      return res.status(400).json({
        error: 'Número de tarjeta inválido',
        message: 'El número de tarjeta no pasa la validación de Luhn'
      });
    }

    const cvvRegex = /^\d{3,4}$/;
    if (!cvvRegex.test(paymentData.cvv)) {
      console.log('❌ CVV inválido');
      return res.status(400).json({
        error: 'CVV inválido',
        message: 'El CVV debe tener 3 o 4 dígitos'
      });
    }


    const amount = parseFloat(paymentData.amount);
    if (isNaN(amount) || amount <= 0 || amount > 10000) {
      console.log(' Monto inválido:', amount);
      return res.status(400).json({
        error: 'Monto inválido',
        message: 'El monto debe estar entre $0.01 y $10,000'
      });
    }


    console.log('Procesando pago...');
    console.log(`   Tarjeta: ${encryptionService.maskCardNumber(paymentData.cardNumber)}`);
    console.log(`   Titular: ${paymentData.cardHolder}`);
    console.log(`   Monto: $${amount.toFixed(2)}`);

    await new Promise(resolve => setTimeout(resolve, 1000));

    const transactionToken = encryptionService.generateTransactionToken();
    const timestamp = new Date().toISOString();

    const responseData = {
      success: true,
      message: 'Pago procesado exitosamente',
      transaction: {
        token: transactionToken,
        amount: amount,
        currency: 'MXN',
        cardLast4: paymentData.cardNumber.slice(-4),
        cardHolder: paymentData.cardHolder,
        timestamp: timestamp,
        status: 'APPROVED'
      },
      security: {
        encrypted: true,
        algorithm: 'RSA-2048 + AES-256-GCM',
        timestamp: Date.now()
      }
    };

    console.log('Pago aprobado:', transactionToken);

    const encryptedResponse = encryptionService.encrypt(
      JSON.stringify(responseData),
      clientPublicKey
    );

    console.log('Respuesta cifrada y enviada\n');

    res.json({
      encrypted: true,
      data: encryptedResponse,
      message: 'Respuesta cifrada'
    });

  } catch (error) {
    console.error('Error procesando pago:', error);
    console.error('Stack:', error.stack);

    const errorResponse = {
      success: false,
      error: error.message,
      timestamp: Date.now()
    };

    try {
      if (req.body.clientPublicKey) {
        const encryptedError = encryptionService.encrypt(
          JSON.stringify(errorResponse),
          req.body.clientPublicKey
        );

        res.status(400).json({
          encrypted: true,
          data: encryptedError,
          message: 'Error cifrado'
        });
      } else {
        res.status(400).json(errorResponse);
      }
    } catch (encryptError) {
      console.error('Error cifrando respuesta de error:', encryptError);
      res.status(500).json({
        error: 'Error procesando la transacción',
        encrypted: false
      });
    }
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'Secure Payment Gateway',
    encryption: 'Hybrid (RSA-2048 + AES-256-GCM)',
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});


app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

app.use((err, req, res, next) => {
  console.error('Error global:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(port, () => {
});

module.exports = app;
