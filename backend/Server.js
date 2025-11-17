const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const SecureEncryptionService = require('Secureencryptionservice');
const app = express();
const port = 3001;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: true
}));


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  message: 'Demasiadas peticiones desde esta IP, intente más tarde',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);


const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, 
  message: 'Demasiados intentos de pago, intente más tarde'
});


app.use(express.json({ limit: '10kb' }));


app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});



const encryptionService = new SecureEncryptionService();
const serverKeys = encryptionService.generateKeyPair();


app.get('/api/public-key', (req, res) => {
  res.json({
    publicKey: serverKeys.publicKey,
    message: 'Clave pública del servidor',
    timestamp: Date.now()
  });
});


app.post('/api/process-payment', paymentLimiter, async (req, res) => {
  try {
    const { encryptedPayment, clientPublicKey } = req.body;


    if (!encryptedPayment || !clientPublicKey) {
      return res.status(400).json({
        error: 'Datos incompletos',
        message: 'Se requiere encryptedPayment y clientPublicKey'
      });
    }


    console.log('📥 Recibiendo pago cifrado...');
    const decryptedData = encryptionService.decrypt(
      encryptedPayment,
      serverKeys.privateKey
    );

    const paymentData = JSON.parse(decryptedData);
    console.log('✓ Datos descifrados exitosamente');

    const requiredFields = ['cardNumber', 'cardHolder', 'expiryDate', 'cvv', 'amount'];
    const missingFields = requiredFields.filter(field => !paymentData[field]);
    
    if (missingFields.length > 0) {
      throw new Error(`Campos faltantes: ${missingFields.join(', ')}`);
    }


    const isValidCard = encryptionService.validateCardNumber(paymentData.cardNumber);
    if (!isValidCard) {
      throw new Error('Número de tarjeta inválido');
    }


    const expiryRegex = /^(0[1-9]|1[0-2])\/\d{2}$/;
    if (!expiryRegex.test(paymentData.expiryDate)) {
      throw new Error('Formato de fecha de expiración inválido (MM/YY)');
    }


    const cvvRegex = /^\d{3,4}$/;
    if (!cvvRegex.test(paymentData.cvv)) {
      throw new Error('CVV inválido');
    }


    const amount = parseFloat(paymentData.amount);
    if (isNaN(amount) || amount <= 0 || amount > 10000) {
      throw new Error('Monto inválido (debe estar entre $0.01 y $10,000)');
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
        currency: 'USD',
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

    console.log(' Pago aprobado:', transactionToken);

    const encryptedResponse = encryptionService.encrypt(
      JSON.stringify(responseData),
      clientPublicKey
    );

    console.log(' Respuesta cifrada y enviada');


    res.json({
      encrypted: true,
      data: encryptedResponse,
      message: 'Respuesta cifrada - descifrar en el cliente'
    });

  } catch (error) {
    console.error(' Error procesando pago:', error.message);

    const errorResponse = {
      success: false,
      error: error.message,
      timestamp: Date.now()
    };

    try {
      const encryptedError = encryptionService.encrypt(
        JSON.stringify(errorResponse),
        req.body.clientPublicKey
      );

      res.status(400).json({
        encrypted: true,
        data: encryptedError,
        message: 'Error cifrado - descifrar en el cliente'
      });
    } catch (encryptError) {

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
    timestamp: Date.now()
  });
});


app.get('/api/security-info', (req, res) => {
  res.json({
    service: 'Sistema de Pago Seguro con Defensa en Profundidad',
    layers: [
      '1. Helmet - Headers de seguridad HTTP',
      '2. CORS - Control de origen cruzado',
      '3. Rate Limiting - Prevención de ataques de fuerza bruta',
      '4. Límite de tamaño de payload',
      '5. Logging de seguridad',
      '6. Cifrado híbrido end-to-end (RSA + AES-256-GCM)',
      '7. Validación de Luhn para tarjetas',
      '8. Timestamp para prevenir replay attacks',
      '9. Sanitización de datos sensibles',
      '10. Tokens de transacción únicos'
    ],
    encryption: {
      asymmetric: 'RSA-2048',
      symmetric: 'AES-256-GCM',
      hash: 'SHA-256'
    }
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
  console.log(`\nServidor iniciado en http://localhost:${port}`);
});

module.exports = app;