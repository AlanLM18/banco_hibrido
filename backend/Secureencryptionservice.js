const crypto = require('crypto');

class SecureEncryptionService {
  constructor() {
    this.asymmetricAlgorithm = 'rsa';
    this.symmetricAlgorithm = 'aes-256-gcm';
    this.keySize = 2048;
    this.symmetricKeySize = 32;
    this.hashAlgorithm = 'sha256';
  }

  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(this.asymmetricAlgorithm, {
      modulusLength: this.keySize,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    return { publicKey, privateKey };
  }


  hashData(data) {
    return crypto.createHash(this.hashAlgorithm).update(data).digest('hex');
  }


  encrypt(data, recipientPublicKey) {
    try {
      const symmetricKey = crypto.randomBytes(this.symmetricKeySize);
      const iv = crypto.randomBytes(12);

      const cipher = crypto.createCipheriv(this.symmetricAlgorithm, symmetricKey, iv);
      let encryptedData = cipher.update(data, 'utf8', 'base64');
      encryptedData += cipher.final('base64');
      const authTag = cipher.getAuthTag();


      const encryptedSymmetricKey = crypto.publicEncrypt(
        {
          key: recipientPublicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        symmetricKey
      );

      const timestamp = Date.now();

      return {
        encryptedData: encryptedData,
        encryptedKey: encryptedSymmetricKey.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        timestamp: timestamp,
        algorithm: this.symmetricAlgorithm
      };
    } catch (error) {
      throw new Error(`Error en cifrado: ${error.message}`);
    }
  }


  decrypt(encryptedPackage, privateKey) {
    try {
      const { encryptedData, encryptedKey, iv, authTag, timestamp } = encryptedPackage;

      const currentTime = Date.now();
      const timeDiff = currentTime - timestamp;
      const MAX_AGE = 5 * 60 * 1000; // 5 minutos

      if (timeDiff > MAX_AGE) {
        throw new Error('Token expirado - posible ataque de replay');
      }

      const symmetricKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(encryptedKey, 'base64')
      );

      const ivBuffer = Buffer.from(iv, 'base64');
      
      const decipher = crypto.createDecipheriv(
        this.symmetricAlgorithm,
        symmetricKey,
        ivBuffer
      );

      decipher.setAuthTag(Buffer.from(authTag, 'base64'));

      let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
      decryptedData += decipher.final('utf8');

      return decryptedData;
    } catch (error) {
      throw new Error(`Error en descifrado: ${error.message}`);
    }
  }

  validateCardNumber(cardNumber) {
    const digits = cardNumber.replace(/\D/g, '');
    let sum = 0;
    let isEven = false;

    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits[i]);

      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }


  maskCardNumber(cardNumber) {
    const cleaned = cardNumber.replace(/\D/g, '');
    if (cleaned.length < 4) return '****';
    return '**** **** **** ' + cleaned.slice(-4);
  }


  generateTransactionToken() {
    return 'TXN_' + crypto.randomBytes(16).toString('hex').toUpperCase();
  }
}

module.exports = SecureEncryptionService;
