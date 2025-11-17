/**
 * Cliente de Cifrado Híbrido para el Frontend
 * Maneja el cifrado/descifrado en el navegador
 */
class ClientEncryptionService {
  constructor() {
    this.serverPublicKey = null;
    this.clientKeys = null;
  }

  /**
   * Inicializar: Obtener clave pública del servidor
   */
  async initialize() {
    try {
      const response = await fetch('http://localhost:3001/api/public-key');
      const data = await response.json();
      this.serverPublicKey = data.publicKey;
      
      // Generar claves del cliente
      await this.generateClientKeys();
      
      return true;
    } catch (error) {
      console.error('Error inicializando cifrado:', error);
      return false;
    }
  }

  /**
   * Generar par de claves RSA para el cliente
   */
  async generateClientKeys() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
      );

      this.clientKeys = keyPair;

      // Exportar clave pública para enviarla al servidor
      const exportedPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );

      this.clientPublicKeyPEM = this.arrayBufferToPEM(exportedPublicKey, 'PUBLIC KEY');
    } catch (error) {
      console.error('Error generando claves del cliente:', error);
      throw error;
    }
  }

  /**
   * Convertir ArrayBuffer a formato PEM
   */
  arrayBufferToPEM(buffer, label) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const formatted = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----\n`;
  }

  /**
   * Convertir PEM a ArrayBuffer
   */
  pemToArrayBuffer(pem) {
    const b64 = pem
      .replace(/-----BEGIN .*-----/, '')
      .replace(/-----END .*-----/, '')
      .replace(/\s/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Cifrar datos para enviar al servidor
   * Usa el cifrado híbrido nativo del navegador
   */
  async encryptForServer(data) {
    try {
      // Generar clave AES
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      // IV aleatorio
      const iv = window.crypto.getRandomValues(new Uint8Array(12));

      // Cifrar datos con AES
      const encoder = new TextEncoder();
      const encryptedData = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        encoder.encode(data)
      );

      // Exportar clave AES
      const exportedAESKey = await window.crypto.subtle.exportKey("raw", aesKey);

      // Importar clave pública del servidor
      const serverPublicKeyBuffer = this.pemToArrayBuffer(this.serverPublicKey);
      const importedServerKey = await window.crypto.subtle.importKey(
        "spki",
        serverPublicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      // Cifrar clave AES con RSA
      const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedServerKey,
        exportedAESKey
      );

      // Convertir a base64
      const encryptedDataB64 = btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
      const encryptedKeyB64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey)));
      const ivB64 = btoa(String.fromCharCode(...iv));

      return {
        encryptedData: encryptedDataB64,
        encryptedKey: encryptedKeyB64,
        iv: ivB64,
        authTag: '', // GCM incluye authTag en encryptedData
        timestamp: Date.now(),
        algorithm: 'aes-256-gcm'
      };
    } catch (error) {
      console.error('Error cifrando datos:', error);
      throw error;
    }
  }

  /**
   * Descifrar respuesta del servidor
   */
  async decryptFromServer(encryptedPackage) {
    try {
      // Decodificar de base64
      const encryptedKeyBuffer = Uint8Array.from(atob(encryptedPackage.encryptedKey), c => c.charCodeAt(0));
      const encryptedDataBuffer = Uint8Array.from(atob(encryptedPackage.encryptedData), c => c.charCodeAt(0));
      const ivBuffer = Uint8Array.from(atob(encryptedPackage.iv), c => c.charCodeAt(0));

      // Descifrar clave AES con clave privada del cliente
      const decryptedAESKey = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        this.clientKeys.privateKey,
        encryptedKeyBuffer
      );

      // Importar clave AES
      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        decryptedAESKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Descifrar datos
      const decryptedData = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuffer },
        aesKey,
        encryptedDataBuffer
      );

      // Convertir a string
      const decoder = new TextDecoder();
      return decoder.decode(decryptedData);
    } catch (error) {
      console.error('Error descifrando datos:', error);
      throw error;
    }
  }

  /**
   * Obtener clave pública del cliente (para enviar al servidor)
   */
  getClientPublicKey() {
    return this.clientPublicKeyPEM;
  }
}

// Exportar para uso global
window.ClientEncryptionService = ClientEncryptionService;