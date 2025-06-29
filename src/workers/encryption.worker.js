// Encryption Worker for NCryp
// Handles client-side encryption and upload coordination

class EncryptionWorker {
  constructor() {
    this.chunkSize = 5 * 1024 * 1024; // 5MB chunks
    this.uploadQueue = [];
    this.isProcessing = false;
  }

  // Generate cryptographically secure random values
  generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  // Derive encryption key from passphrase
  async deriveKey(passphrase, salt) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Encrypt a single chunk
  async encryptChunk(chunk, key, iv) {
    try {
      const arrayBuffer = await chunk.arrayBuffer();
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        arrayBuffer
      );
      return encrypted;
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  // Process file in chunks
  async processFile(file, passphrase) {
    const salt = this.generateRandomBytes(16);
    const key = await this.deriveKey(passphrase, salt);
    const totalChunks = Math.ceil(file.size / this.chunkSize);
    let processedChunks = 0;

    // Generate file metadata
    const fileMetadata = {
      filename: file.name,
      size: file.size,
      mimeType: file.type,
      totalChunks: totalChunks,
      salt: Array.from(salt),
      uploadDate: new Date().toISOString()
    };

    // Send metadata first
    self.postMessage({
      action: "METADATA_READY",
      payload: fileMetadata
    });

    // Process chunks
    for (let offset = 0; offset < file.size; offset += this.chunkSize) {
      const chunk = file.slice(offset, offset + this.chunkSize);
      const iv = this.generateRandomBytes(12);
      
      try {
        const encrypted = await this.encryptChunk(chunk, key, iv);
        
        const chunkData = {
          encrypted: Array.from(new Uint8Array(encrypted)),
          iv: Array.from(iv),
          index: Math.floor(offset / this.chunkSize),
          size: chunk.size
        };

        // Add to upload queue
        this.uploadQueue.push(chunkData);
        
        processedChunks++;
        const progress = Math.round((processedChunks / totalChunks) * 100);
        
        self.postMessage({
          action: "PROGRESS_UPDATE",
          payload: { progress, processedChunks, totalChunks }
        });

        // Trigger upload if not already processing
        if (!this.isProcessing) {
          this.processUploadQueue();
        }

      } catch (error) {
        self.postMessage({
          action: "ERROR",
          payload: { error: error.message, chunkIndex: Math.floor(offset / this.chunkSize) }
        });
        return;
      }
    }

    // Wait for all uploads to complete
    while (this.uploadQueue.length > 0 || this.isProcessing) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    self.postMessage({
      action: "ENCRYPTION_COMPLETE",
      payload: { fileId: fileMetadata.filename }
    });
  }

  // Process upload queue
  async processUploadQueue() {
    if (this.isProcessing || this.uploadQueue.length === 0) {
      return;
    }

    this.isProcessing = true;

    while (this.uploadQueue.length > 0) {
      const chunkData = this.uploadQueue.shift();
      
      try {
        // Send chunk for upload
        self.postMessage({
          action: "UPLOAD_CHUNK",
          payload: chunkData
        });

        // Small delay to prevent overwhelming the server
        await new Promise(resolve => setTimeout(resolve, 50));
      } catch (error) {
        self.postMessage({
          action: "ERROR",
          payload: { error: `Upload failed: ${error.message}`, chunkIndex: chunkData.index }
        });
      }
    }

    this.isProcessing = false;
  }

  // Decrypt file
  async decryptFile(encryptedData, passphrase, salt, iv) {
    try {
      const key = await this.deriveKey(passphrase, new Uint8Array(salt));
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        key,
        new Uint8Array(encryptedData).buffer
      );
      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}

// Initialize worker
const worker = new EncryptionWorker();

// Handle messages from main thread
self.onmessage = async (event) => {
  const { type, data } = event.data;

  try {
    switch (type) {
      case "ENCRYPT_AND_UPLOAD":
        await worker.processFile(data.file, data.passphrase);
        break;

      case "DECRYPT_FILE":
        const decrypted = await worker.decryptFile(
          data.encryptedData,
          data.passphrase,
          data.salt,
          data.iv
        );
        self.postMessage({
          action: "DECRYPTION_COMPLETE",
          payload: { decryptedData: decrypted }
        });
        break;

      case "CANCEL_OPERATION":
        worker.uploadQueue = [];
        worker.isProcessing = false;
        self.postMessage({
          action: "OPERATION_CANCELLED"
        });
        break;

      default:
        self.postMessage({
          action: "ERROR",
          payload: { error: `Unknown operation: ${type}` }
        });
    }
  } catch (error) {
    self.postMessage({
      action: "ERROR",
      payload: { error: error.message }
    });
  }
};

// Handle errors
self.onerror = (error) => {
  self.postMessage({
    action: "ERROR",
    payload: { error: `Worker error: ${error.message}` }
  });
}; 