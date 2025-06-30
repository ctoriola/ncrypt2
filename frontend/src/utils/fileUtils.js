// File size constants
export const FILE_SIZE_LIMITS = {
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
  MIN_PASSPHRASE_LENGTH: 8,
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks for large files
};

// Supported file types
export const SUPPORTED_FILE_TYPES = {
  'application/pdf': ['.pdf'],
  'text/plain': ['.txt'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'application/msword': ['.doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
  'application/vnd.ms-excel': ['.xls'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
  'text/csv': ['.csv'],
  'application/zip': ['.zip'],
  'application/x-rar-compressed': ['.rar'],
};

// File validation functions
export const validateFile = (file) => {
  const errors = [];

  // Check file size
  if (file.size > FILE_SIZE_LIMITS.MAX_FILE_SIZE) {
    errors.push(`File size must be less than ${formatFileSize(FILE_SIZE_LIMITS.MAX_FILE_SIZE)}`);
  }

  // Check file type
  const isValidType = Object.values(SUPPORTED_FILE_TYPES).flat().some(ext => 
    file.name.toLowerCase().endsWith(ext)
  );
  
  if (!isValidType) {
    errors.push('File type not supported');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

export const validatePassphrase = (passphrase) => {
  const errors = [];

  if (!passphrase || passphrase.length < FILE_SIZE_LIMITS.MIN_PASSPHRASE_LENGTH) {
    errors.push(`Passphrase must be at least ${FILE_SIZE_LIMITS.MIN_PASSPHRASE_LENGTH} characters long`);
  }

  if (passphrase && passphrase.length > 128) {
    errors.push('Passphrase must be less than 128 characters');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

// File size formatting
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// File encryption utilities
export const generateEncryptionKey = async (passphrase, salt) => {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
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
};

export const encryptFile = async (file, passphrase) => {
  try {
    // Generate salt and derive key
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await generateEncryptionKey(passphrase, salt);

    // Read file data
    const fileBuffer = await file.arrayBuffer();
    
    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt file
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      fileBuffer
    );

    // Combine salt + iv + encrypted data
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);

    return new Blob([combined], { type: 'application/octet-stream' });
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
};

export const decryptFile = async (encryptedBlob, passphrase) => {
  try {
    const encryptedData = await encryptedBlob.arrayBuffer();
    const encryptedArray = new Uint8Array(encryptedData);

    // Extract salt, IV, and encrypted data
    const salt = encryptedArray.slice(0, 16);
    const iv = encryptedArray.slice(16, 28);
    const encrypted = encryptedArray.slice(28);

    // Derive key
    const key = await generateEncryptionKey(passphrase, salt);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted
    );

    return new Blob([decrypted]);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
};

// File download utilities
export const downloadFile = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

// Chunked file processing for large files
export const processFileInChunks = async (file, processChunk, onProgress) => {
  const chunks = Math.ceil(file.size / FILE_SIZE_LIMITS.CHUNK_SIZE);
  const results = [];

  for (let i = 0; i < chunks; i++) {
    const start = i * FILE_SIZE_LIMITS.CHUNK_SIZE;
    const end = Math.min(start + FILE_SIZE_LIMITS.CHUNK_SIZE, file.size);
    const chunk = file.slice(start, end);
    
    const result = await processChunk(chunk, i, chunks);
    results.push(result);
    
    if (onProgress) {
      onProgress((i + 1) / chunks * 100);
    }
  }

  return results;
};

// File type detection
export const getFileType = (filename) => {
  const extension = filename.toLowerCase().split('.').pop();
  
  const typeMap = {
    'pdf': 'application/pdf',
    'txt': 'text/plain',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'csv': 'text/csv',
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
  };

  return typeMap[extension] || 'application/octet-stream';
};

// File icon mapping
export const getFileIcon = (filename) => {
  const extension = filename.toLowerCase().split('.').pop();
  
  const iconMap = {
    'pdf': '📄',
    'txt': '📝',
    'jpg': '🖼️',
    'jpeg': '🖼️',
    'png': '🖼️',
    'gif': '🖼️',
    'doc': '📄',
    'docx': '📄',
    'xls': '📊',
    'xlsx': '📊',
    'csv': '📊',
    'zip': '📦',
    'rar': '📦',
  };

  return iconMap[extension] || '📄';
}; 