// cryptoWorker.js

// Import sodium.js into the worker context. Adjust the path as needed.
importScripts('sodium.js');

(async () => {
  console.log("Worker: Starting initialization...");
  await sodium.ready;
  console.log("Worker: Libsodium is ready.");
  
  if (typeof sodium.crypto_pwhash !== "function") {
    console.log("Worker ERROR: sodium.crypto_pwhash is not available.");
    return;
  }
  
  // -------------------------------
  // Lazy Getter for MAGIC
  // -------------------------------
  function getMagic() {
    console.log("getMagic: Converting 'HYBRID02__' to ArrayBuffer");
    return strToArrayBuffer("HYBRID02__");
  }
  
  // -------------------------------
  // Constants and Parameters
  // -------------------------------
  console.log("Worker: Defining constants and parameters...");
  const NONCE_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12 bytes
  const ARGON2_MEMLIMIT = 128 * 1024 * 1024; // 128 MB
  const ARGON2_OPSLIMIT = 5;
  const ARGON2_HASHLEN = 64; // derive 64 bytes; we use the first 32 bytes
  
  // -------------------------------
  // Helper Functions for Conversions
  // -------------------------------
  console.log("Worker: Setting up conversion helpers...");
  function strToArrayBuffer(str) {
    const buf = new TextEncoder().encode(str);
    console.log("strToArrayBuffer: Converted string", str, "to buffer", buf);
    return buf;
  }
  
  function arrayBufferToStr(buf) {
    const str = new TextDecoder().decode(buf);
    console.log("arrayBufferToStr: Converted buffer", buf, "to string", str);
    return str;
  }
  
  function concatArrayBuffers(...buffers) {
    const totalLength = buffers.reduce((acc, b) => acc + b.byteLength, 0);
    const temp = new Uint8Array(totalLength);
    let offset = 0;
    buffers.forEach(b => {
      temp.set(new Uint8Array(b), offset);
      offset += b.byteLength;
    });
    console.log("concatArrayBuffers: Concatenated buffers to total length", totalLength);
    return temp.buffer;
  }
  
  function numberToBuffer(num, byteLength) {
    const arr = new Uint8Array(byteLength);
    for (let i = byteLength - 1; i >= 0; i--) {
      arr[i] = num & 0xff;
      num = num >> 8;
    }
    console.log(`numberToBuffer: Converted number to ${byteLength} bytes:`, arr);
    return arr.buffer;
  }
  
  function timingSafeEqual(buf1, buf2) {
    if (buf1.length !== buf2.length) return false;
    let result = 0;
    for (let i = 0; i < buf1.length; i++) {
      result |= buf1[i] ^ buf2[i];
    }
    const eq = result === 0;
    console.log("timingSafeEqual: Comparison result =", eq);
    return eq;
  }
  
  function arrayBufferToHex(buffer) {
    const hex = Array.from(new Uint8Array(buffer))
      .map(b => ('00' + b.toString(16)).slice(-2))
      .join('');
    console.log("arrayBufferToHex: Converted buffer to hex:", hex);
    return hex;
  }
  
  function hexStringToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
      throw new Error("Invalid hex string");
    }
    const array = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
      array[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    console.log("hexStringToUint8Array: Converted hex string to Uint8Array:", array);
    return array;
  }
  
  // -------------------------------
  // Nonce Generation with Counter to Prevent Reuse
  // -------------------------------
  console.log("Worker: Setting up nonce generator...");
  let nonceCounter = 0;
  function getUniqueNonce() {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, nonceCounter++, false); // big-endian
    const randomPart = sodium.randombytes_buf(NONCE_BYTES - counterBytes.length);
    const nonceBuffer = concatArrayBuffers(counterBytes.buffer, randomPart);
    const nonce = new Uint8Array(nonceBuffer);
    console.log("getUniqueNonce: Generated nonce =", nonce);
    return nonce;
  }
  
  // -------------------------------
  // HMAC Calculation using crypto_auth_hmacsha256
  // -------------------------------
  console.log("Worker: Setting up HMAC calculation...");
  function computeHMAC(key, data) {
    const hmac = sodium.crypto_auth_hmacsha256(data, key);
    console.log("computeHMAC: Computed HMAC =", new Uint8Array(hmac));
    return hmac;
  }
  
  // -------------------------------
  // Utility: Generate a Random Salt String (Length 32)
  // -------------------------------
  console.log("Worker: Setting up salt generator...");
  function generateRandomSaltString() {
    const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[]{}|;:,.<>?/";
    let result = "";
    for (let i = 0; i < 32; i++) {
      result += charset.charAt(sodium.randombytes_uniform(charset.length));
    }
    console.log("generateRandomSaltString: Generated salt string =", result);
    return result;
  }
  
  // -------------------------------
  // Argon2id Key Derivation (Password-Only)
  // -------------------------------
  console.log("Worker: Setting up Argon2id key derivation function...");
  async function deriveKeyArgon2id(password, saltStr) {
    console.log("deriveKeyArgon2id: Starting with password =", password, "and saltStr =", saltStr);
    const salt = strToArrayBuffer(saltStr).slice(0, sodium.crypto_pwhash_SALTBYTES);
    const derived = sodium.crypto_pwhash(
      ARGON2_HASHLEN, // 64 bytes output
      password,       // plaintext password
      salt,
      ARGON2_OPSLIMIT,
      ARGON2_MEMLIMIT,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    try {
      sodium.memzero(salt);
      console.log("deriveKeyArgon2id: Salt wiped from memory.");
    } catch (e) {
      console.warn("deriveKeyArgon2id: Failed to wipe salt:", e);
    }
    const finalKey = derived.slice(0, 32);
    console.log("deriveKeyArgon2id: Derived key (first 32 bytes):", new Uint8Array(finalKey));
    return finalKey;
  }
  
  // -------------------------------
  // ChaCha20-Poly1305 Encryption/Decryption
  // -------------------------------
  console.log("Worker: Setting up ChaCha20-Poly1305 functions...");
  function chacha20Poly1305Encrypt(key, data) {
    const nonce = getUniqueNonce();
    console.log("chacha20Poly1305Encrypt: Using nonce =", nonce);
    // Pass an empty Uint8Array for additional data.
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      data,
      new Uint8Array(0),
      null,
      nonce,
      key
    );
    console.log("chacha20Poly1305Encrypt: Ciphertext length =", ciphertext.length);
    return { nonce, ciphertext };
  }
  
  function chacha20Poly1305Decrypt(key, nonce, ciphertext) {
    console.log("chacha20Poly1305Decrypt: Decrypting with nonce =", nonce);
    const plaintext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      new Uint8Array(0),
      ciphertext,
      null,
      nonce,
      key
    );
    console.log("chacha20Poly1305Decrypt: Decrypted plaintext length =", plaintext.byteLength);
    return plaintext;
  }
  
  // -------------------------------
  // Hybrid Encryption with HMAC Authentication
  // Container Format:
  // [MAGIC (10)]
  // [Argon2 salt (32)]
  // [Password wrap nonce (12)]
  // [Password wrapped key length (2)]
  // [Password wrapped session key (variable)]
  // [File nonce (12)]
  // [File ciphertext length (8)]
  // [File ciphertext (variable)]
  // [HMAC (32)]
  // -------------------------------
  console.log("Worker: Setting up container encryption function...");
  async function encryptContainer(plaintextArrayBuffer, password) {
    console.log("encryptContainer: Starting encryption process.");
    // 1. Generate a random 32-byte session key.
    const sessionKey = sodium.randombytes_buf(32);
    console.log("encryptContainer: Generated session key:", new Uint8Array(sessionKey));
    
    // 2. Encrypt the plaintext using ChaCha20-Poly1305.
    const fileNonce = getUniqueNonce();
    console.log("encryptContainer: Generated file nonce:", fileNonce);
    const fileCiphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      new Uint8Array(plaintextArrayBuffer),
      new Uint8Array(0),
      null,
      fileNonce,
      sessionKey
    );
    console.log("encryptContainer: Encrypted file ciphertext length:", fileCiphertext.length);
    
    // 3. Compute HMAC over the file ciphertext.
    const hmacKey = sodium.crypto_generichash(32, sessionKey);
    const hmac = computeHMAC(hmacKey, fileCiphertext);
    
    // 4. Password Wrap: Derive a wrapping key from the password using Argon2id.
    const argon2SaltStr = generateRandomSaltString();
    console.log("encryptContainer: Generated Argon2 salt string:", argon2SaltStr);
    const passWrapKey = await deriveKeyArgon2id(password, argon2SaltStr);
    const { nonce: passWrapNonce, ciphertext: passWrapped } = chacha20Poly1305Encrypt(passWrapKey, sessionKey);
    console.log("encryptContainer: Wrapped session key length:", passWrapped.length);
    
    // Securely wipe sensitive key materials.
    try { sodium.memzero(new Uint8Array(sessionKey)); console.log("encryptContainer: Session key wiped."); } catch (e) { console.warn("encryptContainer: Failed to wipe sessionKey", e); }
    try { sodium.memzero(passWrapKey); console.log("encryptContainer: Password wrap key wiped."); } catch (e) { console.warn("encryptContainer: Failed to wipe passWrapKey", e); }
    try { sodium.memzero(hmacKey); console.log("encryptContainer: HMAC key wiped."); } catch (e) { console.warn("encryptContainer: Failed to wipe hmacKey", e); }
    
    // 5. Build the container.
    const magic = getMagic();
    const passWrappedLenBuf = numberToBuffer(passWrapped.length, 2);
    const fileCiphertextLenBuf = numberToBuffer(fileCiphertext.length, 8);
    const argon2SaltBuf = strToArrayBuffer(argon2SaltStr);
    
    const containerBuffer = concatArrayBuffers(
      magic,
      argon2SaltBuf,
      passWrapNonce,
      passWrappedLenBuf,
      passWrapped,
      fileNonce,
      fileCiphertextLenBuf,
      fileCiphertext,
      hmac
    );
    console.log("encryptContainer: Container encryption complete. Container length:", containerBuffer.byteLength);
    return containerBuffer;
  }
  
  console.log("Worker: Setting up container decryption function...");
  async function decryptContainer(containerArrayBuffer, password) {
    console.log("decryptContainer: Starting decryption process.");
    if (!password) {
      throw new Error("Password is required for decryption.");
    }
    const data = new Uint8Array(containerArrayBuffer);
    let offset = 0;
    
    // 1. Verify MAGIC header.
    const magic = data.slice(offset, offset + getMagic().byteLength);
    offset += getMagic().byteLength;
    if (arrayBufferToStr(magic.buffer) !== arrayBufferToStr(getMagic())) {
      throw new Error("Invalid container format (magic mismatch).");
    }
    console.log("decryptContainer: MAGIC header verified.");
    
    // 2. Read Argon2 salt.
    const argon2SaltBytes = data.slice(offset, offset + 32);
    offset += 32;
    const argon2SaltStr = arrayBufferToStr(argon2SaltBytes.buffer);
    console.log("decryptContainer: Extracted Argon2 salt:", argon2SaltStr);
    
    // 3. Read password wrap nonce.
    const passWrapNonce = data.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    console.log("decryptContainer: Extracted passWrapNonce:", new Uint8Array(passWrapNonce));
    
    // 4. Read wrapped session key length and wrapped session key.
    const passWrappedLen = new DataView(data.buffer, offset, 2).getUint16(0);
    offset += 2;
    const passWrapped = data.slice(offset, offset + passWrappedLen);
    offset += passWrappedLen;
    console.log("decryptContainer: Extracted wrapped session key length:", passWrappedLen);
    
    // 5. Read file nonce.
    const fileNonce = data.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    console.log("decryptContainer: Extracted file nonce:", new Uint8Array(fileNonce));
    
    // 6. Read file ciphertext length and file ciphertext.
    const fileCiphertextLen = Number(new DataView(data.buffer, offset, 8).getBigUint64(0));
    offset += 8;
    const fileCiphertext = data.slice(offset, offset + fileCiphertextLen);
    offset += fileCiphertextLen;
    console.log("decryptContainer: Extracted file ciphertext length:", fileCiphertextLen);
    
    // 7. Read HMAC.
    const hmacStored = data.slice(offset, offset + 32);
    offset += 32;
    console.log("decryptContainer: Extracted stored HMAC:", new Uint8Array(hmacStored));
    
    // 8. Recover the session key using the password wrap.
    let passSessionKey;
    try {
      const passWrapKey = await deriveKeyArgon2id(password, argon2SaltStr);
      passSessionKey = chacha20Poly1305Decrypt(passWrapKey, passWrapNonce, passWrapped);
      try { sodium.memzero(passWrapKey); console.log("decryptContainer: passWrapKey wiped."); } catch (e) { console.warn("decryptContainer: Failed to wipe passWrapKey", e); }
      console.log("decryptContainer: Recovered session key:", new Uint8Array(passSessionKey));
    } catch (e) {
      throw new Error("Password-based decryption failed. Incorrect password or corrupted data.");
    }
    
    // 9. Verify HMAC over file ciphertext.
    const hmacKey = sodium.crypto_generichash(32, passSessionKey);
    const hmacComputed = computeHMAC(hmacKey, fileCiphertext);
    if (!timingSafeEqual(hmacStored, hmacComputed)) {
      throw new Error("HMAC verification failed. Data integrity compromised.");
    }
    try { sodium.memzero(hmacKey); console.log("decryptContainer: hmacKey wiped."); } catch (e) { console.warn("decryptContainer: Failed to wipe hmacKey", e); }
    console.log("decryptContainer: HMAC verification passed.");
    
    // 10. Decrypt the file ciphertext using the session key.
    let plaintext;
    try {
      plaintext = chacha20Poly1305Decrypt(passSessionKey, fileNonce, fileCiphertext);
      try { sodium.memzero(passSessionKey); console.log("decryptContainer: Session key wiped."); } catch (e) { console.warn("decryptContainer: Failed to wipe sessionKey", e); }
    } catch (e) {
      throw new Error("File decryption failed. Data may be corrupted or the password is incorrect.");
    }
    console.log("decryptContainer: Decryption complete. Plaintext length:", plaintext.byteLength);
    return plaintext.buffer;
  }
  
  // -------------------------------
  // Message Handling in the Worker
  // -------------------------------
  console.log("Worker: Setting up message handler...");
  self.onmessage = async function (e) {
    const { action, payload, requestId } = e.data;
    console.log("Worker: Received message. Action:", action, "RequestId:", requestId);
    try {
      let result;
      if (action === 'encryptContainer') {
        console.log("Worker: Starting encryption action.");
        result = await encryptContainer(payload.plaintext, payload.password);
        result = arrayBufferToHex(result);
        console.log("Worker: Encryption complete. Container (hex):", result);
      } else if (action === 'decryptContainer') {
        console.log("Worker: Starting decryption action.");
        const containerBuffer = hexStringToUint8Array(payload.container).buffer;
        result = await decryptContainer(containerBuffer, payload.password);
        result = arrayBufferToHex(result);
        console.log("Worker: Decryption complete. Plaintext (hex):", result);
      } else {
        throw new Error("Worker: Unknown action.");
      }
      self.postMessage({ status: 'success', result, requestId });
    } catch (err) {
      console.error("Worker: Error during processing:", err);
      self.postMessage({ status: 'error', error: "An error occurred during cryptographic processing.", requestId });
    }
  };

})();