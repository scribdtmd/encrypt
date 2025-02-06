// cryptoWorker.js

// Import sodium.js into the worker context. Adjust the path as needed.
importScripts('sodium.js');

let deviceKeyGlobal = null; // Since localStorage isn’t available, we keep the device key here.

(async () => {
  // Wait until sodium is fully initialized.
  await sodium.ready;

  // Check that crypto_pwhash is available.
  if (typeof sodium.crypto_pwhash !== "function") {
    console.error("sodium.crypto_pwhash is not available.");
    return;
  }
  console.log("Worker: Sodium is ready.");

  // ===============================
  // Helper Functions for Conversions, etc.
  // ===============================
  function strToArrayBuffer(str) {
    return new TextEncoder().encode(str);
  }

  function arrayBufferToStr(buf) {
    return new TextDecoder().decode(buf);
  }

  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    bytes.forEach(b => (binary += String.fromCharCode(b)));
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function concatArrayBuffers(...buffers) {
    const totalLength = buffers.reduce((acc, b) => acc + b.byteLength, 0);
    const temp = new Uint8Array(totalLength);
    let offset = 0;
    buffers.forEach(b => {
      temp.set(new Uint8Array(b), offset);
      offset += b.byteLength;
    });
    return temp.buffer;
  }

  // Write a number into a fixed-length ArrayBuffer in big-endian.
  function numberToBuffer(num, byteLength) {
    const arr = new Uint8Array(byteLength);
    for (let i = byteLength - 1; i >= 0; i--) {
      arr[i] = num & 0xff;
      num = num >> 8;
    }
    return arr.buffer;
  }

  // Constant-time comparison of two Uint8Arrays.
  function timingSafeEqual(buf1, buf2) {
    if (buf1.length !== buf2.length) return false;
    let result = 0;
    for (let i = 0; i < buf1.length; i++) {
      result |= buf1[i] ^ buf2[i];
    }
    return result === 0;
  }

  // ===============================
  // Device Key Management (Worker Version)
  // ===============================
  async function getDeviceKeyForEncryption() {
    if (deviceKeyGlobal) {
      return deviceKeyGlobal;
    } else {
      const newKey = sodium.randombytes_buf(32);
      deviceKeyGlobal = newKey.buffer;
      return newKey.buffer;
    }
  }

  async function getDeviceKeyForDecryption() {
    return deviceKeyGlobal;
  }

  // ===============================
  // Constants
  // ===============================
  const MAGIC = strToArrayBuffer("HYBRID02__"); // 10-byte magic header
  const NONCE_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12 bytes

  // Argon2id parameters.
  const ARGON2_MEMLIMIT = 128 * 1024 * 1024; // 128 MB
  const ARGON2_OPSLIMIT = 5;
  const ARGON2_HASHLEN = 64;

  // ===============================
  // Utility: Generate a random salt string of length 32.
  // ===============================
  function generateRandomSaltString() {
    const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[]{}|;:,.<>?/";
    let result = "";
    for (let i = 0; i < 32; i++) {
      result += charset.charAt(sodium.randombytes_uniform(charset.length));
    }
    return result;
  }

  // ===============================
  // Argon2id Key Derivation
  // ===============================
  // Derives a 64-byte key from the password then returns the first 32 bytes.
  async function deriveKeyArgon2id(password, saltStr) {
    const fullSalt = strToArrayBuffer(saltStr);
    const salt = fullSalt.slice(0, sodium.crypto_pwhash_SALTBYTES);
    const derived = sodium.crypto_pwhash(
      ARGON2_HASHLEN,  // outlen
      password,        // password (string)
      salt,            // salt (Uint8Array)
      ARGON2_OPSLIMIT, // opslimit
      ARGON2_MEMLIMIT, // memlimit
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    return derived.slice(0, 32);
  }

  // ===============================
  // ChaCha20-Poly1305 Encryption/Decryption
  // ===============================
  function chacha20Poly1305Encrypt(key, data) {
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      data,
      null,
      null,
      nonce,
      key
    );
    return { nonce, ciphertext };
  }

  function chacha20Poly1305Decrypt(key, nonce, ciphertext) {
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      key
    );
  }

  // ===============================
  // Hybrid Encryption Function
  // ===============================
  async function encryptContainer(plaintextArrayBuffer, password) {
    // 1. Generate a random 32-byte session key.
    const sessionKey = sodium.randombytes_buf(32);

    // 2. File Encryption using ChaCha20–Poly1305.
    const fileNonce = sodium.randombytes_buf(NONCE_BYTES);
    const fileCiphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      new Uint8Array(plaintextArrayBuffer),
      null,
      null,
      fileNonce,
      sessionKey
    );

    // 3. Password Wrap:
    const argon2SaltStr = generateRandomSaltString();
    const passWrapKey = await deriveKeyArgon2id(password, argon2SaltStr);
    const { nonce: passWrapNonce, ciphertext: passWrapped } = chacha20Poly1305Encrypt(passWrapKey, sessionKey);

    // 4. Device Wrap:
    const deviceKeyBuffer = await getDeviceKeyForEncryption();
    const deviceKey = new Uint8Array(deviceKeyBuffer);
    const { nonce: deviceWrapNonce, ciphertext: deviceWrapped } = chacha20Poly1305Encrypt(deviceKey, sessionKey);

    // 5. Build the container.
    // Structure:
    // [MAGIC (10 bytes)]
    // [Argon2 salt (32 bytes)] + [Password wrap nonce (12 bytes)]
    // [Password wrapped key length (2 bytes)] + [Password wrapped session key (ciphertext)]
    // [Device wrap nonce (12 bytes)]
    // [Device wrapped key length (2 bytes)] + [Device wrapped session key (ciphertext)]
    // [File nonce (12 bytes)]
    // [File ciphertext length (8 bytes)] + [File ciphertext]
    const passWrappedLenBuf = numberToBuffer(passWrapped.length, 2);
    const deviceWrappedLenBuf = numberToBuffer(deviceWrapped.length, 2);
    const fileCiphertextLenBuf = numberToBuffer(fileCiphertext.length, 8);
    const argon2SaltBuf = strToArrayBuffer(argon2SaltStr);

    const containerBuffer = concatArrayBuffers(
      MAGIC,
      argon2SaltBuf,
      passWrapNonce,
      passWrappedLenBuf,
      passWrapped,
      deviceWrapNonce,
      deviceWrappedLenBuf,
      deviceWrapped,
      fileNonce,
      fileCiphertextLenBuf,
      fileCiphertext
    );
    return containerBuffer;
  }

  // ===============================
  // Hybrid Decryption Function
  // ===============================
  async function decryptContainer(containerArrayBuffer, password) {
    if (!password) {
      throw new Error("Password is required for decryption.");
    }
    const data = new Uint8Array(containerArrayBuffer);
    let offset = 0;

    // 1. Verify MAGIC header.
    const magic = data.slice(offset, offset + MAGIC.byteLength);
    offset += MAGIC.byteLength;
    if (arrayBufferToStr(magic.buffer) !== arrayBufferToStr(MAGIC)) {
      throw new Error("Invalid container format (magic mismatch).");
    }

    // 2. Read the Password Wrap section.
    const argon2SaltBytes = data.slice(offset, offset + 32);
    offset += 32;
    const argon2SaltStr = arrayBufferToStr(argon2SaltBytes.buffer);
    const passWrapNonce = data.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    const passWrappedLen = new DataView(data.buffer, offset, 2).getUint16(0);
    offset += 2;
    const passWrapped = data.slice(offset, offset + passWrappedLen);
    offset += passWrappedLen;

    // 3. Read the Device Wrap section.
    const deviceWrapNonce = data.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    const deviceWrappedLen = new DataView(data.buffer, offset, 2).getUint16(0);
    offset += 2;
    const deviceWrapped = data.slice(offset, offset + deviceWrappedLen);
    offset += deviceWrappedLen;

    // 4. Read the File Encryption section.
    const fileNonce = data.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    const fileCiphertextLen = Number(new DataView(data.buffer, offset, 8).getBigUint64(0));
    offset += 8;
    const fileCiphertext = data.slice(offset, offset + fileCiphertextLen);
    offset += fileCiphertextLen;

    // 5. Recover the session key via the Password Wrap.
    let passSessionKey;
    try {
      const passWrapKey = await deriveKeyArgon2id(password, argon2SaltStr);
      passSessionKey = chacha20Poly1305Decrypt(passWrapKey, passWrapNonce, passWrapped);
    } catch (e) {
      throw new Error("Password-based decryption failed. Incorrect password or corrupted data.");
    }

    // 6. Optionally, verify using the Device Wrap.
    const deviceKeyBuffer = await getDeviceKeyForDecryption();
    if (deviceKeyBuffer) {
      try {
        const deviceKey = new Uint8Array(deviceKeyBuffer);
        const deviceSessionKey = chacha20Poly1305Decrypt(deviceKey, deviceWrapNonce, deviceWrapped);
        if (!timingSafeEqual(new Uint8Array(passSessionKey), new Uint8Array(deviceSessionKey))) {
          throw new Error("Incorrect password. The session keys do not match.");
        }
      } catch (e) {
        console.warn("Device key decryption unavailable. Proceeding with password-only decryption.");
      }
    } else {
      console.warn("No device key found. Proceeding with password-only decryption.");
    }

    // 7. Decrypt the file ciphertext.
    let plaintext;
    try {
      plaintext = chacha20Poly1305Decrypt(passSessionKey, fileNonce, fileCiphertext);
    } catch (e) {
      throw new Error("File decryption failed. Data may be corrupted or the password is incorrect.");
    }
    return plaintext.buffer;
  }

  // ===============================
  // Message Handling in the Worker
  // ===============================
  self.onmessage = async function (e) {
    const { action, payload, requestId } = e.data;
    try {
      let result;
      if (action === 'encryptContainer') {
        // payload: { plaintext: ArrayBuffer, password: string }
        result = await encryptContainer(payload.plaintext, payload.password);
        // Return as base64 string.
        result = arrayBufferToBase64(result);
      } else if (action === 'decryptContainer') {
        // payload: { container: base64 string, password: string }
        const containerBuffer = base64ToArrayBuffer(payload.container);
        result = await decryptContainer(containerBuffer, payload.password);
        result = arrayBufferToBase64(result);
      } else {
        throw new Error(`Unknown action: ${action}`);
      }
      self.postMessage({ status: 'success', result, requestId });
    } catch (err) {
      self.postMessage({ status: 'error', error: err.message, requestId });
    }
  };

})();
