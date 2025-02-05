// hybrid_crypto.js

// Wrap all code in an immediately invoked async function
// to ensure that sodium is ready before using it.
(async () => {
  // Wait until sodium is fully initialized.
  await sodium.ready;

  // Check that crypto_pwhash is available.
  if (typeof sodium.crypto_pwhash !== "function") {
    console.error("sodium.crypto_pwhash is not available. Make sure you're using a complete build of libsodium.js.");
    return;
  }
  console.log("Sodium is ready and crypto_pwhash is available.");

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
    return window.btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
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
  // Device Key Management
  // ===============================
  const DEVICE_KEY_STORAGE = "device_key";

  async function getDeviceKeyForEncryption() {
    let stored = localStorage.getItem(DEVICE_KEY_STORAGE);
    if (stored) {
      return base64ToArrayBuffer(stored);
    } else {
      const newKey = sodium.randombytes_buf(32);
      localStorage.setItem(DEVICE_KEY_STORAGE, arrayBufferToBase64(newKey.buffer));
      return newKey.buffer;
    }
  }

  async function getDeviceKeyForDecryption() {
    const stored = localStorage.getItem(DEVICE_KEY_STORAGE);
    if (stored) {
      return base64ToArrayBuffer(stored);
    } else {
      return null;
    }
  }

  // ===============================
  // Constants
  // ===============================
  const MAGIC = strToArrayBuffer("HYBRID02__"); // 10-byte magic header
  // ChaCha20–Poly1305 (IETF) uses a 12-byte nonce.
  const NONCE_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12 bytes

  // Argon2id parameters (per requirements):
  const ARGON2_MEMLIMIT = 128 * 1024 * 1024; // 128 MB
  const ARGON2_OPSLIMIT = 12; // iterations count as given
  const ARGON2_HASHLEN = 64; // 64 bytes output

  // In our design the wrapped session key ciphertext will be:
  // session key (32 bytes) + 16-byte Poly1305 tag = 48 bytes.
  const WRAPPED_KEY_LENGTH = 48;

  // ===============================
  // Utility: Generate a random salt string of length 32
  // using numbers, uppercase, lowercase, and special symbols.
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
  // This function derives a key of 64 bytes and then returns the first 32 bytes.
  // IMPORTANT: libsodium expects the salt to be exactly sodium.crypto_pwhash_SALTBYTES bytes long.
  // We generate a 32-character salt string (per requirements) but then take only the first
  // sodium.crypto_pwhash_SALTBYTES bytes (usually 16 bytes) for key derivation.
  async function deriveKeyArgon2id(password, saltStr) {
    const fullSalt = strToArrayBuffer(saltStr);
    const salt = fullSalt.slice(0, sodium.crypto_pwhash_SALTBYTES); // Ensure correct salt length.
    // Derive 64 bytes.
    const derived = sodium.crypto_pwhash(
      ARGON2_HASHLEN,  // outlen
      password,        // password (string)
      salt,            // salt (Uint8Array)
      ARGON2_OPSLIMIT, // opslimit (number)
      ARGON2_MEMLIMIT, // memlimit (in bytes)
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    // Return first 32 bytes for use as a key.
    return derived.slice(0, 32);
  }

  // ===============================
  // ChaCha20-Poly1305 Encryption/Decryption
  // ===============================
  // Encrypt data with the given key. Returns an object { nonce, ciphertext }.
  // The ciphertext output includes the 16-byte authentication tag.
  function chacha20Poly1305Encrypt(key, data) {
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      data,   // message as Uint8Array
      null,   // no additional data
      null,   // no secret nonce
      nonce,  // nonce
      key     // key (Uint8Array)
    );
    return { nonce, ciphertext };
  }

  // Decrypt data with the given key and nonce.
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
  // Hybrid Encryption Function (Using Password and Device Key)
  // ===============================
  async function encryptContainer(plaintextArrayBuffer, password) {
    // 1. Generate a random 32-byte session key.
    const sessionKey = sodium.randombytes_buf(32);

    // 2. File Encryption using ChaCha20–Poly1305:
    const fileNonce = sodium.randombytes_buf(NONCE_BYTES);
    // Encrypt the file (plaintext) with the session key.
    // The output ciphertext includes a 16-byte authentication tag.
    const fileCiphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      new Uint8Array(plaintextArrayBuffer),
      null,
      null,
      fileNonce,
      sessionKey
    );

    // 3. Password Wrap:
    // Generate a random salt string of length 32.
    const argon2SaltStr = generateRandomSaltString();
    // Derive a key from the password using Argon2id.
    const passWrapKey = await deriveKeyArgon2id(password, argon2SaltStr);
    // Encrypt (wrap) the session key.
    const { nonce: passWrapNonce, ciphertext: passWrapped } = chacha20Poly1305Encrypt(passWrapKey, sessionKey);

    // 4. Device Wrap:
    const deviceKeyBuffer = await getDeviceKeyForEncryption();
    const deviceKey = new Uint8Array(deviceKeyBuffer);
    const { nonce: deviceWrapNonce, ciphertext: deviceWrapped } = chacha20Poly1305Encrypt(deviceKey, sessionKey);

    // 5. Build the container.
    // Container structure:
    // [MAGIC (10 bytes)]
    // [Argon2id salt (32 bytes)] + [Password wrap nonce (12 bytes)]
    // [Password wrapped key length (2 bytes)] + [Password wrapped session key (ciphertext, expected 48 bytes)]
    // [Device wrap nonce (12 bytes)]
    // [Device wrapped key length (2 bytes)] + [Device wrapped session key (ciphertext, expected 48 bytes)]
    // [File encryption nonce (12 bytes)]
    // [File ciphertext length (8 bytes)] + [File ciphertext (variable)]
    const passWrappedLenBuf = numberToBuffer(passWrapped.length, 2);
    const deviceWrappedLenBuf = numberToBuffer(deviceWrapped.length, 2);
    const fileCiphertextLenBuf = numberToBuffer(fileCiphertext.length, 8);

    // Convert the Argon2 salt string to an ArrayBuffer.
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
  // Hybrid Decryption Function (Enforcing Password)
  // ===============================
  async function decryptContainer(containerBuffer, password) {
    if (!password) {
      throw new Error("Password is required for decryption.");
    }

    const data = new Uint8Array(containerBuffer);
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
    const argon2SaltStr = arrayBufferToStr(argon2SaltBytes.buffer); // salt as string
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

    // 6. Optionally, recover and verify the session key via the Device Wrap.
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

    // 7. Decrypt the file ciphertext using the recovered session key.
    let plaintext;
    try {
      plaintext = chacha20Poly1305Decrypt(passSessionKey, fileNonce, fileCiphertext);
    } catch (e) {
      throw new Error("File decryption failed. Data may be corrupted or the password is incorrect.");
    }
    return plaintext.buffer;
  }

  // ===============================
  // UI Handlers (Text/File Encryption & Decryption)
  // ===============================
  // Text Encryption
  document.getElementById("encryptTextBtn").addEventListener("click", async () => {
    try {
      const plaintext = document.getElementById("plaintext").value;
      const password = document.getElementById("passwordText").value;
      if (!plaintext || !password) {
        alert("Please fill in both the plaintext and password fields.");
        return;
      }
      const plaintextBuffer = strToArrayBuffer(plaintext);
      const containerBuffer = await encryptContainer(plaintextBuffer, password);
      const containerBase64 = arrayBufferToBase64(containerBuffer);
      document.getElementById("encryptedText").value = containerBase64;
    } catch (e) {
      alert("Encryption failed: " + e.message);
    }
  });

  // Copy encrypted text to clipboard.
  document.getElementById("copyEncryptedTextBtn").addEventListener("click", () => {
    const encryptedText = document.getElementById("encryptedText").value;
    navigator.clipboard.writeText(encryptedText);
    alert("Encrypted text copied to clipboard.");
  });

  // Text Decryption
  document.getElementById("decryptTextBtn").addEventListener("click", async () => {
    try {
      const containerBase64 = document.getElementById("encryptedTextInput").value;
      const password = document.getElementById("passwordDecryptText").value;
      if (!containerBase64) {
        alert("Please paste the encrypted container.");
        return;
      }
      const containerBuffer = base64ToArrayBuffer(containerBase64);
      const plaintextBuffer = await decryptContainer(containerBuffer, password);
      const plaintext = arrayBufferToStr(plaintextBuffer);
      document.getElementById("decryptedText").value = plaintext;
    } catch (e) {
      alert("Decryption failed: " + e.message);
    }
  });

  // Copy decrypted text to clipboard.
  document.getElementById("copyDecryptedTextBtn").addEventListener("click", () => {
    const decryptedText = document.getElementById("decryptedText").value;
    navigator.clipboard.writeText(decryptedText);
    alert("Decrypted text copied to clipboard.");
  });

  // File Encryption
  document.getElementById("encryptFileBtn").addEventListener("click", async () => {
    try {
      const fileInput = document.getElementById("fileInputEncrypt");
      const password = document.getElementById("passwordFile").value;
      if (!fileInput.files.length || !password) {
        alert("Please select a file and fill in the password field for encryption.");
        return;
      }
      const file = fileInput.files[0];
      const fileBuffer = await file.arrayBuffer();
      const containerBuffer = await encryptContainer(fileBuffer, password);
      const containerBase64 = arrayBufferToBase64(containerBuffer);
      // Create a download link for the encrypted file.
      const blob = new Blob([containerBase64], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const dlLink = document.createElement("a");
      dlLink.href = url;
      dlLink.download = file.name + ".enc";
      dlLink.textContent = "Download Encrypted File";
      const containerDiv = document.getElementById("encryptedFileDownload");
      containerDiv.innerHTML = "";
      containerDiv.appendChild(dlLink);
    } catch (e) {
      alert("File encryption failed: " + e.message);
    }
  });

  // File Decryption
  document.getElementById("decryptFileBtn").addEventListener("click", async () => {
    try {
      const fileInput = document.getElementById("fileInputDecrypt");
      const password = document.getElementById("passwordFileDecrypt").value;
      if (!fileInput.files.length) {
        alert("Please select an encrypted file.");
        return;
      }
      const file = fileInput.files[0];
      const fileText = await file.text();
      const containerBuffer = base64ToArrayBuffer(fileText.trim());
      const plaintextBuffer = await decryptContainer(containerBuffer, password);
      // Create a download link for the decrypted file.
      const blob = new Blob([plaintextBuffer]);
      const url = URL.createObjectURL(blob);
      const dlLink = document.createElement("a");
      dlLink.href = url;
      let fileName = file.name.replace(/\.enc$/i, "") || "decrypted_file";
      dlLink.download = fileName;
      dlLink.textContent = "Download Decrypted File";
      const containerDiv = document.getElementById("decryptedFileDownload");
      containerDiv.innerHTML = "";
      containerDiv.appendChild(dlLink);
    } catch (e) {
      alert("File decryption failed: " + e.message);
    }
  });

})(); // End of main async IIFE
