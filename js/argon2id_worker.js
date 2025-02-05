// keyDerivationWorker.js

// Import the libsodium library into the worker.
importScripts('./js/sodium.js');

// Wait for sodium to be fully initialized.
sodium.ready.then(() => {
  // Listen for messages from the main thread.
  self.onmessage = function (e) {
    const { password, saltStr, opslimit, memlimit, hashlen } = e.data;
    try {
      // Convert the provided salt string to bytes.
      // (The salt string is 32 characters long per requirement, but libsodium
      // requires the salt to be exactly sodium.crypto_pwhash_SALTBYTES bytes long.)
      const saltFull = new TextEncoder().encode(saltStr);
      const salt = saltFull.slice(0, sodium.crypto_pwhash_SALTBYTES);
    
      // Derive a 64-byte key using Argon2id.
      const derived = sodium.crypto_pwhash(
        hashlen,      // Desired output length (e.g. 64 bytes)
        password,     // Password (as a string)
        salt,         // Salt (must be Uint8Array of correct length)
        opslimit,     // Opslimit (e.g. 12)
        memlimit,     // Memory limit in bytes (e.g. 128 * 1024 * 1024)
        sodium.crypto_pwhash_ALG_ARGON2ID13
      );
      
      // For our purposes, we use the first 32 bytes of the derived output.
      const key = derived.slice(0, 32);
      
      // Post the result back to the main thread.
      // We convert the Uint8Array to a normal array to allow structured cloning.
      self.postMessage({ key: Array.from(key) });
    } catch (err) {
      self.postMessage({ error: err.message });
    }
  };
}).catch(err => {
  self.postMessage({ error: "Sodium initialization failed in worker: " + err.message });
});
