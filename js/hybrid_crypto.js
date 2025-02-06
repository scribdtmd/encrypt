// hybrid_crypto.js

// Create the worker. Make sure the path to cryptoWorker.js is correct.
const cryptoWorker = new Worker('js/cryptoWorker.js');

// Global callback registry to handle worker responses.
const workerCallbacks = {};

// Generate a unique ID for each worker request.
function generateRequestId() {
  return 'req_' + Math.random().toString(36).substr(2, 9);
}

// Listen for messages from the worker.
cryptoWorker.onmessage = function (e) {
  const { status, result, error, requestId } = e.data;
  if (workerCallbacks[requestId]) {
    if (status === 'success') {
      workerCallbacks[requestId].resolve(result);
    } else {
      workerCallbacks[requestId].reject(new Error(error));
    }
    delete workerCallbacks[requestId];
  }
};

// Helper to send a message to the worker and wait for a response.
function sendWorkerMessage(message) {
  return new Promise((resolve, reject) => {
    const requestId = generateRequestId();
    workerCallbacks[requestId] = { resolve, reject };
    cryptoWorker.postMessage({ ...message, requestId });
  });
}

// ===============================
// UI Handlers for Text and File Encryption & Decryption
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
    const plaintextBuffer = new TextEncoder().encode(plaintext).buffer;
    const containerBase64 = await sendWorkerMessage({
      action: 'encryptContainer',
      payload: { plaintext: plaintextBuffer, password }
    });
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
    if (!containerBase64 || !password) {
      alert("Please provide both the encrypted container and a password.");
      return;
    }
    const plaintextBase64 = await sendWorkerMessage({
      action: 'decryptContainer',
      payload: { container: containerBase64, password }
    });
    // Convert decrypted base64 back to text.
    const decryptedBuffer = base64ToArrayBuffer(plaintextBase64);
    const plaintext = new TextDecoder().decode(decryptedBuffer);
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
    const containerBase64 = await sendWorkerMessage({
      action: 'encryptContainer',
      payload: { plaintext: fileBuffer, password }
    });
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
    if (!fileInput.files.length || !password) {
      alert("Please select an encrypted file and provide the password.");
      return;
    }
    const file = fileInput.files[0];
    const fileText = await file.text();
    const plaintextBase64 = await sendWorkerMessage({
      action: 'decryptContainer',
      payload: { container: fileText.trim(), password }
    });
    // Convert decrypted base64 back to ArrayBuffer.
    const plaintextBuffer = base64ToArrayBuffer(plaintextBase64);
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

// ===============================
// Helper function for the main thread
// ===============================
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
