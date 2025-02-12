// hybrid_crypto.js

console.log("Main Thread: Initializing worker...");
const cryptoWorker = new Worker('js/cryptoWorker.js');

const workerCallbacks = {};

function generateRequestId() {
  return 'req_' + Math.random().toString(36).substr(2, 9);
}

cryptoWorker.onmessage = function (e) {
  const { status, result, error, requestId } = e.data;
  console.log("Main Thread: Received response from worker. RequestId:", requestId, "Status:", status);
  if (workerCallbacks[requestId]) {
    if (status === 'success') {
      workerCallbacks[requestId].resolve(result);
    } else {
      console.error("Main Thread: Worker error message:", error);
      workerCallbacks[requestId].reject(new Error("An error occurred. Please try again."));
    }
    delete workerCallbacks[requestId];
  }
};

function sendWorkerMessage(message) {
  return new Promise((resolve, reject) => {
    const requestId = generateRequestId();
    workerCallbacks[requestId] = { resolve, reject };
    console.log("Main Thread: Sending message to worker. RequestId:", requestId, "Action:", message.action);
    cryptoWorker.postMessage({ ...message, requestId });
  });
}

// ================================
// We send the plaintext password directly to the worker.
// ================================

// Helper: Convert hex string to Uint8Array.
function hexStringToUint8Array(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const array = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    array[i / 2] = parseInt(hexString.substr(i, 2), 16);
  }
  return array;
}

console.log("Main Thread: Setting up UI event listeners...");

// Text Encryption
document.getElementById("encryptTextBtn").addEventListener("click", async () => {
  try {
    const plaintext = document.getElementById("plaintext").value;
    const password = document.getElementById("passwordText").value;
    console.log("Main Thread: Encrypting text. Plaintext:", plaintext, "Password provided:", password);
    if (!plaintext || !password) {
      alert("Please fill in both the plaintext and password fields.");
      return;
    }
    const plaintextBuffer = new TextEncoder().encode(plaintext).buffer;
    const containerHex = await sendWorkerMessage({
      action: 'encryptContainer',
      payload: { plaintext: plaintextBuffer, password }
    });
    console.log("Main Thread: Received encrypted container (hex):", containerHex);
    document.getElementById("encryptedText").value = containerHex;
  } catch (e) {
    console.error("Main Thread: Encryption failed:", e);
    alert("Encryption failed. Please try again.");
  }
});

// Copy encrypted text to clipboard.
document.getElementById("copyEncryptedTextBtn").addEventListener("click", () => {
  const encryptedText = document.getElementById("encryptedText").value;
  navigator.clipboard.writeText(encryptedText);
  console.log("Main Thread: Encrypted text copied to clipboard.");
  alert("Encrypted text copied to clipboard.");
});

// Text Decryption
document.getElementById("decryptTextBtn").addEventListener("click", async () => {
  try {
    const containerHex = document.getElementById("encryptedTextInput").value;
    const password = document.getElementById("passwordDecryptText").value;
    console.log("Main Thread: Decrypting text. Container (hex):", containerHex, "Password provided:", password);
    if (!containerHex || !password) {
      alert("Please provide both the encrypted container and a password.");
      return;
    }
    const plaintextHex = await sendWorkerMessage({
      action: 'decryptContainer',
      payload: { container: containerHex, password }
    });
    console.log("Main Thread: Received decrypted plaintext (hex):", plaintextHex);
    const plaintextBuffer = hexStringToUint8Array(plaintextHex).buffer;
    const plaintext = new TextDecoder().decode(plaintextBuffer);
    document.getElementById("decryptedText").value = plaintext;
  } catch (e) {
    console.error("Main Thread: Decryption failed:", e);
    alert("Decryption failed. Please try again.");
  }
});

// Copy decrypted text to clipboard.
document.getElementById("copyDecryptedTextBtn").addEventListener("click", () => {
  const decryptedText = document.getElementById("decryptedText").value;
  navigator.clipboard.writeText(decryptedText);
  console.log("Main Thread: Decrypted text copied to clipboard.");
  alert("Decrypted text copied to clipboard.");
});

// File Encryption
document.getElementById("encryptFileBtn").addEventListener("click", async () => {
  try {
    const fileInput = document.getElementById("fileInputEncrypt");
    const password = document.getElementById("passwordFile").value;
    console.log("Main Thread: Starting file encryption. Password provided:", !!password);
    if (!fileInput.files.length || !password) {
      alert("Please select a file and fill in the password field for encryption.");
      return;
    }
    const file = fileInput.files[0];
    console.log("Main Thread: File selected:", file.name);
    const fileBuffer = await file.arrayBuffer();
    const containerHex = await sendWorkerMessage({
      action: 'encryptContainer',
      payload: { plaintext: fileBuffer, password }
    });
    console.log("Main Thread: Received encrypted file container (hex):", containerHex);
    const blob = new Blob([containerHex], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const dlLink = document.createElement("a");
    dlLink.href = url;
    dlLink.download = file.name + ".enc";
    dlLink.textContent = "Download Encrypted File";
    const containerDiv = document.getElementById("encryptedFileDownload");
    containerDiv.innerHTML = "";
    containerDiv.appendChild(dlLink);
    console.log("Main Thread: File encryption complete. Download link created.");
  } catch (e) {
    console.error("Main Thread: File encryption failed:", e);
    alert("File encryption failed. Please try again.");
  }
});

// File Decryption
document.getElementById("decryptFileBtn").addEventListener("click", async () => {
  try {
    const fileInput = document.getElementById("fileInputDecrypt");
    const password = document.getElementById("passwordFileDecrypt").value;
    console.log("Main Thread: Starting file decryption. Password provided:", !!password);
    if (!fileInput.files.length || !password) {
      alert("Please select an encrypted file and provide the password.");
      return;
    }
    const file = fileInput.files[0];
    console.log("Main Thread: Encrypted file selected:", file.name);
    const fileText = await file.text();
    const plaintextHex = await sendWorkerMessage({
      action: 'decryptContainer',
      payload: { container: fileText.trim(), password }
    });
    console.log("Main Thread: Received decrypted file plaintext (hex):", plaintextHex);
    const plaintextBuffer = hexStringToUint8Array(plaintextHex).buffer;
    const blob = new Blob([plaintextBuffer]);
    const url = URL.createObjectURL(blob);
    let fileName = file.name.replace(/\.enc$/i, "") || "decrypted_file";
    const dlLink = document.createElement("a");
    dlLink.href = url;
    dlLink.download = fileName;
    dlLink.textContent = "Download Decrypted File";
    const containerDiv = document.getElementById("decryptedFileDownload");
    containerDiv.innerHTML = "";
    containerDiv.appendChild(dlLink);
    console.log("Main Thread: File decryption complete. Download link created.");
  } catch (e) {
    console.error("Main Thread: File decryption failed:", e);
    alert("File decryption failed. Please try again.");
  }
});