importScripts('sodium.js');

console.log("Worker: Attempting to load sodium.js...");

sodium.ready.then(() => {
    console.log("Worker: Sodium.js is ready!");

    self.onmessage = function (e) {
        console.log("Worker received message:", e.data);
        const { password, salt, opslimit, memlimit, hashlen } = e.data;
        try {
            const key = sodium.crypto_pwhash(
                hashlen,
                password,
                new Uint8Array(salt),
                opslimit,
                memlimit,
                sodium.crypto_pwhash_ALG_ARGON2ID13
            );
            console.log("Worker: Derived key successfully!");
            self.postMessage({ key: Array.from(key.slice(0, 32)) });
        } catch (err) {
            console.error("Worker: Error during key derivation:", err);
            self.postMessage({ error: err.message });
        }
    };
}).catch(err => {
    console.error("Worker: Sodium initialization failed!", err);
    self.postMessage({ error: "Sodium initialization failed in worker: " + err.message });
});
