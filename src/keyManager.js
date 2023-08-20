import * as cryptoUtils from './cryptoUtils.js';
import { encryptionPassword } from './config.js';

// Function to initialize keys: generate new ones if they don't exist or retrieve from local storage
export async function initializeKeys() {
    let keypair;
    let encryptedPrivKey = cryptoUtils.getKeysFromLocalStorage().encryptedPrivKey;
    let pubKey = cryptoUtils.getKeysFromLocalStorage().pubKey;

    // Check if keys exist in local storage
    if (!encryptedPrivKey || !pubKey) {
        keypair = cryptoUtils.generateKeyPair();
        let privKey = keypair.privateKey.toString("hex");
        pubKey = keypair.publicKey.toString("hex");
        pubKey = pubKey.substring(2);
        encryptedPrivKey = await cryptoUtils.encryptPrivateKey(privKey);
        cryptoUtils.saveKeysToLocalStorage(encryptedPrivKey, pubKey);
        console.log("New keys generated and stored.");
    } else {
        console.log("Keys retrieved from local storage.");
    }

    return { encryptedPrivKey, pubKey };
}