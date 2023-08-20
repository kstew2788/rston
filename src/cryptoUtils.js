import * as bitcoinjs from 'bitcoinjs-lib';
import * as nobleSecp256k1 from 'noble-secp256k1';
import * as browserifyCipher from 'crypto-browserify';
import { encryptionPassword } from './config.js';

export function getRand(size) {
    return window.crypto.getRandomValues(new Uint8Array(size));
}

export function sha256(data) {
    return bitcoinjs.crypto.sha256(data);
}

export function generateKeyPair() {
    return bitcoinjs.ECPair.makeRandom();
}

export async function getSignedEvent(event, privateKey) {
    var eventData = JSON.stringify([
        0, // Reserved for future use
        event['pubkey'], // The sender's public key
        event['created_at'], // Unix timestamp
        event['kind'], // Message “kind” or type
        event['tags'], // Tags identify replies/recipients
        event['content'] // Your note contents
    ]);
    event.id = sha256(eventData).toString('hex');
    event.sig = await schnorr.sign(event.id, privateKey);
    return event;
}

export function hexToBytes(hex) {
    return Uint8Array.from(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

export function bytesToHex(bytes) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

export function base64ToHex(str) {
    var raw = atob(str);
    var result = '';
    var i;
    for (i = 0; i < raw.length; i++) {
        var hex = raw.charCodeAt(i).toString(16);
        result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result;
}

export function encrypt(privkey, pubkey, text) {
    var key = nobleSecp256k1.getSharedSecret(privkey, '02' + pubkey, true).substring(2);
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    var cipher = browserifyCipher.createCipheriv('aes-256-cbc', hexToBytes(key), iv);
    var encryptedMessage = cipher.update(text, "utf8", "base64");
    emsg = encryptedMessage + cipher.final("base64");
    var uint8View = new Uint8Array(iv.buffer);
    var decoder = new TextDecoder();
    return emsg + "?iv=" + btoa(String.fromCharCode.apply(null, uint8View));
}

export function decrypt(privkey, pubkey, ciphertext) {
    var [emsg, iv] = ciphertext.split("?iv=");
    var key = nobleSecp256k1.getSharedSecret(privkey, '02' + pubkey, true).substring(2);
    var decipher = browserifyCipher.createDecipheriv('aes-256-cbc', hexToBytes(key), hexToBytes(base64ToHex(iv)));
    var decryptedMessage = decipher.update(emsg, "base64");
    dmsg = decryptedMessage + decipher.final("utf8");
    return dmsg;
}

export function saveKeysToLocalStorage(privKey, pubKey) {
    localStorage.setItem('privateKey', privKey);
    localStorage.setItem('publicKey', pubKey);
}

export function getKeysFromLocalStorage() {
    const privKey = localStorage.getItem('privateKey');
    const pubKey = localStorage.getItem('publicKey');
    return { privKey, pubKey };
}

export async function encryptPrivateKey(privKey) {
    const encoder = new TextEncoder();
    const data = encoder.encode(privKey);
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(encryptionPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return {
        encryptedContent: new Uint8Array(encryptedContent),
        salt: salt,
        iv: iv
    };
}

export async function decryptPrivateKey(encryptedData) {
    const encoder = new TextEncoder();
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(encryptionPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: encryptedData.salt, iterations: 100000, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: encryptedData.iv },
        key,
        encryptedData.encryptedContent
    );
    const decoder = new TextDecoder();
    return decoder.decode(decryptedContent);
}