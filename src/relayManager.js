import * as cryptoUtils from './cryptoUtils';

// Function to get the subId for a relay or generate a new one if it doesn't exist
export function getSubIdForRelay(relay, privKey) {
    let relayMappings = JSON.parse(localStorage.getItem('relayMappings') || '{}');
    if (!relayMappings[relay]) {
        // Generate a new subId for the relay using a hash of the relay URL and the private key
        let hash = cryptoUtils.sha256(relay + privKey);
        let subId = hash.toString("hex").substring(0, 16);
        relayMappings[relay] = subId;
        localStorage.setItem('relayMappings', JSON.stringify(relayMappings));
    }
    return relayMappings[relay];
}

// Add more relay-specific functions as needed
