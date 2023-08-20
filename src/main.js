import * as eventHandlers from './eventHandlers.js';
import * as keyManager from './keyManager.js';
import * as relayManager from './relayManager.js';
import * as wsUtils from './wsUtils.js';

async function main() {
    // Initialize keys
    const { encryptedPrivKey, pubKey } = await keyManager.initializeKeys();

    // Initialize WebSocket
    const relay = "wss://relay.damus.io";  // This could come from config.js
    const socket = wsUtils.initializeWebSocket(relay);

    // Get or generate subId for the relay
    const subId = relayManager.getSubIdForRelay(relay, encryptedPrivKey);

    // Attach event handlers using wsUtils
    wsUtils.addMessageListener(socket, eventHandlers.handleMessageEvent);
    wsUtils.addOpenListener(socket, () => eventHandlers.handleOpenEvent(socket, relay, subId));

    // ... any other initialization code
}

// Run the main function to start the application
main();
