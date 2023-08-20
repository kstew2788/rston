import * as cryptoUtils from './cryptoUtils.js';
import * as relayManager from './relayManager.js';

// Event handler for incoming WebSocket messages
// Decrypts the private key from local storage and processes the message
export async function handleMessageEvent(message) {
    // Retrieve and decrypt the private key from local storage
    let encryptedPrivKey = cryptoUtils.getKeysFromLocalStorage().encryptedPrivKey;
    let pubKey = cryptoUtils.getKeysFromLocalStorage().pubKey;
    let privKey = await cryptoUtils.decryptPrivateKey(JSON.parse(encryptedPrivKey));

    // Parse the incoming message data
    var [type, subId, event] = JSON.parse(message.data);
    var { kind, content } = event || {};

    // If there's no event or the event is true, exit the function
    if (!event || event === true) return;
    console.log('message:', event);

    // If the message kind is 4, decrypt the content using the private key
    if (kind === 4) {
        content = await cryptoUtils.decrypt(privKey, event.pubkey, content);
    }
    console.log('content:', content);
}

// Event handler for when the WebSocket connection is opened
// Sends a subscription request and a test message
export async function handleOpenEvent(socket, relay, subId) {  // Added subId parameter
    // Retrieve and decrypt the private key from local storage
    let encryptedPrivKey = cryptoUtils.getKeysFromLocalStorage().encryptedPrivKey;
    let pubKey = cryptoUtils.getKeysFromLocalStorage().pubKey;
    let privKey = await cryptoUtils.decryptPrivateKey(JSON.parse(encryptedPrivKey));

    // Log the connection status
    console.log("connected to " + relay);

    // Define a filter for the subscription
    var filter = { "authors": [pubKey] };
    var subscription = ["REQ", subId, filter];  // Using the passed-in subId
    console.log('Subscription:', subscription);
    socket.send(JSON.stringify(subscription));

    var signedEvent = await cryptoUtils.getSignedEvent(event, privKey);
    console.log('signedEvent:', signedEvent);
    socket.send(JSON.stringify(["EVENT", signedEvent]));

    // Define a test encrypted message and send it
    var message = "this message is super secret!";
    var encrypted = cryptoUtils.encrypt(privKey, pubKey, message);

    var event2 = {
        "content": encrypted,
        "created_at": Math.floor(Date.now() / 1000),
        "kind": 4,
        "tags": [['p', pubKey]],
        "pubkey": pubKey,
    };

    var signedEvent2 = await cryptoUtils.getSignedEvent(event2, privKey);
    socket.send(JSON.stringify(["EVENT", signedEvent2]));
}