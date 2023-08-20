export function initializeWebSocket(relay) {
    return new WebSocket(relay);
}

export function addMessageListener(socket, callback) {
    socket.addEventListener('message', callback);
}

export function addOpenListener(socket, callback) {
    socket.addEventListener('open', callback);
}

export function sendSocketMessage(socket, message) {
    socket.send(JSON.stringify(message));
}