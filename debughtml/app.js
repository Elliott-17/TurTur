
// Get environment variables from session storage
const sessionId = document.cookie.length > 0 ? document.cookie.split('=')[1] : '';
const encryptionKey = sessionStorage.getItem('encryption_key');
const userId = sessionStorage.getItem('user_id');

// Debugging values
// const sessionId = "BananaBananaBananaBananaBananaBanana"; // First 36 bytes is the session ID
// const encryptionKey = "BananaBananaBananaBananaBananaBa"; // Encryption key
// const userId = "BananaBananaBana"; // User ID given by auth server

// Create WebSocket connection.
const socket = new WebSocket('ws://127.0.0.1:3030/ws');

let connected = false;  // Flag to indicate if the client is connected to the server
let knownMessages = 0;  // Number of messages the client has received from the server for currently open chat room
let currentRoom = 0;
let knowAll = false;// The current room id the client is connected to
let requestingUsersLoop = false;
let usernames = [];
let roomusers = [];
let curtask = null;

socket.addEventListener('open', function () {
    connected = true;
    sendTTPP(0);
    // Check connection status after 5 seconds
    setTimeout(check_conn, 5000);
});

// Listen for messages
socket.onmessage = async function(event) {
    if (event.data instanceof Blob) {
        try {
            // Convert the Blob to ArrayBuffer
            const arrayBuffer = await event.data.arrayBuffer();

            // Create a Uint8Array from the ArrayBuffer
            const uint8Array = new Uint8Array(arrayBuffer);

            // Convert to string
            const text = new TextDecoder().decode(uint8Array);

            // First 36 bytes is the session ID
            const sessionId = text.slice(0, 36);

            // Ensure the session ID matches the one we sent
            if (sessionId !== sessionId) {
                console.error('Session ID mismatch');
                return;
            }

            // Remaining bytes is the encrypted data
            const remaining = decryptData(uint8Array.slice(36), encryptionKey);

            // First 16 bytes is the user ID
            const userIdBytes = remaining.slice(0, 16);
            const userId = new TextDecoder().decode(userIdBytes);

            // Ensure the user ID matches the one we sent
            if (userId !== userId) {
                console.error('User ID mismatch');
                return;
            }

            // Remaining bytes is the message
            const messageBytes = remaining.slice(16);

            // Handle the packet
            handlePacket(messageBytes);

        } catch (error) {
            console.error('Error processing Blob:', error);
        }
    } else {
        console.log('Received non-binary data:', event.data);
    }
};

socket.onerror = function(event) {
    document.getElementById('disconnected-popup').classList.add('show');
}


function sendTTPP(type, data = '') {

    let sessionIdBytes = stringToByteArray(sessionId);
    let userIdBytes = stringToByteArray(userId);
    let packetTypeBytes = stringToByteArray(type);
    let dataBytes = stringToByteArray(data);

    let encrypted_payload = encryptData(concatenateByteArrays(userIdBytes, packetTypeBytes, dataBytes), encryptionKey);

    let packet = concatenateByteArrays(sessionIdBytes, encrypted_payload);

    if (connected) {
        socket.send(packet);
    } else {
        console.error('Not connected to server');
    }
}

function stringToByteArray(str) {
    const encoder = new TextEncoder(); // Using UTF-8 encoding
    return encoder.encode(str);
}



function handlePacket(packet){

    // First byte is the packet type
    const packetType = packet[0];

    // Remaining bytes is the message
    const messageBytes = packet.slice(1);


    const data = new TextDecoder().decode(messageBytes);

    console.log('Received packet type:', packetType, 'data:', data);

    switch (packetType) {
        case 1:
            // Process server list
            try {
                const { servers } = JSON.parse(data);
                displayServerList(servers);
            } catch (error) {
                console.error('Error parsing server list:', error);
            }
            break;
        case 3:
            // Process server messages
            try {
                const { messages, server_id } = JSON.parse(data);
                if (messages.length === 0) {
                    knowAll = true;
                    if (server_id === currentRoom) {
                        return;
                    }
                }
                displayMessages(messages, server_id !== currentRoom);
                currentRoom = parseInt(server_id);
                document.getElementById('current-room-name').innerHTML = document.getElementsByClassName('room active')[0].textContent;
                startUsersLoop();
            } catch (error) {
                console.error('Error parsing server messages:', error);
            }
            break;
        case 5:
            // Process received message
            try {
                const message = JSON.parse(data);
                receivedMessage(message);
            } catch (error) {
                console.error('Error parsing received message:', error);
            }
            break;
        case 7:
            // Success or Fail the running task
            try {
                const { success } = JSON.parse(data);
                taskResult(success);
            } catch (error) {
                console.error('Error parsing success/fail:', error);
            }
            break;
        case 9:
            // Process users
            try {
                const { server_id, users } = JSON.parse(data);
                updateUsers(server_id, users);
            } catch (error) {
                console.error('Error parsing users:', error);
            }
            break;
        case 11:
            // Process room creation
            try {
                const server = JSON.parse(data);
                if (server.id === -1) {
                    console.error('Error creating room');
                    return;
                }
                addServer(server);
            } catch (error) {
                console.error('Error parsing room creation:', error);
            }
            break;
        case 13:
            // Alert
            try {
                const { message } = JSON.parse(data);
                alert(message);
            } catch (error) {
                console.error('Error parsing alert:', error);
            }
            break;
        case 15:
            // Process nickname change
            try {
                const { old_username, new_username } = JSON.parse(data);
                updateUsername(old_username, new_username);
            } catch (error) {
                console.error('Error parsing nickname change:', error);
            }
            break;
        default:
            // Handle other packet types
            console.log('Unhandled packet type:', packetType);
            break;
    }
}


function decryptData(data, key) {
    // Convert packet to a CryptoJS WordArray
    const packetWordArray = CryptoJS.lib.WordArray.create(data);

    // Convert the key to a CryptoJS WordArray
    const keyWordArray = CryptoJS.enc.Utf8.parse(key);

    // Decrypt the packet using AES-256-ECB
    const decrypted = CryptoJS.AES.decrypt({ ciphertext: packetWordArray }, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });

    // Convert decrypted WordArray to a hexadecimal string
    const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);

    // Convert hexadecimal string to a Uint8Array
    const byteArray = new Uint8Array(decryptedHex.length / 2);
    for (let i = 0; i < decryptedHex.length; i += 2) {
        byteArray[i / 2] = parseInt(decryptedHex.substr(i, 2), 16);
    }

    return byteArray;
}

function concatenateByteArrays(...arrays) {
    // Calculate the total length of all arrays
    let totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);

    // Create a new Uint8Array with the total length
    let result = new Uint8Array(totalLength);

    // Set each array into the result
    let offset = 0;
    for (let arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }

    return result;
}


function encryptData(data, key) {
    // Convert packet to a CryptoJS WordArray
    const packetWordArray = CryptoJS.lib.WordArray.create(data);

    // Convert the key to a CryptoJS WordArray
    const keyWordArray = CryptoJS.enc.Utf8.parse(key);

    // Encrypt the packet using AES-256-ECB
    const encrypted = CryptoJS.AES.encrypt(packetWordArray, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding, // Ensure no padding is applied
    });

    // Convert the encrypted data back to a Uint8Array
    return Uint8Array.from(encrypted.ciphertext.words.flatMap(word => [
        (word >> 24) & 0xFF,
        (word >> 16) & 0xFF,
        (word >> 8) & 0xFF,
        word & 0xFF
    ]));
}



function displayServerList(servers) {
    const serverButtonsContainer = document.getElementById('room-bar');
    serverButtonsContainer.innerHTML = ''; // Clear previous buttons

    servers.forEach(server => {
        addServer(server)
    });
}

function addServer(server) {
    const serverButtonsContainer = document.getElementById('room-bar');
    const button = document.createElement('div');
    button.className = 'room';
    button.textContent = server.name;
    button.addEventListener('click', () => {
        if (server.id === currentRoom) {
            return;
        }
        button.className = 'room active';
        // Change all other buttons to inactive
        const buttons = Array.from(serverButtonsContainer.getElementsByClassName('room'));
        buttons.forEach(b => {
            if (b !== button) {
                b.classList.remove('active');
            }
        });
        // remove show class from notification
        button.children[0].classList.remove('show');
        requestServerMessages(server.id);
    });
    const notif = document.createElement('span');
    notif.className = 'notification';
    const notifIcon = document.createElement('i');
    notifIcon.className = 'fas fa-exclamation-circle';

    // Encode the server ID in the button
    button.dataset.serverId = server.id;

    notif.appendChild(notifIcon);
    button.appendChild(notif);


    serverButtonsContainer.appendChild(button);
}

function requestServerMessages(server_id, known_messages = 0) {

    server_id = parseInt(server_id);

    const data = JSON.stringify({ server_id, known_messages });

    console.log(data);

    sendTTPP(2, data); // Send a TTPP Message Request (type 2)

}

function displayMessages(messages, clear) {

    const chat = document.getElementById('chat-window');

    if (clear) {
        // Clear the chat by removing all children
        while (chat.firstChild) {
            chat.removeChild(chat.firstChild);
        }
        knownMessages = 0;
        knowAll = false;
    }

    let previousScrollHeight = chat.scrollHeight;
    let previousScrollTop = chat.scrollTop;

    // Only calculate the scroll offset if not clearing the chat
    let scrollOffset = clear ? 0 : previousScrollHeight - previousScrollTop;

    // Add new messages at the top
    messages.forEach(message => {
        let div = createMsgObject(message.message, message.userident, message.timestamp);
        chat.prepend(div);
    });
    knownMessages += messages.length;

    if (clear) {
        // Scroll to the bottom if chat was cleared
        chat.scrollTop = chat.scrollHeight;
    } else {
        // Keep the current scroll position
        chat.scrollTop = chat.scrollHeight - scrollOffset;
    }


}

function updateUsers(server_id, users) {
    if (server_id === 0) {
        // Update the user list
        usernames = users.map(user => user.username);
    } else {
        updateUserList(users);
    }
}


function updateUserList(users) {

    roomusers = users.map(user => user.username);

    const usersList = document.getElementById('users-list');
    usersList.innerHTML = ''; // Clear previous users

    users.forEach(user => {
        const div = createUsersObject(user.username, user.connected);
        usersList.appendChild(div);
    });

    // Sort the users list, online users first
    const onlineUsers = Array.from(usersList.getElementsByClassName('user online'));
    const offlineUsers = Array.from(usersList.getElementsByClassName('user offline'));
    usersList.innerHTML = '';


    onlineUsers.forEach(user => usersList.appendChild(user));
    offlineUsers.forEach(user => usersList.appendChild(user));


    // Add a timeout to request users again after 1.7 seconds
    setTimeout(requestUsers, 1700);
}

function createUsersObject(user, online) {
    let div = document.createElement('div');
    div.className = 'user';
    if (online === "true") {
        div.classList.add('online');
    } else {
        div.classList.add('offline');
    }
    let p = document.createElement('p');
    p.textContent = user;
    let span = document.createElement('span');
    span.className = 'user-status';
    div.appendChild(p);
    div.appendChild(span);

    return div;
}


function sendChatMessage(message) {
    if (currentRoom === 0) {
        console.error('No chat room selected');
        return;
    }
    const data = JSON.stringify({ server_id: currentRoom, message });
    sendTTPP(4, data); // Send a TTPP Message Send (type 4)
}

function receivedMessage(message) {
    if (message.server_id !== currentRoom) {
        // Set notification for the room
        const room = document.querySelector(`.room[data-server-id="${message.server_id}"]`);
        const notification = room.children[0];
        notification.classList.add('show');
        return;
    }
    const chat = document.getElementById('chat-window');
    const div = createMsgObject(message.message, message.userident, message.timestamp);
    chat.appendChild(div);

    // If the user is scrolled to the bottom, scroll to the new message
    if (chat.scrollHeight - chat.scrollTop <= chat.clientHeight + 100) {
        chat.scrollTop = chat.scrollHeight;
    }
}


function createMsgObject(message, username, timestamp) {
    let div = document.createElement('div');
    div.className = 'chat-message';
    // let img = document.createElement('img');
    // img.src = 'https://via.placeholder.com/40';
    // img.alt = username;
    let messageContent = document.createElement('div');
    messageContent.className = 'message-content';
    let messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';
    let user = document.createElement('span');
    user.className = 'username';
    user.textContent = username;
    let time = document.createElement('span');
    time.className = 'timestamp';
    time.textContent = timestamp;
    let p = document.createElement('p');
    p.textContent = message;

    messageHeader.appendChild(user);
    messageHeader.appendChild(time);
    messageContent.appendChild(messageHeader);
    messageContent.appendChild(p);
    // div.appendChild(img);
    div.appendChild(messageContent);
    return div;
}


function startUsersLoop() {
    if (requestingUsersLoop) {
        return;
    } else {
        requestingUsersLoop = true;
    }
    requestUsers();
}

function requestUsers() {
    console.log('Requesting users');
    const data = JSON.stringify({ server_id: currentRoom });
    sendTTPP(8, data);
}



document.getElementById('message').addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
        // Ensure the message is not empty
        if (event.target.value.trim() === '') {
            return;
        }
        const message = event.target.value;
        event.target.value = '';
        sendChatMessage(message);
    }
});




// On Load
document.addEventListener('DOMContentLoaded', () => {
    const chatWindow = document.getElementById('chat-window');

    chatWindow.addEventListener('scroll', () => {
        if (chatWindow.scrollTop === 0 && knowAll === false) { // Allow some extra scroll space
            getMoreMessages();
        }
    });

    document.body.classList.remove('no-fouc');
});


function getMoreMessages() {
    requestServerMessages(currentRoom, knownMessages);
}



function taskResult(success) {
    if (curtask != null) {
        switch (curtask) {
            case 1:
                // Adding a user task
                if (success) {
                    alert('User added successfully');
                } else {
                    alert('Error adding user');
                }
                break;
            case 2:
                // Removing a user task
                if (success) {
                    alert('User removed successfully');
                } else {
                    alert('Error removing user');
                }
                break;
            case 3:
                // Changing nickname task
                if (success) {
                    window.location.href = '/logout';
                } else {
                    alert('Error deleting account, please try again');
                }
                break;
        }
        curtask = null;
    }
}

function updateUsername(old_username, new_username) {
    // Update the username in each message
    const messages = document.getElementsByClassName('chat-message');
    Array.from(messages).forEach(message => {
        const username = message.getElementsByClassName('username')[0];
        if (username.textContent === old_username) {
            username.textContent = new_username;
        }
    });
}



// On Load
document.addEventListener('DOMContentLoaded', function() {
    const createRoomButton = document.getElementById('create-room-button');
    const createRoomPopup = document.getElementById('create-room-popup');
    const createRoom = document.getElementById('create-room');
    const cancelCreateRoom = document.getElementById('cancel-create-room');
    const roomNameInput = document.getElementById('room-name');

    // Show the popup when the "Create Room" button is clicked
    createRoomButton.addEventListener('click', function() {
        createRoomPopup.classList.add('show');
    });

    // Hide the popup when the "Cancel" button is clicked
    cancelCreateRoom.addEventListener('click', function() {
        createRoomPopup.classList.remove('show');
    });

    // Handle the "Create" button click
    createRoom.addEventListener('click', function() {
        const roomName = roomNameInput.value.trim();
        if (roomName === '') {
            alert('Room name cannot be empty');
            return;
        }
        roomNameInput.value = '';
        createRoomFunction(roomName);
        createRoomPopup.classList.remove('show');
    });

    const settingsButton = document.getElementById('settings-button');
    const settingsPopup = document.getElementById('settings-popup');
    const closeSettings = document.getElementById('close-settings');
    const logoutButton = document.getElementById('logout');
    const addUserText = document.getElementById('add-user');
    const addUserButton = document.getElementById('add-user-to-room');
    const addUserDropdown = document.getElementById('add-user-dropdown');
    const removeUserText = document.getElementById('remove-user');
    const removeUserButton = document.getElementById('remove-user-from-room');
    const removeUserDropdown = document.getElementById('remove-user-dropdown');



    settingsButton.addEventListener('click', function() {
        settingsPopup.classList.add('show');
    });

    closeSettings.addEventListener('click', function() {
        settingsPopup.classList.remove('show');
    });

    logoutButton.addEventListener('click', function() {
        window.location.href = '/logout';
    });

    addUserText.addEventListener('input', function() {
        sendTTPP(8, JSON.stringify({ server_id: 0 }));
        usernames = usernames.filter(user => !roomusers.includes(user));
        filterDropdown(addUserText, addUserDropdown, usernames);
    });

    addUserButton.addEventListener('click', function() {
        const user = addUserText.value;
        if (!usernames.includes(user)) {
            return;
        }
        addUserText.value = '';
        curtask = 1;
        sendTTPP(12, JSON.stringify({ server_id: currentRoom, username: user, access: true }));
    });

    removeUserText.addEventListener('input', function() {
        sendTTPP(8, JSON.stringify({ server_id: currentRoom }));
        filterDropdown(removeUserText, removeUserDropdown, roomusers);
    });

    removeUserButton.addEventListener('click', function() {
        const user = removeUserText.value;
        if (!roomusers.includes(user)) {
            return;
        }
        removeUserText.value = '';
        curtask = 2;
        sendTTPP(12, JSON.stringify({ server_id: currentRoom, username: user, access: false }));
    });

    // Hide dropdown when clicking outside
    document.addEventListener('click', (event) => {
        if (!addUserText.contains(event.target) && !addUserDropdown.contains(event.target)) {
            addUserDropdown.style.display = 'none';
        }
        if (!removeUserText.contains(event.target) && !removeUserDropdown.contains(event.target)) {
            removeUserDropdown.style.display = 'none';
        }
    });


    const nicknameButton = document.getElementById('set-nickname');
    const nicknameInput = document.getElementById('user-nickname-input');

    nicknameButton.addEventListener('click', function() {
        sendTTPP(8, JSON.stringify({ server_id: 0 }));
        const nickname = nicknameInput.value;
        if (nickname === '') {
            alert('Nickname cannot be empty');
            return;
        }
        if (nickname.length > 30) {
            alert('Nickname cannot be longer than 30 characters');
            return;
        }
        if (usernames.includes(nickname)) {
            alert('Nickname already taken');
            return;
        }

        nicknameInput.value = '';
        sendTTPP(14, JSON.stringify({ new_username: nickname }));
    });

    const deleteUserButton = document.getElementById('delete-account');
    const deleteAccountPopup = document.getElementById('delete-account-popup');
    const confirmDeleteButton = document.getElementById('confirm-delete-account');
    const cancelDeleteButton = document.getElementById('cancel-delete-account');


    deleteUserButton.addEventListener('click', function() {
        deleteAccountPopup.classList.add('show');
        settingsPopup.classList.remove('show');
    });

    confirmDeleteButton.addEventListener('click', function() {
        curtask = 3;
        sendTTPP(16);
    });

    cancelDeleteButton.addEventListener('click', function() {
        deleteAccountPopup.classList.remove('show');
    });


    document.getElementById('reload-page').addEventListener('click', function(event) {
        window.location.reload();
    });

});

// Function to create the room
function createRoomFunction(roomName) {
    sendTTPP(10, JSON.stringify({ server_name: roomName }));
}


// Filter and display dropdown options
function filterDropdown(input, dropdown, users) {
    const filter = input.value.toLowerCase();
    dropdown.innerHTML = '';
    const filteredUsers = users.filter(user => user.toLowerCase().includes(filter));
    filteredUsers.forEach(user => {
        const div = document.createElement('div');
        div.textContent = user;
        div.addEventListener('click', () => {
            input.value = user;
            dropdown.style.display = 'none';
        });
        dropdown.appendChild(div);
    });
    dropdown.style.display = filteredUsers.length ? 'block' : 'none';
}


function check_conn(){
    if (socket.readyState == WebSocket.CLOSED) {
        document.getElementById('disconnected-popup').classList.add('show');
    }
    else if (document.getElementById('room-bar').children.length == 0){
        document.getElementById('disconnected-popup').classList.add('show');
    }
    // Add a timeout to check connection again after 10 seconds
    setTimeout(check_conn, 10000);
}