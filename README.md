IoT Chat Server

The IoT Chat Server is a Python-based server application that facilitates chat communication between multiple clients over a network. It incorporates authentication and encryption features to ensure secure and controlled communication.

Dependencies
asyncio: A Python library for asynchronous programming.
cryptography: A library for secure communication with encryption and decryption capabilities.
os: Provides functions for working with the operating system.
hashlib: A library for hashing data.
datetime: Provides functionality for working with dates and times.

Configuration
HOST: The IP address or hostname where the server will listen for incoming connections.
PORT: The port number on which the server will listen for incoming connections.
key: A secret key for AES encryption. This key is used for encrypting and decrypting messages.

User Database
The server maintains a user database (users) that stores user information, including usernames, hashed passwords, and user roles. The roles can be "admin" or "user."
Audit Log
audit_log: A list used to store audit logs that track various events occurring on the server, such as authentication attempts, user connections, disconnections, and administrative actions.

Cryptographic Functions
The server includes functions for encrypting and decrypting messages:
encrypt_message(message): Encrypts a given message using AES encryption and returns the encrypted message.
decrypt_message(encrypted_message): Decrypts a given encrypted message using AES decryption and returns the original message.

Authentication and Authorization
authenticate_user(username, password_hash): Authenticates a user based on the provided username and hashed password. If authentication is successful, it returns True; otherwise, it returns False.
authorize_user(username, action): Authorizes a user to perform specific actions such as broadcasting messages or kicking other users. The authorization is based on the user's role (admin or user).

Chat Clients
clients: A dictionary that maps usernames to their respective client socket writers. This allows the server to communicate with clients.

Kicking Users
kick_user(username_to_kick, admin_username): Kicks a user out of the chat. It sends a notification to the kicked user and logs the action in the audit log. Only users with the "admin" role can perform this action.

Broadcasting Messages
broadcast_message(message, sender, action="message"): Broadcasts a message to all connected clients. The action parameter specifies the type of action, such as "message," "broadcast," or "kick." Authorization is enforced based on user roles.

Client Handling
handle_client(reader, writer): Handles the communication with a connected client. It performs the following steps:
Authenticates the user based on the provided credentials (username and password).
If authentication is successful, the client is allowed to join the chat.
Handles incoming messages, including broadcasting messages, kicking users (if authorized), and logging messages and events.
Handles disconnection events and removes the client from the list of active clients.

Server Startup
start_server(): Starts the chat server and listens for incoming client connections on the specified host and port.

Main Execution
The code block at the end of the script initiates the execution of the server by calling asyncio.run(start_server()).

Logging
log_event(event): Logs events and messages to an audit log. Each log entry includes a timestamp, event description, and username (if applicable).

Security Features
Authentication: Users must provide a valid username and password to access the chat. Authentication is enforced using a user database with hashed passwords.
Authorization: User roles ("admin" or "user") determine their privileges, such as the ability to broadcast messages or kick other users.
Encryption: Messages exchanged between clients and the server are encrypted using AES encryption with a secret key.

Server Operation
The server starts and listens for incoming client connections.
Clients connect to the server and provide their credentials (username and hashed password).
Upon successful authentication, clients can participate in the chat.
Clients can send messages, which are broadcast to other connected clients.
Clients with "admin" roles can kick other users out of the chat.
Audit logs record various events and actions on the server.


IoT Chat Client
The IoT Chat Client is a Python-based client application that allows users to connect to a chat server, authenticate themselves, and participate in chat communication. It includes encryption features to ensure secure communication.

Dependencies
asyncio: A Python library for asynchronous programming.
cryptography: A library for secure communication with encryption and decryption capabilities.
os: Provides functions for working with the operating system.
hashlib: A library for hashing data.

Configuration
HOST: The IP address or hostname of the chat server to connect to.
PORT: The port number on which the chat server is listening.
key: A secret key used for AES encryption and decryption.

Cryptographic Functions
The client includes functions for encrypting and decrypting messages:
encrypt_message(message): Encrypts a given message using AES encryption and returns the encrypted message.
decrypt_message(encrypted_message): Decrypts a given encrypted message using AES decryption and returns the original message.

User Authentication
The client requests the user to enter a username and password.
The provided password is hashed using SHA-256 and sent to the server along with the username for authentication.
If the server responds with "Authentication Successful," the client proceeds to chat.

Message Handling
The client can send messages to the server, including regular messages, broadcast messages, and kick requests.
Messages are encrypted before being sent to the server for added security.
Messages received from the server are decrypted and displayed to the user.

Command Processing
The client processes commands entered by the user. Supported commands include:
/kick username: Initiates a kick request to remove the specified user from the chat.
/broadcast message: Sends a message to all connected users.
Messages and commands are formatted and encrypted before being sent to the server.

Main Execution
The client establishes a connection to the server using asyncio.
User authentication is performed by sending encrypted credentials to the server.
If authentication is successful, the client enters the chat environment and can send/receive messages.
If authentication fails, an error message is displayed.

Security Features
Authentication: Users must provide valid credentials (username and password) to access the chat.
Encryption: Messages exchanged between the client and server are encrypted using AES encryption with a secret key.

Usage
The client starts and requests the user to enter a username and password.
The provided credentials are sent to the server for authentication.
If authentication is successful, the client enters the chat environment.
The client can send regular messages, broadcast messages, or initiate kick requests using specific commands.
Messages and commands are encrypted before being sent to the server.
The client displays incoming messages and responds to server actions.
