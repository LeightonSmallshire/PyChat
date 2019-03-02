import asyncio
import struct
from asyncio import Protocol, Transport
from hashlib import sha3_256
from os.path import join as joinpath
from weakref import WeakSet

from modules.cryptography import RC4, DHE
from modules.misc import Constants
from modules.misc import bytes_to_int, int_to_bytes
from modules.pluginRunner import plugin_build

ENCODING = Constants.ENCODING  # Constants.ENCODING becomes global


# noinspection PyAttributeOutsideInit
class _CommonProtocol(Protocol):
    """Contains methods both server and client use."""
    Enum = Constants.Enum
    request_size = {Enum.REQ_QUERY: 0}
    transport: Transport

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.loop = asyncio.get_event_loop()
        self.buffer = b''  # Buffered incoming data
        self._bytestream = None  # A generator object
        self.waiting_identifiers = {}  # Queued promises per type.
        self.tasks = WeakSet()  # The list of pending tasks.
        self._last_identifier = 0

    def connection_made(self, transport):
        """Called when a connection has been made."""
        self.transport: Transport = transport  # Similar to a socket
        self.address = transport.get_extra_info('peername')  # (IP, port)
        print(f'Connection made: {self.address}')

    def data_received(self, data):
        """Called by the event loop whenever data is received."""
        try:
            req_type, identifier, content = self._parse(data)
            print('Received', Constants.Enum(req_type), content)
            if req_type is self.Enum.RESPONSE:
                assert identifier in self.waiting_identifiers, ''
                future = self.waiting_identifiers.pop(identifier)  # Pop the promise
                future.set_result(content)  # Hand the data to the promise
            else:
                task = self.request_lookup[req_type](self, identifier, *content)
                self.create_task(task)  # Queue the request
                return req_type, identifier, content
        except BaseException as e:
            print(e, e.__traceback__)
            raise e

    def connection_lost(self, exc):
        """Called when the connection is lost/closed.
        Cancels all tasks created by this connection.
        """
        print(f'connection lost: {self.address}')
        for task in self.tasks:
            task.cancel()

    @staticmethod
    def encode(type, identifier: int, *content: bytes):
        """Encode a list of bytes objects to be sent.
        Each argument can be no longer than 256 bytes"""
        assert type in Constants.Enum, 'Invalid type'
        assert all(isinstance(c, bytes) for c in content), 'Invalid type'
        assert all(len(c) <= 256 for c in content), 'Content arguments can be at most 256 bytes.'
        # Concatenated length + content per input.
        content: bytes = b''.join(int_to_bytes(len(b) - 1, 1) + b for b in content)
        packet = struct.pack('!HBB', len(content), type, identifier) + content
        return packet

    @staticmethod
    def decode(content: bytes):
        """Decode the list of bytes previously encoded, minus the 'header'."""
        out = []
        i = 0
        l_size = 1  # Size of 'length' bytes
        while i < len(content):
            length = bytes_to_int(content[i:i + l_size]) + 1  # Length of the next section
            out.append(content[i + l_size:i + l_size + length])  #
            i += length + l_size
        return out

    def send(self, _type: int, *content: bytes, identifier: int = None):
        assert _type in Constants.Enum, 'Invalid type'
        identifier = identifier or self.get_identifier()
        # The 'packet' of data to send.
        packet = self.encode(_type, identifier, *content)
        if self._bytestream is not None:  # Encrypt if available
            packet = RC4.crypt_bytes(self._bytestream, packet)
        self.transport.write(packet)  # Queue the packet to be sent
        print(f'Sending {Constants.Enum(_type).name} {content}')
        return identifier

    def get_identifier(self):
        """Get the next unused identifier."""
        if isinstance(self, ServerProtocol):
            offset = 128
        elif isinstance(self, ClientProtocol):
            offset = 0
        else:
            raise NotImplemented('Improper usage. Must be called by a ServerProtocol or ClientProtocol subclass')

        # Client uses identifiers 0-127, Server uses identifiers 127-255
        _id = self._last_identifier
        next_id = lambda: (_id + 1) % 128 + offset
        _id = next_id()
        while _id in self.waiting_identifiers.keys():
            _id = next_id()
        self._last_identifier = _id
        return _id

    async def recv(self, identifier: int):
        """
        Wait for and then return the next packet to be received of response_type.
        :param identifier: The type within CommEnum to expect and wait for.
        :return: Request content tuple.
        """
        future = self.loop.create_future()  # Create a promise for a future value
        self.waiting_identifiers[identifier] = future
        data = await future
        return data  # Wait for the promised values

    def _parse(self, data: bytes):
        """
        Parse the given 'data' into a packet,
        :param data:
        :return: (Enum req_type, list content). Will be (-1, []) if a full packet was not read.
        """
        try:
            if self._bytestream:  # Decrypt the data as it comes.
                data = RC4.crypt_bytes(self._bytestream, data)
            data = self.buffer + data  # Prepend the buffer
            # First three bytes is always the length and type of data
            content_length, req_type, identifier = struct.unpack('!HBB', data[:4])
            req_type = Constants.Enum(req_type)

            if req_type in self.request_size:  # If the request has a fixed size, check it.
                assert content_length == self.request_size[req_type], f'Packet incorrect size.'
            assert content_length <= Constants.PACKET_SIZE_MAX, 'Packet too large.'

            # If the whole packet is not received, buffer & wait for the rest
            if len(data) + 4 < content_length:
                self.buffer = data
                return -1, -1, []

            self.buffer = data[content_length + 4:]  # Set buffer to the excess data
            content = data[4:content_length + 4]
            content = self.decode(content)
            return req_type, identifier, content
        except BaseException as e:
            print(e, e.__traceback__)
            self.loop.call_exception_handler({
                'message': 'manually caught',
                'exception': e,
                'protocol': self})

    def disconnect(self, reason: str = ''):
        """Disconnect from the other party.
        Sends a disconnect packet containing the reason.
        """
        reason_b = reason.encode(ENCODING)
        self.send(self.Enum.INF_DISCONNECT, reason_b)  # Send inform_disconnect message with 'reason'
        self.transport.close()  # Close the connection. Waits to send all data first. No data received hereon.

    def create_task(self, coro):
        task = self.loop.create_task(coro)
        self.tasks.add(task)  # Keep references to tasks so they can be canceled

    def log(self, message: str):
        """Add the given message to the log file."""
        with open(self.log_file, 'a') as f:
            f.write(message)

    request_lookup = {}


class ServerProtocol(_CommonProtocol):
    """A client instance as viewed by the server."""

    def __init__(self, server, log_file: str):
        super().__init__(log_file)
        self.server = server  # Reference to the Server instance.
        self.username = None  # None until logged in, then their bytes name.
        self.guest: bool = None  # None until logged in, then whether a guest or not.

    # ---------- Asyncio callbacks ----------
    def connection_made(self, transport):
        """Called when the connection is first created."""
        super().connection_made(transport)
        # Do not allow new foreign connections if server already at or past limit.
        if self.server.is_full() and self.address[0] != '127.0.0.1':
            return self.disconnect(f'Server full.')
        self.server.connections.append(self)

    def data_received(self, data):
        """Called when data is received."""
        req_type, _, _ = super().data_received(data)
        if self._bytestream is None:
            assert req_type is self.Enum.REQ_DHE, 'Encryption not set up. The only valid request is REQ_DHE.'

    def connection_lost(self, exc):
        """Called when the connection is lost or after transport.close()."""
        super().connection_lost(exc)
        if self in self.server.connections:
            self.server.connections.remove(self)
        self.server.connection_lost(self)

    # ---------------------------------------
    async def respond_handshake(self, identifier: int, *content: bytes):
        """Function that responds to Client().request_handshake()"""
        group = bytes_to_int(content[0])  # parse the contents
        other_public = bytes_to_int(content[1])
        dh = DHE(group_id=group)  # This class manages the maths.
        secret = dh.update(other_public)  # Generate the secret.
        self.send(self.Enum.RESPONSE, int_to_bytes(dh.public), identifier=identifier)  # Send the response.
        key = RC4.convert_int_key(secret)  # Convert key for RC4
        self._bytestream = RC4.generate(key)  # Create the keystream generator
        print('Secret:', secret)

    async def respond_query(self, identifier: int):
        """Function that responds to Client().request_query()"""
        server = self.server
        content = struct.pack(Constants.QUERY_FORMAT,
                              server.allow_guests, server.allow_signup, len(server.connections), server.users_max)
        self.send(self.Enum.RESPONSE, content, identifier=identifier)

    async def respond_signup(self, identifier: int, username: bytes, password: bytes):
        """Function that handles signup requests."""
        Enum = self.Enum
        users_dict = self.server.user_shelf
        str_username = username.decode(ENCODING)

        if len(username) > 30:  # Limit username length
            return self.send(Enum.RESPONSE, Enum.USER_ERR.byteValue,
                             f'Username must be less than 20 characters.'.encode(ENCODING), identifier=identifier)
        elif len(password) != sha3_256().digest_size:  # Password (hash) not the expected size.
            return self.send(
                Enum.RESPONSE, Enum.USER_ERR.byteValue,
                'Password must be provided to register.\nClose tab and retry.'.encode(ENCODING), identifier=identifier)
        elif not self.server.allow_signup:  # If server does not allow sign-ups, then refuse the request
            return self.send(Enum.RESPONSE, Enum.SIGNUP_DISABLED.byteValue, identifier=identifier)
        elif str_username in users_dict:  # If username is already in the database, refuse the request
            return self.send(Enum.RESPONSE, Enum.USERNAME_TAKEN.byteValue, identifier=identifier)
        else:
            users_dict[str_username] = password
            self.username = username
            self.guest = False
            self.server.connection_made(self)
            return self.send(Enum.RESPONSE, Enum.OK.byteValue, identifier=identifier)

    async def respond_login(self, identifier: int, username: bytes, password: bytes):
        """Function that handles login requests"""
        Enum = self.Enum
        users_dict = self.server.user_shelf
        str_username = username.decode(ENCODING)

        if len(password) == 1:  # password was blank. Should be \x00 but value does not matter.
            if self.server.allow_guests:
                self.username = username
                self.guest = True
                self.server.connection_made(self)
                return self.send(Enum.RESPONSE, Enum.OK.byteValue, identifier=identifier)
            else:
                return self.send(Enum.RESPONSE, Enum.GUESTS_DISABLED.byteValue, identifier=identifier)
        elif len(password) != sha3_256().digest_size:
            # Password (hash) not the expected size.
            return self.send(Enum.RESPONSE, Enum.HASH_INVALID.byteValue, identifier=identifier)
        elif str_username in users_dict and password == users_dict[str_username]:
            # Username exists and matches the stored password, log the user in.
            self.username = username
            self.guest = False
            self.server.connection_made(self)
            return self.send(Enum.RESPONSE, Enum.OK.byteValue, identifier=identifier)
        else:
            return self.send(Enum.RESPONSE, Enum.USER_ERR.byteValue,
                             f'Incorrect username or password'.encode(ENCODING), identifier=identifier)

    async def respond_sync(self, identifier: int, name: bytes = None):
        """Respond to plugin sync requests."""
        assert self.username is not None, 'User must be logged in'
        client_plugin_names: tuple = self.server.client_plugins
        b_names = (n.encode(ENCODING) for n in client_plugin_names)
        if name is None:  # No plugin requested, respond with the list of plugin names
            return self.send(self.Enum.RESPONSE, *b_names, identifier=identifier)
            # todo, this is limited by packet size. Note

        else:  # Plugin requested by name, send the plugin's source.
            path = joinpath(self.server.plugin_folder, name.decode(ENCODING) + '.py')
            with open(path) as f:
                source = f.read().encode(ENCODING)
            source_size = len(source)
            # Number of blocks the plugin will be sent in, rounded up
            blocks = (source_size + Constants.BLOCK_SIZE - 1) // Constants.BLOCK_SIZE

            _hash = sha3_256(source).digest()  # Hash of the file
            self.send(self.Enum.RESPONSE, int_to_bytes(blocks), _hash, identifier=identifier)

            for i in range(0, source_size, Constants.BLOCK_SIZE):
                self.send(Constants.Enum.RESPONSE, source[i:i + Constants.BLOCK_SIZE], identifier=identifier)
                await asyncio.sleep(0.1)  # Give control back to the event loop

    async def respond_plugin(self, identifier: int, plugin_name: bytes, *contents: bytes):
        assert self.username is not None, 'User must be logged in'
        context = {'user': self.username, 'content': contents, 'identifier': identifier}
        self.server.plugins[plugin_name.decode(ENCODING)].server_handle(context)

    # ----------- Class constants -----------
    Enum = Constants.Enum  # Shortened reference for below
    # Lookup for what function deals with each packet type.
    request_lookup = {Enum.INF_DISCONNECT: _CommonProtocol.disconnect,
                      Enum.REQ_DHE: respond_handshake, Enum.REQ_QUERY: respond_query,
                      Enum.REQ_SIGNUP: respond_signup, Enum.REQ_LOGIN: respond_login,
                      Enum.REQ_SYNC: respond_sync, Enum.PLUGIN: respond_plugin}


# noinspection PyAttributeOutsideInit
class ClientProtocol(_CommonProtocol):
    def __init__(self, page):
        """
        :param page:
        :type page: modules.clientWidgets.ChatPage
        """
        super().__init__(page.log_file)
        self.page = page  # The ChatPage instance it is connected to

    # ---------------------------------------
    async def request_handshake(self):
        """Establishes a shared key and starts encryption."""
        group = 14
        dh = DHE(group_id=group)  # Manages the maths.
        ident = self.send(self.Enum.REQ_DHE, int_to_bytes(group, 1), int_to_bytes(dh.public))  # Send the response.

        other_public, = await self.recv(ident)
        other_public = bytes_to_int(other_public)
        secret = dh.update(other_public)  # Generate the secret.

        key = RC4.convert_int_key(secret)
        self._bytestream = RC4.generate(key)
        print('Secret established:', secret)

    async def request_query(self):
        ident = self.send(self.Enum.REQ_QUERY)  # Send the request
        response, = await self.recv(ident)  # Wait for response
        # Unpack the data into a dict. Leaves room for future additions.
        return Constants.QUERY_TUPLE(*struct.unpack(Constants.QUERY_FORMAT, response))._asdict()

    async def request_login(self, username: str, password: str, register: bool = False):
        # Ensure that encryption is being used
        if self._bytestream is None:
            await self.request_handshake()  # Queue and wait for the encryption
        # Format the username and convert to bytes
        username = username.strip()  # Strip username of whitespace but not passwords
        username = username.encode(Constants.FIXED_ENCODING)
        # Hash the password if present, \x00 byte if no password
        password = b'\x00' if password == '' else sha3_256(password.encode(Constants.FIXED_ENCODING)).digest()
        request_type = self.Enum.REQ_SIGNUP if register else self.Enum.REQ_LOGIN

        ident = self.get_identifier()
        response = self.recv(ident)
        self.send(request_type, username, password, identifier=ident)  # Send the login request
        response = await response  # Wait for the response
        response_type = self.Enum(bytes_to_int(response[0]))  # One of; OK, GUESTS_DISABLED, HASH_INVALID, USER_ERR
        return response_type, response[1:]

    async def request_sync(self, name: str = None):
        # Request for plugin list if name is None or the source for plugin with name
        if name is None:
            ident = self.send(self.Enum.REQ_SYNC)  # Send request for name list
            names = await self.recv(ident)  # Wait for reply
            names = tuple(n.decode(ENCODING) for n in names)  # Decode names to strings
            return names
        else:  # Name is given, request for that plugin and create it.
            ident = self.send(self.Enum.REQ_SYNC, name.encode(ENCODING))
            blocks, _hash = await self.recv(ident)
            blocks = bytes_to_int(blocks)

            source = bytearray()
            for _ in range(blocks):  # Concatenate the blocks back into the source.
                dat = await self.recv(ident)
                source.extend(dat[0])
            return plugin_build(self.page.interface, name, source.decode('utf-8'), proto=self, page=self.page)

    async def _sync_loop(self):
        """A coroutine that periodically tries to update the list of plugins."""
        active_names = self.page.client_plugins.keys()  # Names of plugins running.
        while True:
            server_names = set(await self.request_sync())  # Names of plugins on server.
            names_added = server_names - active_names  # Plugins added since last check
            names_removed = active_names - server_names  # Plugins removed since last check

            for name in names_removed:  # Removed plugins
                del self.page.client_plugins[name]
            for name in names_added:  # Added plugins
                self.page.client_plugins[name] = await self.request_sync(name)

            await asyncio.sleep(60)  # Wait for 60s between checks

    async def respond_plugin(self, identifier, plugin_name: bytes, user: bytes, *content: bytes):
        context = {'user': user, 'content': content, 'identifier': identifier}
        # try:
        self.page.client_plugins[plugin_name.decode(ENCODING)].client_handle(context)
        # except:
        #     pass

    # ----------- Class constants -----------
    Enum = Constants.Enum  # Shortened reference for below
    # Functions to respond to server requests
    request_lookup = {Enum.INF_DISCONNECT: _CommonProtocol.disconnect, Enum.PLUGIN: respond_plugin}
