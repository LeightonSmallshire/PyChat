"""
A plugin serving as an example of a plugin and also as the 'core' mechanics of the client-server default behaviour.

Specification breakdown;
    PRIORITY is an integer constant that specifies the plugin's priority in having its client_parse function called
        relative to other plugins. The default is zero and the higher the priority, the earlier the plugin is called.
    MODE is an integer flag enumeration, defining whether the plugin will run on servers, clients, both or neither.

    INTERFACE is a global variable specific to each plugin that provides callback functions, allowing the plugin limited
        control of the client's page and to communicate between the client and server.
    Constants is a global variable shared among all plugins, providing a set of constants to the plugins.

    If MODE is zero or not defined, the plugin will not be loaded.
    Mode is a flag enumeration.
        Bit 1   ->  Run client-side
        Bit 2   ->  Run server-side
"""
# PRIORITY = inf  # Priority determines client_parse call order between plugins. Defaults to zero. Highest first.
MODE = INTERFACE.BOTH  # This plugin will run on both the server and client.
ENCODING = Constants.ENCODING
add_message = INTERFACE.add_message


def client_parse(context: dict) -> (True, False, None):
    """
    Called client-side to parse and handle user input.
    :param context: A dictionary containing all relevant information. Breakdown below.
    :return: True       if the data has been handled (no further plugins' client_parse called)
    :return: False/None if the data has NOT been handled (call the next plugin with same context object)
    ------- 'context' breakdown -------
    'input'     : The user-supplied string.
    """
    _input: str = context['input']
    INTERFACE.send(_input.encode(Constants.ENCODING))  # Send the message
    add_message(_input, 1)  # Add text bubble on right side
    return True  # Always handles the data.


def client_handle(context: dict) -> None:
    """
    Called client-side to handle data from the server.
    :param context:
    :return: None
    ------- 'context' breakdown -------
    'user'                  : The bytes username of the sender.
    'content'               : Tuple of bytes.
    'identifier'            : Integer identifier for communication.
    """
    assert len(context['content']) == 1, 'Expected to receive only one element.'
    user, message = context['user'].decode(ENCODING), context['content'][0].decode(ENCODING)
    add_message(f'{user}: {message}', 0)  # Add text bubble on left side


def server_handle(context: dict) -> None:
    """
    Called server-side to handle data from clients.
    :param context:
    :return:
    ------- 'context' breakdown -------
    'user'                  : The bytes username of the sender.
    'content'               : Tuple of bytes
    'identifier'            : Integer identifier for communication.
    """
    user, content = context['user'], context['content']
    # Broadcast the content to everyone but the sender.
    INTERFACE.broadcast(user, *content, blacklist=(user,))


def server_connection_made(context) -> None:
    user = context["user"]
    message = f'{user.decode(ENCODING)} has joined.'
    if context["guest"] is True:
        message = 'Guest ' + message
    message = message.encode(ENCODING)
    INTERFACE.broadcast(b'SYSTEM', message, blacklist=(user,))


def server_connection_lost(context) -> None:
    user = context["user"]
    message = f'{user.decode(ENCODING)} has left.'
    if context["guest"] is True:
        message = 'Guest ' + message
    message = message.encode(ENCODING)
    INTERFACE.broadcast(b'SYSTEM', message, blacklist=(user,))
