"""A collection of miscellaneous functions"""
import asyncio
import enum
from collections import namedtuple
from os import path
from sys import stderr
from time import strftime

inf = float('inf')  # Infinity constant shorthand.


def int_to_bytes(i: int, l: int = None, order: str = 'big') -> bytes:
    """Convert int 'i' to bytes."""
    l = l or (i.bit_length() + 7) // 8
    return i.to_bytes(l, order)


def bytes_to_int(b: bytes, order: str = 'big') -> int:
    """Convert bytes 'b' to an int."""
    return int.from_bytes(b, order)


def hex_to_int(h: str) -> int:
    return bytes_to_int(bytes.fromhex(h))


def int_to_hex(i: int, *a, **kw):
    return int_to_bytes(i, *a, **kw).hex()


def exception_handler(loop: asyncio.BaseEventLoop, context: dict):
    """
    Called when errors within the loop are not caught before it reaches the EventLoop.
    Calls protocol.disconnect and protocol.log if possible, otherwise defaults to the normal handler.

    :param loop: The loop that ran the raising function.
    :param context: A dictionary containing information on the raising context. See breakdown below.
    :return: None
    ------- 'context' breakdown -------
    ‘message’             : Error message
    ‘exception’ (optional): Exception object
    ‘future’    (optional): asyncio.Future instance
    ‘handle’    (optional): asyncio.Handle instance
    ‘protocol’  (optional): Protocol instance
    ‘transport’ (optional): Transport instance
    ‘socket’    (optional): socket.socket instance
    """
    message: str = context['message']
    exception: BaseException = context.get('exception', None)
    protocol = context.get('protocol', None)

    if exception:  # If we know the exception object, generate our own message
        _time = strftime('%Y-%m-%d-%H:%m:%S')
        _type = type(exception)
        _file = exception.__traceback__.tb_frame.f_code.co_filename  # The path the exception came from
        _file = path.split(_file)[1]  # Just the filename from line above
        _line = exception.__traceback__.tb_lineno  # The line the exception came from
        context['message'] = message = f'{_time}:{type(exception)}({message}) at {_line} in {_file}'

    if protocol is not None:
        protocol.disconnect('Unexpected error raised.')
        protocol.log(message)
        print(message)
        return
    else:
        # Print warning to console. Probably seen by plugin developers, as console is usually disabled.
        print('Protocol unknown, cannot handle the error. Please report the below error to developer.', file=stderr)
        loop.default_exception_handler(context)  # Use the default exception handler.


class Constants:
    ENCODING = 'utf-8'  # Should be same for both client and server, actual encoding does not matter.
    FIXED_ENCODING = 'utf-8'  # Encoding used for username and password encoding. Changes would corrupt login data.
    PACKET_SIZE_MAX = 4096  # Maximum size of a single 'packet' allowed.
    BLOCK_SIZE = 256  # Maximum size of a single 'block' of plugin source code.
    # Query parsing
    QUERY_FORMAT = '!??HH'
    QUERY_TUPLE = namedtuple('QuarryTuple', 'allow_guests allow_signup users_now users_max')

    @enum.unique  # Ensures unique values
    class Enum(enum.IntEnum):
        """An enumeration of all control signals needed for communication.
        All values must be unique integers.
        Acronym disambiguation;
            REQ     Request         (expects RES/response)
            RES     Response
            INF     Inform          (not expecting a response)
        """
        # Type constants
        RESPONSE = 0
        REQ_DHE = 1
        REQ_QUERY = 2
        REQ_LOGIN = 3
        REQ_SIGNUP = 4
        REQ_SYNC = 5
        INF_DISCONNECT = 6
        PLUGIN = 7
        # Response values
        OK = 100
        USER_ERR = 101
        HASH_INVALID = 102
        SIGNUP_DISABLED = 103
        GUESTS_DISABLED = 104
        USERNAME_TAKEN = 105
        USERNAME_INVALID = 106
        # Note; No value can exceed 255.

    # Also calculate the big-endian byte equivalent for each int and store it as an attribute
    for attr in Enum:
        attr.byteValue = int_to_bytes(attr.value, 1)
