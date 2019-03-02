import os
from collections import namedtuple
from importlib import util
from sys import stderr

from modules.misc import Constants, inf

INTERFACE_TUPLE = namedtuple("PluginInterface", "CLIENT SERVER BOTH import_replacement print send_to send "
                                                "add_bubble add_message broadcast")
ALLOWED_MODULES = ('math', 'tkinter', 'asyncio')

CLIENT: int = 1
SERVER: int = 2
BOTH: int = CLIENT | SERVER


def make_interface_factory(plugins: dict, data_folder: str, server=None):
    """:param plugins: {pluginName: Plugin or None, ...}. The value should be None while it has yet to load."""

    def interface_factory(plugin_name: str, proto=None, page=None):
        """Called to create an 'interface' namedtuple instance specific to each plugin.
        :param plugin_name: Name of the plugin
        :param proto: Protocol instance
        :param page: ChatPage instance if run on a client, otherwise None.
        :return: Interface namedtuple instance.
        """
        # Called near the start of 'build_plugin' with the plugin-specific details.
        b_name = plugin_name.encode(Constants.ENCODING)

        def import_replacement(name, globals=None, locals=None, fromlist=None, level=None):
            """A replacement for the standard __import__ function."""
            try:
                assert fromlist is None, "__import__ 'fromlist' argument unsupported within plugins."
                assert level is 0, "Only absolute imports are permitted within plugins."
                module_spec = util.find_spec(name)  # Try to find an installed module.
                if module_spec is not None:  # Standard module found
                    # Allowed standard modules.
                    if name in ALLOWED_MODULES:  # if in list of allowed modules
                        return __import__(name, globals, locals, [], 0)  # import normally
                    raise ImportError('Illegal standard library module.', name)  # otherwise, raise error
            except BaseException as e:
                raise ImportError('Module not found', name, e, e.args, e.__traceback__)

        def print_override(*args, **kwargs):
            """Override the default print function to instead append to a log file for that plugin.
            Creates the file if it does not exist. The file will be placed into 'data_folder'."""
            with open(f'{data_folder}/{plugin_name}.log', 'a') as f:  # open the plugin's log file in append mode.
                print(*args, **{**kwargs, 'file': f})  # Normal print but output to the log file.

        def _send(conn, *content, identifier=None):  # Send '*content' over connection (protocol) 'conn'
            conn.send(Constants.Enum.PLUGIN, b_name, *content, identifier=identifier)

        def send(*content:bytes, identifier=None):
            return _send(proto, *content, identifier=identifier)

        add_bubble = getattr(page, 'add_bubble', None)
        add_message = getattr(page, 'add_message', None)

        def send_to(user, *content: bytes, identifier=None):
            """Send the given packet, wrapped in a PLUGIN packet with the plugin's name to the given user."""
            conn = next((c for c in server.connections if c.username == user), None)  # First username match
            if conn is None:
                raise ValueError(f'User {user} is not connected')
            _send(conn, *content, identifier=identifier)

        def broadcast(user, *content: bytes, blacklist=()):
            for conn in server.connections:
                if conn.username not in blacklist:
                    _send(conn, user, *content)

        return INTERFACE_TUPLE(CLIENT, SERVER, BOTH, import_replacement, print_override, send_to, send, add_bubble,
                               add_message, broadcast)

    return interface_factory


def get_plugin_attrs(plugins: dict, attr: str = 'server_handle'):
    """Produces a dict {key: value.attr, ...} for each key,value pair in the 'plugins' dict."""
    return {k: getattr(v, attr) for (k, v) in plugins.items() if hasattr(v, attr)}


def plugin_build(interface_factory, name: str, source: str, **kwargs):
    """Create a ModuleType instance from the plugin.
    The plugin is created in a controlled environment, with modified built-ins and globals.
    :param interface_factory: A function used to produce interface instances.
    :param name: The string name of the plugin
    :param source: The string source code of the plugin.
    :return: The plugin ModuleType.
    """
    # noinspection PyUnresolvedReferences
    from types import ModuleType
    assert type(name) is str, 'String name must be given'
    assert '\\' not in name and '/' not in name, 'Plugin must be a file with no specified path'
    assert isinstance(source, str), 'Source code must be a string object'
    code = compile(source, '', 'exec')  # Compile the plugin code to be run.

    interface = interface_factory(name, **kwargs)
    plugin: ModuleType = ModuleType("<<Plugin>> " + name)  # Create a fake Module instance.
    plugin_dict = plugin.__dict__
    # Edit builtins so that only specific functions are allowed, and imports use a wrapper for this function.
    plugin_builtins = plugin_dict['__builtins__'] = globals()['__builtins__'].copy()  # Copy current built-ins
    plugin_builtins['__import__'] = interface.import_replacement  # Replace the import function
    plugin_builtins['INTERFACE'] = interface  # Give a reference to the interface
    plugin_builtins['Constants'] = Constants
    plugin_builtins['print'] = interface.print  # Replace the print function with a logging function.
    del plugin_builtins['open']  # Remove file access.
    # Potentially remove access to or replace other global methods or attributes for additional security
    try:
        exec(code, plugin.__dict__, plugin.__dict__)  # Execute the code, storing all within the Module object.
    except BaseException as e:
        raise ImportError(f'Failed to load plugin \'{name}\' with error;', type(e).__name__, *e.args)

    # Validity tests
    assert hasattr(plugin, 'MODE'), 'Plugin \'MODE\' is not defined.'
    assert type(plugin.MODE) is int, 'Only integer modes are accepted.'  # Does not allow subclasses.
    plugin.__dict__.setdefault('PRIORITY', 0)  # Sets PRIORITY to zero by default
    assert plugin.PRIORITY is inf or type(plugin.PRIORITY) is int, '\'PRIORITY\' must be an int or infinity.'
    return plugin


def load_plugins(plugins: dict, interface_factory, folder: str, mode: int, *, verbose=True) -> None:
    """Load the Plugins from the plugin folder, ignoring Plugins that fail to load."""
    assert isinstance(mode, int) and 0 <= mode <= 3, 'Invalid mode'

    def plugin_load(name: str):
        """Tries to load the plugin, returning 'None' rather than raising errors."""
        try:
            assert '\\' not in name and '/' not in name, 'Plugin must be a filename, not path.'

            with open(f'{folder}/{name}.py') as f:
                plugin = plugin_build(interface_factory, name, f.read())
            assert plugin.MODE & mode, f'Plugin \'{name}\' does not support current running mode.'
            return plugin
        except BaseException as e:
            if verbose:
                print(e, file=stderr)
            return None

    files = os.listdir(folder)  # list of files in the plugin folder
    files = map(lambda f: os.path.splitext(f), files)  # split each file into its path and extension
    files = filter(lambda f: f[1] == '.py', files)  # filter Plugins to be only '.py' files. f is [path, extension]
    loaded = {file: plugin_load(file) for file, _ in files}  # Attempt to load all Plugins into a dict.
    loaded = {k: v for (k, v) in loaded.items() if v is not None}  # Remove Plugins that failed to load
    plugins.update(loaded)  # Update
