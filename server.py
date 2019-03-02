#!/usr/bin/env python3
"""
Server code.
When run with 'python server.py' or otherwise, starts a server.
"""
import argparse
import asyncio
import shelve
from os.path import dirname, abspath, join as joinpath

from modules.communication import ServerProtocol, Constants
from modules.misc import exception_handler
from modules.pluginRunner import load_plugins, make_interface_factory, CLIENT, SERVER, get_plugin_attrs

this_path = dirname(__file__)  # Path to the folder this script is in.
ENCODING = Constants.ENCODING


class Server:
    def __init__(self, host: str, port: int, *, log_file: str, users_max: int, allow_guests: bool, allow_signup: bool,
                 users_file: str, data_folder):
        """
        Create a server instance. Prepares plugins.
        use Server().mainloop() to start receiving connections and run forever.
        :param host: The address to bind the server socket to.
        :param port: The port to bind the server socket to. Will auto-assign if 0.
        :param log_file: The name of the log file within 'data_folder'. Will be created if file absent.
        :param users_max: The maximum number of users that can be connected at one time. Does not count from 127.0.0.1.
        :param allow_guests: Whether the server allows 'guest' connections, unregistered users.
        :param allow_signup: Whether the server allows new users to sign-up/ register a username&password combination.
        :param users_file: The name of the file used to store login information within 'data_folder'.
        :param data_folder: The path to the folder containing server data and log files. Defaults to '../_ServerData'.
        """
        # Set basic attributes
        self.connections: list = []  # List of active connection tasks
        self.loop = asyncio.get_event_loop()
        self.address = host, port
        self.users_max = users_max
        self.allow_guests = allow_guests
        self.allow_signup = allow_signup

        self.data_folder = data_folder = abspath(data_folder) if data_folder else joinpath(this_path, '_ServerData')
        self.log_file = joinpath(data_folder, log_file)
        self.users_file = joinpath(data_folder, users_file)
        self.plugin_folder = plugin_folder = joinpath(data_folder, 'Plugins')

        self.user_shelf = shelve.open(self.users_file)  # Persistent dictionary-like; {username: passwordHash, ...}
        self.loop.set_exception_handler(exception_handler)

        # Load the plugins
        self.plugins = plugins = {}  # {name: plugin, ...}
        self.interface = make_interface_factory(plugins, data_folder, server=self)
        load_plugins(plugins, self.interface, plugin_folder, SERVER)  # Load the plugins into the 'plugins' dict

        plugins = {}  # {name: plugin, ...}
        load_plugins(plugins, self.interface, plugin_folder, CLIENT)
        self.client_plugins = tuple(plugins.keys())  # List of client plugin names.
        self.plugin_responses = get_plugin_attrs(plugins, 'server_handle')

        self.loop.create_task(self.loop.create_server(lambda: ServerProtocol(self, log_file), host, port))

    def is_full(self):
        """Returns true if the server has users_max or more users connected."""
        return len(self.connections) >= self.users_max

    def mainloop(self):
        self.loop.run_forever()

    # ----------- plugin callbacks ---------------------------------------
    def __plugin_callback(self, fn_name: str, *args):
        for plugin in self.plugins.values():
            if hasattr(plugin, fn_name):
                try:
                    getattr(plugin, fn_name)(*args)  # Get & call the function with context.
                except BaseException as e:  # Log the error in the plugin's log file.
                    plugin.__builtins__.print(f'Error {e} caught within "{fn_name}".')

    def connection_made(self, proto: ServerProtocol):
        """Called when a user logs into the server. Calls all plugins' server_connection_made() functions."""
        assert proto.username is not None and proto.guest is not None, "Sanity check"
        self.__plugin_callback('server_connection_made', {'user': proto.username, 'guest': proto.guest})

    def connection_lost(self, proto: ServerProtocol):
        """Called when a user disconnects from the server. Calls all plugins' server_connection_lost() functions."""
        if proto.username is not None and proto.guest is not None:
            self.__plugin_callback('server_connection_lost', {'user': proto.username, 'guest': proto.guest})


if __name__ == '__main__':
    # Gets IP and PORT from command line and parses them
    ConnectionInfo = argparse.ArgumentParser()
    ConnectionInfo.add_argument("-host", default='127.0.0.1')
    ConnectionInfo.add_argument("-port", type=int, default='65535')
    ConnectionInfo.add_argument("-log_file", default='serverLog.log')
    ConnectionInfo.add_argument("-users_max", type=int, default=32)
    ConnectionInfo.add_argument("-deny_guests", dest='allow_guests', default=True, action='store_false')
    ConnectionInfo.add_argument("-allow_signup", default=False, action='store_true')
    ConnectionInfo.add_argument("-users_file", default='registered_users')
    ConnectionInfo.add_argument("-data_folder", default=None)
    parsed = ConnectionInfo.parse_args()  # Parse the command line for the above args.

    # Create and start the server's mainloop.
    Server(**parsed.__dict__).mainloop()
