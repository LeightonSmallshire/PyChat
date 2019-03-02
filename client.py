#!/usr/bin/python3.6
"""
Client code.
When run with 'python client.py' or otherwise, starts a client.
"""
import asyncio
import tkinter as tk
from os.path import dirname, abspath, join as joinpath

from modules.clientWidgets import TabManager, COLOUR_DEFAULTS
from modules.misc import exception_handler

this_path = dirname(__file__)  # Path to the folder this file is in


class Client:
    def __init__(self, log_file: str = 'clientLog.log', data_folder=None):
        """
        Create a client instance.
        use Client().start() to create the two threads and start them.
        :param log_file: The name of the log file within 'data_folder'. Will be created if file absent.
        :param data_folder: The path to the folder containing server data and log files. Defaults to '../_ClientData'.
        """
        # Set basic attributes
        self.loop = loop = asyncio.get_event_loop()
        loop.set_exception_handler(exception_handler)  # Called for any uncaught exceptions
        # File & folder setup
        self.data_folder = data_folder = \
            abspath(data_folder) if data_folder is not None else joinpath(this_path, '_ClientData')
        self.log_file = joinpath(data_folder, log_file)
        # Setup the GUI
        self.root = root = tk.Tk()  # Create the window
        root.title('PyChat')
        root.minsize(270, 360)
        root.tk_setPalette(**COLOUR_DEFAULTS)
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        self.tab_manager = TabManager(self, root)
        self.tab_manager.frame.grid(sticky='NSEW')

    def start(self, freq=20):
        """Start and run the client forever."""
        # Queue task for periodically updating the GUI.
        self.loop.run_until_complete(self._tk_loop(frequency=freq))

    async def _tk_loop(self, frequency):
        """A coroutine that periodically runs the tkinter event loop until all its events are handled."""
        while True:
            try:
                self.root.update()  # Handle the events
                await asyncio.sleep(1 / frequency)  # Wait 1/freq seconds until next call
            except:
                return  # End this task when tkinter exits.


if __name__ == '__main__':
    Client().start()
