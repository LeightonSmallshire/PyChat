import asyncio
import tkinter as tk

from modules.communication import ClientProtocol
from modules.misc import Constants
from modules.pluginRunner import make_interface_factory, INTERFACE_TUPLE

# Global colour constants
COLOUR_FG = '#eeeeee'  # '#b0b0b0'
COLOUR_BG = '#999999'  # '#282828'
COLOUR_FG_SELECTED = '#ffff33'  # '#3c3c3c'
COLOUR_BG_SELECTED = '#ffffff'  # '#323232'
COLOUR_TEXT = '#101010'

COLOURS_BASIC = {'foreground': COLOUR_FG, 'background': COLOUR_BG}
COLOUR_DEFAULTS = {**COLOURS_BASIC, 'activeforeground': COLOUR_FG_SELECTED, 'activebackground': COLOUR_BG_SELECTED}

COLOUR_INVERTED = {'foreground': COLOUR_BG, 'background': COLOUR_FG}
COLOURS_BUBBLE = {'bg': COLOUR_BG, 'activebackground': COLOUR_BG_SELECTED,
                  'fg': COLOUR_FG, 'activeforeground': COLOUR_FG_SELECTED}
COLOURS_TEXT = {**COLOURS_BASIC, 'fg': COLOUR_TEXT, 'activeforeground': COLOUR_TEXT}


def find_in_grid(frame, row, column):
    """"""
    for child in frame.children.values():
        info = child.grid_info()
        # note that rows and column numbers are stored as string
        if info['row'] == str(row) and info['column'] == str(column):
            return child


class ScrollableFrame(tk.Frame):
    """A tk.Frame object that has a built-in vertical scrollbar."""

    def __init__(self, master, *args, **kwargs):
        """Create the ScrollableFrame object."""
        # ------- Details -------
        # attribute Type        Master
        # self      Frame       __canvas        This object.
        # __top     Frame       master (arg)    Contains sub-objects.
        # __canvas  Canvas      __top           Used for its scroll functionality. Contains 'self' object.
        # __vsb     Scrollbar   __top           Placed to the right of the __canvas object. The scrollbar.

        # Instance the objects
        self.__top = tk.Frame(master, *args, **kwargs)  # Contains all sub-objects.
        self.__canvas = tk.Canvas(self.__top, highlightthickness=0, **kwargs)
        super().__init__(self.__canvas, *args, **kwargs)
        self.__vsb = tk.Scrollbar(self.__top, orient=tk.VERTICAL, command=self.__canvas.yview)
        # Place the objects within their containers
        self.__canvas.create_window((0, 0), window=self, anchor=tk.NW, tags="self.frame")
        self.__vsb.pack(side=tk.RIGHT, fill=tk.Y)  # Place to right of canvas. Stretch vertically.
        self.__canvas.pack(side=tk.LEFT, fill="both", expand=True)  # Place to left of scrollbar. Fill the area.
        # Configure the objects
        self.__canvas.configure(yscrollcommand=self.__vsb.set)
        self.bind_updates(self, self.__top, self.__canvas)  # Scrolling up and down.
        self.columnconfigure(0, weight=1)  # Column 0 can expand
        self.columnconfigure(1, weight=1)  # Column 1 can expand
        self.rows = 0
        # Bind the resize event to also update the canvas' viewable area
        self.__top.bind("<Configure>", lambda _: self.__canvas.configure(scrollregion=self.__canvas.bbox("all")))
        self.bind_updates()

    def grid(self, *args, **kwargs):
        # Instead of placing 'self' in a position, place '__top' there instead. '__top' contains self, etc.
        return self.__top.grid(*args, **kwargs)

    def pack(self, *args, **kwargs):
        return self.__top.pack(*args, **kwargs)

    def place(self, *args, **kwargs):
        return self.__top.place(*args, **kwargs)

    def __scroll_fn(self, e):
        """Called to move the scrollbar with the mouse wheel"""
        try:  # Platform-independent
            self.__vsb.event_generate(f'<Button-{e.num}>')
        except:
            self.__vsb.event_generate('<MouseWheel>', delta=e.delta, time=e.time,
                                      x=e.x, y=e.y, rootx=e.x_root, rooty=e.y_root)

    def bind_updates(self, *widgets, widget=None):
        """Bind scrolling events to the scroll function"""
        for c in widgets or (widget or self).winfo_children():
            c.bind("<MouseWheel>", self.__scroll_fn)
            c.bind("<Button-4>", self.__scroll_fn)
            c.bind("<Button-5>", self.__scroll_fn)

    def trigger_update(self):
        """"""
        self.__top.event_generate('<Configure>')
        self.__top.event_generate('<Configure>')
        self.__top.update_idletasks()


class TabManager:
    """Manages its list of tabs."""

    def __init__(self, client, master):
        """
        :param client:
        :type client: client.Client
        :param master:
        """
        self.client = client
        self.frame = frame = tk.Frame(master)  # Containing frame.
        self.tab_frame = tk.Frame(self.frame, background=COLOUR_BG)  # Contains tabs.
        frame.grid_columnconfigure(0, weight=1)  # Tabs expand horizontally only
        frame.grid_rowconfigure(1, weight=1)  # Tab contents expand both dirs

        self.tabs = []  # the list of connected tabs
        self.active = None  # the active/selected tab
        self.__adder = self.tab_adder()  # the button used to add new tabs
        self.tab_frame.grid(row=0, sticky='NSEW')

    def add_tab(self, name: str, page):
        self.tabs.append(Tab(name, page, self))

    def rem_tab(self, tab):
        assert tab in self.tabs
        if len(self.tabs) >= 2:
            self.set_active(self.tabs[self.tabs.index(tab) - 1])  # Set the next-left tab as the active one
        else:
            self.active = None
        self.tabs.remove(tab)
        tab.destroy()

    def set_active(self, tab):
        if tab == self.active:
            return  # If re-selecting current tab, do nothing.

        tab.page_frame.grid(row=1, sticky='NSEW')  # Show the newly opened tab's contents
        tab.frame.configure(state=tk.ACTIVE)  # Set the new tab to active

        if self.active:  # In case there isn't a currently active tab
            self.active.frame.configure(state=tk.NORMAL)  # Set the old tab to normal
            self.active.page_frame.grid_remove()  # Hide the previously active tab's page

        self.active = tab  # Set active tab reference to the one activated

    def tab_adder(self):
        label = tk.Label(self.tab_frame, text=' + ', **COLOURS_TEXT)
        label.grid(row=0, column=100)
        label.bind('<Button-1>', lambda _: LoginWindow(self))
        return label


class Tab:
    """A tab managed by a TabManager instance.
    When clicked, other tabs' page_frames are hidden and this tab's page_frames is shown"""

    def __init__(self, name: str, page_frame, manager):
        """
        :param name: Name displayed on the tab.
        :param page_frame: The 'page' to be shown/hidden.
        :param manager: The TabManager managing this tab.
        """
        # No need to catch error; will always be called within TabManager for this case. Use value if given.
        self.manager = manager
        self.page_frame = page_frame  # The object being shown/hidden as tab is selected/deselected
        self.frame = tk.Label(manager.tab_frame, text=name, **COLOURS_TEXT)
        # Call the manager's set_active method when left-clicked.
        self.frame.bind('<Button-1>', lambda _e: manager.set_active(self))
        self.frame.bind('<Button-2>', lambda _: manager.rem_tab(self))  # middle-click closes the tab.
        # Must add the tab to the window to initialize its grid position.
        #  Has the desirable side-effect of selecting the newly created tab.
        self.frame.grid(column=len(manager.tabs), row=0)
        if hasattr(manager, 'active'):  # Only false on first call.
            manager.set_active(self)  # Simulate clicking this tab.
        else:
            self.page_frame.grid(sticky='NSEW')  # Show the newly opened tab's contents
            self.frame.configure(state=tk.ACTIVE)  # Set the tab to active

    def destroy(self):
        self.frame.grid_remove()
        self.frame.destroy()
        self.page_frame.stop()


class ChatPage(tk.Frame):
    """A 'page' within the chat client. Manages its own communication with the server."""

    def __init__(self, tab_man: TabManager, address: tuple, username: str, password: str, register: bool = False):
        """
        :param tab_man: The TabManager instance
        :param address: The (host, port) address of the server
        :param username: The string username to connect with.
        :param password: The string password to connect with.
        :param register: Boolean; If True, then the request will be to sign-up rather than log-in.
        """
        super().__init__(tab_man.frame)
        self.tab_man = tab_man
        self.client = client = tab_man.client  # The Client() instance
        self.log_file = client.log_file  # Path to log file

        self.client_plugins: dict = None  # {pluginName: pluginModule, ...}
        self.interface: INTERFACE_TUPLE = None
        self.protocol = self.transport = None

        self.message_history = ScrollableFrame(self, bg=COLOUR_INVERTED['background'])
        self.entry = tk.Entry(self, **COLOUR_INVERTED)  # Text entry
        self.entry.bind('<Return>', self.entry_send)  # Enter triggers

        self.message_history.grid(row=0, column=0, sticky='NSEW')
        self.entry.grid(row=1, column=0, sticky='NSEW')

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        loop = client.loop
        self.maintainer = loop.create_task(self.maintain_channel(address, username, password, register))

    def stop(self):
        """Called to delete this object. Cancels the task setting up its connections."""
        self.maintainer.cancel()  # Cancel the task maintaining the connection.
        self.grid_remove()
        self.destroy()
        if self.transport:
            self.transport.close()

    async def maintain_channel(self, address: tuple, username: str, password: str, register: bool = False):
        def clear_err():
            if err:  # Remove error message if one is present.
                err.grid_remove()
                # err.destroy()

        loop = asyncio.get_event_loop()
        err: tk.Canvas = None
        transport: asyncio.Transport = None
        while True:
            try:
                # Prepare for plugins.
                self.client_plugins: dict = {}  # {pluginName: pluginModule, ...}
                self.interface = make_interface_factory(self.client_plugins, self.tab_man.client.data_folder)
                # Create a connection and wait for it to initialize, then login/signup.
                self.transport, self.protocol = transport, protocol = \
                    await loop.create_connection(lambda: ClientProtocol(self), *address)
                clear_err()
                await protocol.request_handshake()  # Setup encryption
                response_type, response = await protocol.request_login(username, password, register)  # Login.
                response = [r.decode(Constants.ENCODING) for r in response]

                if response_type is Constants.Enum.OK:  # Login accepted
                    register = False  # No need to re-register.
                    protocol.create_task(protocol._sync_loop())  # Add the task to sync plugins
                    while not transport.is_closing():  # Wait in this loop until the connection is lost.
                        await asyncio.sleep(0.5)
                elif response_type is Constants.Enum.USER_ERR:  # Contents is the error text.
                    # Tell user the error in the gui
                    err = self.add_message('\n'.join(response), columnspan=2)
                    print('User error', response)
                    return  # Full-stop this tab.
                elif response_type is Constants.Enum.GUESTS_DISABLED:
                    err = self.add_message(
                        'Guests disabled on this server.\nPlease close this tab then login or signup.', columnspan=2)
                    return  # Full-stop this tab.
                else:  # Unexpected response.
                    raise NotImplementedError(response_type, response)
            except ConnectionError as e:
                clear_err()
                err = self.add_message(f'Cannot contact server; Retrying.\nReason:{e}', columnspan=2)
                print('Cannot contact server', e)
                await asyncio.sleep(5)  # Cannot connect, wait 5s then retry.
            except asyncio.CancelledError:
                return  # Immediately stop when task is canceled.
            except BaseException as e:
                # log and print error
                loop.call_exception_handler({'message': 'unexpected error', 'exception': e})
                clear_err()
                err = self.add_message(str(e), columnspan=2)
            finally:  # Always clean up nicely by closing the connection.
                if transport and not transport.is_closing():
                    transport.close()
                    print('closing transport')

    def entry_send(self, _):
        """Called when the user presses enter in the entry box.
        For each plugin, call its 'parse' function on the input until all Plugins have been called or any returns "DONE"
        """
        line = self.entry.get().strip()  # The entered text, stripped of end whitespace
        self.entry.delete(0, tk.END)  # Clear entry box
        plugins = sorted(self.client_plugins.values(), key=lambda p: p.PRIORITY, reverse=True)  # Priority-order plugins
        context = {'input': line}

        if not line:
            return  # Do nothing if the line is blank
        for plugin in plugins:
            try:  # Catch and ignore errors within plugin.parse
                if plugin.client_parse(context) is True:
                    break  # Stop if client_parse returns True
            except BaseException as e:
                plugin.__builtins__.print(f'Error {e} caught within "client_parse".')
        self.message_history.trigger_update()

    def add_bubble(self, width, height, column=0, columnspan=1):
        """Creates a 'bubble' instance, adds it to the message feed and returns it.
        Exposed to Plugins."""
        assert isinstance(width, int) and isinstance(height, int), 'Invalid width/height.'
        assert column in (0, 1), 'Invalid column'
        sticky = tk.E if column else tk.W  # Which side to  stick to
        bubble = Bubble(self.message_history, width, height)
        self.message_history.rows += 1
        bubble.grid(row=self.message_history.rows, column=column, padx=2, pady=4, sticky=sticky, columnspan=columnspan)
        self.message_history.trigger_update()
        return bubble

    def add_message(self, message: str, column=0, wraplength=200, columnspan=1):
        bubble = self.add_bubble(0, 0, column, columnspan=columnspan)
        label = tk.Label(master=bubble, text=message, wraplength=wraplength,
                         justify=tk.LEFT if column == 0 else tk.RIGHT, **COLOURS_TEXT)
        bubble.width, bubble.height = max(label.winfo_reqwidth() + 20, 60), max(label.winfo_reqheight() + 20, 22)
        bubble.config(width=bubble.width, height=bubble.height)
        label.place(x=10, y=10)
        bubble.make_background()
        return bubble


class Bubble(tk.Canvas):
    def __init__(self, master, width=50, height=50):
        super().__init__(master)
        self.width, self.height = width, height

    def make_background(self, colour=COLOURS_BUBBLE['bg']):
        """Create the background for the bubble."""
        # NOTE: can make prettier backgrounds with no backwards-comparability issues.
        self.create_rectangle((0, 0, self.width, self.height), fill=colour, outline=colour)


class LoginWindow(tk.Toplevel):
    def __init__(self, tab_man: TabManager):
        super().__init__()
        self.resizable(width=False, height=False)
        self.tab_man = tab_man
        #   Column 0        Column 1  Column 2  Column 3
        #   < - - - - - - - - - -ERROR- - - - - - - - - - >     Row 0
        #   Address:port    [ENTRY]      :      [ENTRY]         Row 1
        #   Username        [ENTRY]                             Row 2
        #   Password        [ENTRY]                             Row 3
        #   Login           Register                            Row 4

        self.address = tk.Entry(self, width=14, **COLOUR_INVERTED)
        self.port = tk.Entry(self, width=5, **COLOUR_INVERTED)
        self.username = tk.Entry(self, width=14, **COLOUR_INVERTED)
        self.password = tk.Entry(self, width=14, show='*', **COLOUR_INVERTED)

        for w in (self.address, self.port, self.username, self.password):
            w.bind('<Return>', self.connect)
        self.address.focus_set()  # Select the address box by default

        tk.Label(self, text='Address:port', **COLOURS_TEXT).grid(row=1, column=0, sticky=tk.W)
        tk.Label(self, text=':', **COLOURS_TEXT).grid(row=1, column=2, sticky=tk.W)
        tk.Label(self, text='Username', **COLOURS_TEXT).grid(row=2, column=0, sticky=tk.W)
        tk.Label(self, text='Password', **COLOURS_TEXT).grid(row=3, column=0, sticky=tk.W)

        tk.Button(self, text='Login', command=self.connect).grid(row=4, column=0, sticky=tk.W)
        tk.Button(self, text='Register', command=self.register).grid(row=4, column=1, sticky=tk.W)

        self.address.grid(row=1, column=1, sticky=tk.W)
        self.port.grid(row=1, column=3, sticky=tk.W)
        self.username.grid(row=2, column=1, sticky=tk.W)
        self.password.grid(row=3, column=1, sticky=tk.W)

    def connect(self, _=None, *, register=False):
        err = find_in_grid(self, 0, 0)
        if err:  # If the error label exists, hide and delete it.
            err.grid_remove()
            err.destroy()
        try:  # Get & verify the address
            address = self.address.get()
            address = [int(i.strip()) for i in address.split('.')]
            assert len(address) == 4
            assert all(0 <= i <= 255 for i in address)
            address = '.'.join([str(int(i)) for i in address])  # Remove trailing zeros, whitespace, etc
        except (AssertionError, ValueError):
            self.address.focus_set()
            tk.Label(self, text='Invalid address', **COLOURS_TEXT).grid(row=0, column=0, columnspan=4, sticky=tk.W)
            return False  # Fail
        try:  # Get & verify the port
            port = int(self.port.get())
            assert 0 <= port <= 65535
        except (AssertionError, ValueError):
            self.port.focus_set()
            tk.Label(self, text='Invalid port', **COLOURS_TEXT).grid(row=0, column=0, columnspan=4, sticky=tk.W)
            return False  # Fail

        username = self.username.get().strip()
        password = self.password.get()
        # Create & add new chat page (as new tab).
        self.tab_man.add_tab(address, ChatPage(self.tab_man, (address, port), username, password, register))
        self.withdraw()  # Close the login window.

    def register(self):
        return self.connect(register=True)
