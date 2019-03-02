import tkinter as tk

PRIORITY = 2  # Should be the first client_parse called
MODE = INTERFACE.BOTH  # This plugin will run on both the server and client.
ENCODING = Constants.ENCODING
add_bubble = INTERFACE.add_bubble


def client_parse(context: dict) -> (True, False, None):
    _input: str = context['input']
    if _input == 'TestBubble':
        INTERFACE.send()  # Send empty message to other clients
        add_test_bubble()
        return True  # Handled the data
    return False  # Done nothing


def client_handle(context: dict) -> None:
    assert len(context['content']) == 0, 'Expected to receive zero elements.'
    add_test_bubble()


def server_handle(context: dict) -> None:
    """Blindly rebroadcast anything received."""
    INTERFACE.broadcast(context['user'], *context['content'], blacklist=(context['user'],))


def add_test_bubble():
    def button_callback():
        """Swaps the button's foreground and background colours"""
        config = btn.config()
        btn.config(fg=config['background'][-1], bg=config['foreground'][-1])

    bubble = add_bubble(100, 30)
    btn = tk.Button(bubble, text='Swap', command=button_callback)
    btn.pack()
