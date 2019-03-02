PRIORITY = 1  # Call before core.py
MODE = INTERFACE.BOTH  # This plugin will run on both the server and client.
ENCODING = Constants.ENCODING

banned_words = ("foo", "bar", "fibonacci")  # Tuple of banned words.
banned_words = sorted(banned_words, key=len, reverse=True)  # Largest words first


def client_parse(context: dict) -> (True, False, None):
    """
    For every banned word in the user's input, replace all but the first character with '*'.
    :param context: A dictionary containing all relevant information. Breakdown below.
    :return: True       if the data has been handled (no further plugins' client_parse called)
    :return: False/None if the data has NOT been handled (call the next plugin with same context object)
    ------- 'context' breakdown -------
    'input'     : The user-supplied string.
    """
    _input: str = context['input']
    for word in banned_words:
        _input = _input.replace(word, word[0] + "*" * (len(word) - 1))
    context['input'] = _input
    return False  # This call never handles data itself.
