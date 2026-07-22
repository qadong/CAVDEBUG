import inspect


def filter_kwargs(kwargs, func):
    """
    Filter the kwargs to only include the ones that are required by the function.
    """
    signature = inspect.signature(func)
    filtered = {k: v for k, v in kwargs.items() if k in signature.parameters}

    return filtered
