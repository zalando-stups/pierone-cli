def get_registry(url: str) -> str:
    """
    Get registry name from url
    """
    return url[8:] if url.startswith('https://') else url
