KNOWN_USERS = {
    "credprov-cdp-controller-proxy_pierone-token": "[CDP]",
    "credprov-cdp-controller-proxy-credentials-cdp_proxy-token": "[CDP]",
}


def get_registry(url: str) -> str:
    """
    Get registry name from url
    """
    return url[8:] if url.startswith('https://') else url


def get_user_friendly_user_name(long_user_name: str) -> str:
    """
    Try to make long user names more user friendly by mapping known long user names to short
    versions.

    IF the user name is not "known" it is return unchanged.
    """
    return KNOWN_USERS.get(long_user_name, long_user_name)
