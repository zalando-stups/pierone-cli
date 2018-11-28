from click import ClickException

from .ui import format_full_image_name
from .types import DockerImage


class PieroneException(ClickException):
    '''Thrown when something does not go as expected'''


class APIException(PieroneException):
    """
    Exception when accessing the API.

    ``action`` is a format string, and everything in ``kwargs`` is used to format it. If there's
    an ``image`` key in ``kwargs`` it's value is formated with ``format_full_image_name``.
    """
    def __init__(self, action: str, **kwargs):
        if "image" in kwargs:
            kwargs["image"] = format_full_image_name(kwargs["image"])
        formatted_action = action.format_map(kwargs)
        self.message = "You can't {}.".format(formatted_action)


class ArtifactNotFound(APIException):
    """
    Exception When Image was Not Found.
    """
    def __init__(self, image: DockerImage):
        self.image = image
        self.message = "{} doesn't exist.".format(format_full_image_name(self.image))


class Forbidden(APIException):
    """
    Exception When Pierone Returns a 403.
    """


class Conflict(APIException):
    """
    Exception When Pierone Returns a 409.
    """


class UnprocessableEntity(APIException):
    """
    Exception When Pierone Returns a 422.
    """
