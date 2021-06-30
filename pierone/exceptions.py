from typing import Optional
from click import ClickException
import requests
import json

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
        self.response: Optional[requests.Response] = None
        if "image" in kwargs:
            kwargs["image"] = format_full_image_name(kwargs["image"])
        self.action = action
        self.kwargs = kwargs

    @property
    def message(self) -> str:
        formatted_action = self.action.format_map(self.kwargs)

        details = None
        if self.response is not None:
            try:
                problem = self.response.json()
                details = problem["detail"]
            except (KeyError, json.JSONDecodeError):
                pass

        if details is not None:
            return "You can't {}: {}.".format(formatted_action, details)
        else:
            return "You can't {}.".format(formatted_action)


class ArtifactNotFound(APIException):
    """
    Exception When Image was Not Found.
    """
    def __init__(self, image: DockerImage):
        self.image = image

    @property
    def message(self):
        return "{} doesn't exist.".format(format_full_image_name(self.image))


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


class MarkProductionReadyRejected(APIException):
    """
    Exception when Docker-Meta refuses a mark production ready request (400)
    """
