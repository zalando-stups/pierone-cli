from click import ClickException

from .ui import format_full_image_name
from .types import DockerImage


class PieroneException(ClickException):
    '''Thrown when something does not go as expected'''


class APIException(PieroneException):
    """
    Exception when accessing the API
    """


class ArtifactNotFound(APIException):
    """
    Exception When Image was Not Found.
    """
    def __init__(self, image: DockerImage):
        self.image = image
        self.message = "{} doesn't exist.".format(format_full_image_name(self.image))
