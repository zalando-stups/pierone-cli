from click import ClickException


class PieroneException(ClickException):
    '''Thrown when something does not go as expected'''


class APIException(PieroneException):
    """
    Exception when accessing the API
    """


class ImageNotFound(APIException):
    """
    Exception When Image was Not Found.
    """
    def __init__(self, image: 'DockerImage'):
        self.image = image
        self.message = "'{}' doesn't exist.".format(self.image)