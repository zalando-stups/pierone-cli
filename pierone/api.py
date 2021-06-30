from typing import Optional
import base64
import codecs
import datetime
import json
import os
import time
from urllib.parse import urlparse
import warnings

import requests
from clickclick import Action
from zign.api import get_token

from .exceptions import (
    ArtifactNotFound,
    Forbidden,
    Conflict,
    UnprocessableEntity,
    APIException,
    MarkProductionReadyRejected,
)
from .types import DockerImage
from .utils import get_user_friendly_user_name

adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
session = requests.Session()
session.mount("http://", adapter)
session.mount("https://", adapter)


class Service:
    def __init__(self, url: str):
        self.url = url if url.startswith("https://") else "https://" + url
        self._access_token = get_token("pierone", ["uid"])
        self.session = requests.Session()
        self.session.headers["Authorization"] = "Bearer {}".format(self._access_token)

    @staticmethod
    def _handle_exceptions(http_error: requests.HTTPError, exceptions: Optional[dict]):
        """
        Handles HTTP exceptions by looking for ``http_error``'s status code in ``exceptions`` and
        raising the value, if any, or re-raising the original exception if there isn't a custom one.
        """
        exceptions = exceptions or {}
        exception: APIException = exceptions.get(http_error.response.status_code)
        if exception:
            exception.response = http_error.response
            raise exception
        else:
            raise http_error

    def _request(
        self, method: str, path: str, exceptions: Optional[dict] = None, *args, **kwargs
    ) -> requests.Response:
        url = self.url + path
        response = self.session.request(method, url, *args, **kwargs)
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            self._handle_exceptions(error, exceptions)
        return response

    def _get(
        self, path, exceptions: Optional[dict] = None, *args, **kwargs
    ) -> requests.Response:
        """
        GETs things from Pierone.

        ``path`` will be prepended with the registry's base url.
        ``exceptions`` is a map of status of code and exceptions to be raised if they happen.
        Everything else is passed to the ``session.get`` request.
        """
        return self._request("GET", path, *args, exceptions=exceptions, **kwargs)

    def _put(
        self, path, json=None, exceptions: Optional[dict] = None, *args, **kwargs
    ) -> requests.Response:
        """
        PUTs things to Pierone and Docker Meta.

        ``path`` will be prepended with the registry's base url.
        ``exceptions`` is a map of status of code and exceptions to be raised if they happen.
        Everything else is passed to the ``session.put`` request.
        """
        return self._request(
            "PUT", path, *args, json=json, exceptions=exceptions, **kwargs
        )

    def _post(
        self, path, json=None, exceptions: Optional[dict] = None, *args, **kwargs
    ) -> requests.Response:
        """
        POSTs things to Pierone.

        ``path`` will be prepended with the registry's base url.
        ``exceptions`` is a map of status of code and exceptions to be raised if they happen.
        Everything else is passed to the ``session.post`` request.
        """
        return self._request(
            "POST", path, *args, json=json, exceptions=exceptions, **kwargs
        )


class DockerMeta(Service):
    def __init__(self):
        super().__init__("https://docker-meta.stups.zalan.do")

    def mark_production_ready(
        self, image: DockerImage, incident_id: str, reason: Optional[str] = None
    ):
        path = "/image-metadata/{}/{}/{}:{}".format(
            image.registry, image.team, image.artifact, image.tag
        )
        payload = {
            "compliance": {
                "user": {
                    "incident": incident_id,
                    "reason": reason,
                    "status": "production_ready",
                }
            }
        }
        self._put(
            path,
            json=payload,
            exceptions={
                400: MarkProductionReadyRejected(
                    "mark {image} as production ready", image=image
                ),
                404: ArtifactNotFound(image),
            },
        )

    def get_image_metadata(self, image: DockerImage) -> dict:
        """
        Gets all the image's metadata that Pierone-CLI uses.
        """
        path = "/image-metadata/{}/{}/{}:{}".format(
            image.registry, image.team, image.artifact, image.tag
        )
        response = self._get(
            path,
            params={"embed": "(base-image,compliance,ci)"},
            exceptions={
                403: Forbidden("get {image}'s metadata", image=image),
                404: ArtifactNotFound(image),
            },
        )
        return response.json()


class PierOne(Service):
    def get_tag_info(self, image: DockerImage) -> list:
        """
        Gets detailed tag information
        """
        path = "/teams/{}/artifacts/{}/tags/{}".format(
            image.team, image.artifact, image.tag
        )

        response = self._get(
            path,
            exceptions={
                403: Forbidden("get {image}'s detailed information", image=image),
                404: ArtifactNotFound(image),
            },
        )
        tag_info = response.json()
        created_by = tag_info["created_by"]
        tag_info["created_by"] = get_user_friendly_user_name(created_by)
        return tag_info

    def get_image_tags(self, image: DockerImage) -> list:
        """
        Gets all tags for an image.
        """
        path = "/teams/{team}/artifacts/{artifact}/tags".format(
            team=image.team, artifact=image.artifact
        )

        response = self._get(
            path,
            exceptions={
                403: Forbidden("get all {image}'s tags", image=image),
                404: ArtifactNotFound(image),
            },
        )
        return [
            parse_pierone_artifact_dict(entry, image.team, image.artifact)
            for entry in response.json()
        ]

    def get_scm_source(self, image: DockerImage) -> dict:
        """
        GETs ``image``s scm_source
        """
        path = "/teams/{}/artifacts/{}/tags/{}/scm-source".format(
            image.team, image.artifact, image.tag
        )
        response = self._get(
            path,
            exceptions={
                403: Forbidden("get {image}'s scm source", image=image),
                404: ArtifactNotFound(image),
            },
        )
        return response.json()

    def get_artifacts(self, team: str):
        """
        GETs all ``teams``'s artifacts.
        """
        response = self._get("/teams/{}/artifacts".format(team))
        return response.json()

    def mark_production_ready(self, image: DockerImage, incident_id: str):
        path = "/teams/{}/artifacts/{}/tags/{}/production-ready".format(
            image.team, image.artifact, image.tag
        )
        payload = {"incident_id": incident_id}
        self._post(
            path,
            json=payload,
            exceptions={
                403: Forbidden("mark {image} as production ready", image=image),
                404: ArtifactNotFound(image),
                409: Conflict(
                    "mark {image} as production ready because the flag is already set",
                    image=image,
                ),
                422: UnprocessableEntity(
                    "mark {image} as production ready because it doesn't have a SCM Source",
                    image=image,
                ),
            },
        )


def load_docker_config():
    path = os.path.expanduser("~/.docker/config.json")
    try:
        with open(path) as fd:
            return json.load(fd)
    except Exception:
        return {}


def store_docker_config(config):
    path = os.path.expanduser("~/.docker/config.json")
    with Action("Storing Docker client configuration in {}..".format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fd:
            json.dump(config, fd, indent=2)


def docker_login_with_credhelper(url):
    dockercfg = load_docker_config()

    dockercfg["auths"] = dockercfg.get("auths", {})
    try:
        del dockercfg["auths"][url]
    except KeyError:
        pass

    dockercfg["credHelpers"] = dockercfg.get("credHelpers", {})
    hostname = urlparse(url).hostname
    dockercfg["credHelpers"][hostname] = "pierone"

    store_docker_config(dockercfg)


# all the other paramaters are deprecated, but still here for compatibility
def docker_login(
    url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False
):
    warnings.warn("deprecated", DeprecationWarning)
    with Action('Getting OAuth2 token "{}"..'.format(name)):
        access_token = get_token(name, ["uid", "application.write"])
    docker_login_with_token(url, access_token)


def docker_login_with_token(url, access_token):
    """Configure docker with existing OAuth2 access token"""
    warnings.warn("deprecated", DeprecationWarning)
    dockercfg = load_docker_config()
    basic_auth = (
        codecs.encode("oauth2:{}".format(access_token).encode("utf-8"), "base64")
        .strip()
        .decode("utf-8")
    )

    dockercfg["auths"] = dockercfg.get("auths", {})
    dockercfg["auths"][url] = {
        "auth": basic_auth,
        "email": "no-mail-required@example.org",
    }

    # Explicitly disable credential helpers for the host in URL
    dockercfg["credHelpers"] = dockercfg.get("credHelpers", {})
    hostname = urlparse(url).hostname
    dockercfg["credHelpers"][hostname] = ""

    store_docker_config(dockercfg)


def iid_auth():
    """Return AWS instance identity document encoded as a Pier One atuh token"""
    pkcs7 = request("http://169.254.169.254", "/latest/dynamic/instance-identity/pkcs7")
    basic_auth = "instance-identity-document:{}".format(pkcs7.text).encode("utf-8")
    return base64.b64encode(basic_auth).decode("utf-8")


def docker_login_with_iid(url):
    """Configure docker with IID auth"""
    dockercfg = load_docker_config()

    if "auths" not in dockercfg:
        dockercfg["auths"] = {}
    dockercfg["auths"][url] = {
        "auth": iid_auth(),
        "email": "no-mail-required@example.org",
    }

    store_docker_config(dockercfg)


def request(
    url,
    path,
    access_token: str = None,
    not_found_is_none: bool = False,
    method: str = "GET",
    data=None,
) -> Optional[requests.Response]:
    if access_token:
        headers = {"Authorization": "Bearer {}".format(access_token)}
    else:
        headers = {}

    r = session.request(
        method, "{}{}".format(url, path), headers=headers, data=data, timeout=10
    )

    if not_found_is_none and r.status_code == 404:
        return None
    else:
        r.raise_for_status()
        return r


def image_exists(image: DockerImage, token: str = None) -> bool:
    url = "https://{}".format(image.registry)
    path = "/v1/repositories/{team}/{artifact}/tags".format(
        team=image.team, artifact=image.artifact
    )

    r = request(url, path, token, True)
    if r is None:
        return False
    result = r.json()
    return image.tag in result


def get_latest_tag(image: DockerImage, token: str = None) -> Optional[bool]:
    url = "https://{}".format(image.registry)
    path = "/teams/{team}/artifacts/{artifact}/tags".format(
        team=image.team, artifact=image.artifact
    )

    r = request(url, path, token, True)
    if r is None:
        return None
    result = r.json()
    if result:
        return sorted(result, key=lambda x: x["created"])[-1]["name"]
    else:
        return None


def parse_pierone_artifact_dict(original_payload_from_api, team, artifact) -> dict:
    """
    Enhance pierone artifact dict by:
    - Adding defaults
    - Adding team and artifact name
    - Adding useful aliases
    - Parsing times
    - Shortening know robot user's name (e.g. CDP)
    """
    # The dict is pre-populated with defaults
    parsed_dict = {
        "status": "Not Processed",
        "status_reason": "Not Processed",
    }
    parsed_dict.update(original_payload_from_api)
    parsed_dict["team"] = team
    parsed_dict["artifact"] = artifact
    parsed_dict["tag"] = original_payload_from_api["name"]
    created_by = original_payload_from_api["created_by"]
    parsed_dict["created_by"] = get_user_friendly_user_name(created_by)
    parsed_dict["created_time"] = parse_time(original_payload_from_api["created"])
    status_received_at = original_payload_from_api.get("status_received_at")
    parsed_dict["status_time"] = (
        parse_time(status_received_at) if status_received_at else "N/A"
    )
    return parsed_dict


def parse_time(s: str) -> Optional[float]:
    """
    >>> parse_time('foo')
    time data 'foo' does not match format '%Y-%m-%dT%H:%M:%S.%fZ'
    >>> parse_time('2015-04-14T19:09:01.000Z') > 0
    True
    """
    try:
        utc = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
        ts = time.time()
        utc_offset = datetime.datetime.fromtimestamp(
            ts
        ) - datetime.datetime.utcfromtimestamp(ts)
        local = utc + utc_offset
        return local.timestamp()
    except Exception as e:
        print(e)
        return None
