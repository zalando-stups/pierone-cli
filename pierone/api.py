import base64
import codecs
import collections
import datetime
import json
import os
import time

import requests
from clickclick import Action
from zign.api import get_token

KNOWN_USERS = {
    "credprov-cdp-controller-proxy_pierone-token": "[CDP]",
    "credprov-cdp-controller-proxy-credentials-cdp_proxy-token": "[CDP]"
}

adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
session = requests.Session()
session.mount('http://', adapter)
session.mount('https://', adapter)


class Unauthorized(Exception):
    def __str__(self):
        return 'Unauthorized: token missing or invalid'


class DockerImage(collections.namedtuple('DockerImage', 'registry team artifact tag')):
    @classmethod
    def parse(cls, image: str):
        '''
        >>> DockerImage.parse('x')
        Traceback (most recent call last):
        ValueError: Invalid docker image "x" (format must be [REGISTRY/]TEAM/ARTIFACT:TAG)
        >>> DockerImage.parse('foo/bar')
        DockerImage(registry=None, team='foo', artifact='bar', tag='')
        >>> DockerImage.parse('registry/foo/bar:1.9')
        DockerImage(registry='registry', team='foo', artifact='bar', tag='1.9')
        '''
        parts = image.split('/')
        if len(parts) == 3:
            registry = parts[0]
        elif len(parts) < 2:
            raise ValueError('Invalid docker image "{}" (format must be [REGISTRY/]TEAM/ARTIFACT:TAG)'.format(image))
        else:
            registry = None
        team = parts[-2]
        artifact, sep, tag = parts[-1].partition(':')
        return DockerImage(registry=registry, team=team, artifact=artifact, tag=tag)

    def __str__(self):
        '''
        >>> str(DockerImage(registry='registry', team='foo', artifact='bar', tag='1.9'))
        'registry/foo/bar:1.9'
        '''
        return '{}/{}/{}:{}'.format(*tuple(self))


# all the other paramaters are deprecated, but still here for compatibility
def docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
    with Action('Getting OAuth2 token "{}"..'.format(name)):
        access_token = get_token(name, ['uid', 'application.write'])
    docker_login_with_token(url, access_token)


def docker_login_with_token(url, access_token):
    '''Configure docker with existing OAuth2 access token'''

    path = os.path.expanduser('~/.docker/config.json')
    try:
        with open(path) as fd:
            dockercfg = json.load(fd)
    except Exception:
        dockercfg = {}
    basic_auth = codecs.encode('oauth2:{}'.format(access_token).encode('utf-8'), 'base64').strip().decode('utf-8')
    if 'auths' not in dockercfg:
        dockercfg['auths'] = {}
    if 'credsStore' in dockercfg:
        del dockercfg['credsStore']

    dockercfg['auths'][url] = {'auth': basic_auth,
                               'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)


def iid_auth():
    '''Return AWS instance identity document encoded as a Pier One atuh token'''
    pkcs7 = request('http://169.254.169.254', '/latest/dynamic/instance-identity/pkcs7')
    basic_auth = 'instance-identity-document:{}'.format(pkcs7.text).encode('utf-8')
    return base64.b64encode(basic_auth).decode('utf-8')


def docker_login_with_iid(url):
    '''Configure docker with IID auth'''

    path = os.path.expanduser('~/.docker/config.json')
    try:
        with open(path) as fd:
            dockercfg = json.load(fd)
    except Exception:
        dockercfg = {}
    if 'auths' not in dockercfg:
        dockercfg['auths'] = {}
    dockercfg['auths'][url] = {'auth': iid_auth(),
                               'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)


def request(url, path, access_token: str = None,
            not_found_is_none: bool = False, method: str = 'GET', data=None) -> requests.Response:
    if access_token:
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
    else:
        headers = {}

    r = session.request(method, '{}{}'.format(url, path), headers=headers, data=data, timeout=10)

    if not_found_is_none and r.status_code == 404:
        return None
    else:
        r.raise_for_status()
        return r


def image_exists(image: DockerImage, token: str = None) -> bool:
    url = 'https://{}'.format(image.registry)
    path = '/v1/repositories/{team}/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    r = request(url, path, token, True)
    if r is None:
        return False
    result = r.json()
    return image.tag in result


def get_image_tag(image: DockerImage, token: str = None) -> dict:
    tags = get_image_tags(image, token) or []
    for entry in tags:
        if entry['tag'] == image.tag:
            return entry
    return None


def get_image_tags(image: DockerImage, token: str = None) -> list:
    url = 'https://{}'.format(image.registry)
    path = '/teams/{team}/artifacts/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    response = request(url, path, token, True)
    if response is None:
        return None
    return [parse_pierone_artifact_dict(entry, image.team, image.artifact)
            for entry in response.json()]


def get_tag_info(image: DockerImage, token: str = None) -> list:
    """
    Gets detailed tag information
    """
    url = "https://{}".format(image.registry)
    path = "/teams/{}/artifacts/{}/tags/{}".format(image.team, image.artifact, image.tag)

    response = request(url, path, token, False)
    return response.json()


def get_latest_tag(image: DockerImage, token: str = None) -> bool:
    url = 'https://{}'.format(image.registry)
    path = '/teams/{team}/artifacts/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    r = request(url, path, token, True)
    if r is None:
        return None
    result = r.json()
    if result:
        return sorted(result, key=lambda x: x['created'])[-1]['name']
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
        "status_reason_summary": "Not Processed",
        "trusted": None
    }
    parsed_dict.update(original_payload_from_api)
    parsed_dict['team'] = team
    parsed_dict['artifact'] = artifact
    parsed_dict['tag'] = original_payload_from_api['name']
    created_by = original_payload_from_api['created_by']
    parsed_dict['created_by'] = KNOWN_USERS.get(created_by, created_by)
    parsed_dict['created_time'] = parse_time(original_payload_from_api['created'])
    status_received_at = original_payload_from_api.get('status_received_at')
    parsed_dict['status_time'] = parse_time(status_received_at) if status_received_at else 'N/A'
    return parsed_dict


def parse_time(s: str) -> float:
    '''
    >>> parse_time('foo')
    time data 'foo' does not match format '%Y-%m-%dT%H:%M:%S.%fZ'
    >>> parse_time('2015-04-14T19:09:01.000Z') > 0
    True
    '''
    try:
        utc = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ')
        ts = time.time()
        utc_offset = datetime.datetime.fromtimestamp(ts) - datetime.datetime.utcfromtimestamp(ts)
        local = utc + utc_offset
        return local.timestamp()
    except Exception as e:
        print(e)
        return None
