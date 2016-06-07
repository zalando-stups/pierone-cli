import codecs
import collections
import datetime
import json
import os
import re
import time

import requests
from clickclick import Action
from zign.api import get_named_token

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


def docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
    with Action('Getting OAuth2 token "{}"..'.format(name)) as action:
        try:
            token = get_named_token(['uid', 'application.write'],
                                    realm, name, user, password, url=token_url,
                                    use_keyring=use_keyring, prompt=prompt)
        except requests.HTTPError as error:
            status_code = error.response.status_code
            if 400 <= status_code < 500:
                action.fatal_error(
                    'Authentication Failed ({} Client Error). Check your configuration.'.format(status_code))
            if 500 <= status_code < 600:
                action.fatal_error('Authentication Failed ({} Server Error).'.format(status_code))
            else:
                action.fatal_error('Authentication Failed ({})'.format(status_code))
    access_token = token.get('access_token')
    docker_login_with_token(url, access_token)


def docker_login_with_token(url, access_token):
    '''Configure docker with existing OAuth2 access token'''

    path = os.path.expanduser('~/.docker/config.json')
    try:
        with open(path) as fd:
            dockercfg = json.load(fd)
    except:
        dockercfg = {}
    basic_auth = codecs.encode('oauth2:{}'.format(access_token).encode('utf-8'), 'base64').strip().decode('utf-8')
    if 'auths' not in dockercfg:
        dockercfg['auths'] = {}
    dockercfg['auths'][url] = {'auth': basic_auth,
                               'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)


def request(url, path, access_token: str=None) -> requests.Response:
    headers = {}
    if access_token:
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
    return session.get('{}{}'.format(url, path), headers=headers, timeout=10)


def image_exists(image: DockerImage, token: str=None) -> bool:
    url = 'https://{}'.format(image.registry)
    path = '/v1/repositories/{team}/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    try:
        r = request(url, path, token)
    except:
        return False
    result = r.json()
    return image.tag in result


def get_image_tag(image: DockerImage, token: str=None) -> dict:
    tags = get_image_tags(image, token) or []
    for entry in tags:
        if entry['tag'] == image.tag:
            return entry
    return None


def get_image_tags(image: DockerImage, token: str=None) -> list:
    url = 'https://{}'.format(image.registry)
    path = '/teams/{team}/artifacts/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    response = request(url, path, token)
    if response.status_code == 404:
        return None

    return [parse_pierone_artifact_dict(entry, image.team, image.artifact)
            for entry in response.json()]


def get_latest_tag(image: DockerImage, token: str=None) -> bool:
    url = 'https://{}'.format(image.registry)
    path = '/teams/{team}/artifacts/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    try:
        r = request(url, path, token)
        r.raise_for_status()
    except:
        return None
    result = r.json()
    if result:
        return sorted(result, key=lambda x: x['created'])[-1]['name']
    else:
        return None


def parse_pierone_artifact_dict(original_payload_from_api, team, artifact) -> dict:
    return {'team': team,
            'artifact': artifact,
            'tag': original_payload_from_api['name'],
            'created_by': original_payload_from_api['created_by'],
            'created_time': parse_time(original_payload_from_api['created']),
            'severity_fix_available': parse_severity(
                original_payload_from_api.get('severity_fix_available'),
                original_payload_from_api.get('clair_id', False)),
            'severity_no_fix_available': parse_severity(
                original_payload_from_api.get('severity_no_fix_available'),
                original_payload_from_api.get('clair_id', False))}


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


def parse_severity(value, clair_id_exists) -> str:
    '''Parse severity values to displayable values'''
    if value is None and clair_id_exists:
        return 'NOT_PROCESSED_YET'
    elif value is None:
        return 'TOO_OLD'

    value = re.sub('^clair:', '', value)
    value = re.sub('(?P<upper_letter>(?<=[a-z])[A-Z])', '_\g<upper_letter>', value)

    return value.upper()
