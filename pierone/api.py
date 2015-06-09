import codecs
import json
import os
from clickclick import Action
import collections
import requests
import yaml
from zign.api import get_named_token, get_existing_token


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


def docker_login(url, realm, name, user, password, token_url=None, use_keyring=True):
    with Action('Getting OAuth2 token "{}"..'.format(name)):
        token = get_named_token(['uid'], realm, name, user, password, url=token_url, use_keyring=use_keyring)
    access_token = token.get('access_token')
    path = os.path.expanduser('~/.dockercfg')
    try:
        with open(path) as fd:
            dockercfg = yaml.safe_load(fd)
    except:
        dockercfg = {}
    basic_auth = codecs.encode('oauth2:{}'.format(access_token).encode('utf-8'), 'base64').strip().decode('utf-8')
    dockercfg[url] = {'auth': basic_auth,
                      'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)


def request(url, path, access_token):
    return requests.get('{}{}'.format(url, path),
                        headers={'Authorization': 'Bearer {}'.format(access_token)}, timeout=10)


def image_exists(token_name: str, image: DockerImage) -> bool:
    token = get_existing_token(token_name)
    if not token:
        raise Unauthorized()

    url = 'https://{}'.format(image.registry)
    path = '/v1/repositories/{team}/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    try:
        r = request(url, path, token['access_token'])
    except:
        return False
    result = r.json()
    return image.tag in result
