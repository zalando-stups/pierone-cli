import collections


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
