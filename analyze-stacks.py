#!/usr/bin/env python3

import sys
import zign.api

from clickclick import Action
from pierone.api import DockerImage
from pierone.inspect import inspect_files, get_config

token = zign.api.get_token('uid', ['uid'])

stacks = {}

for line in sys.stdin.readlines():
    cols = line.strip().split()
    image = cols[1]
    image = DockerImage.parse(image)

    with Action('Analyzing {}..'.format(image)) as act:
        url = 'https://' + image.registry
        config = get_config(url, image.team, image.artifact, image.tag, token) or {}

        cmd = ' '.join(config.get('config', {}).get('Cmd') or [])
        print(cmd)
        stack = None
        if 'uwsgi' in cmd:
            stack = 'python/uwsgi'
        elif 'python' in cmd:
            stack = 'python'
        elif 'cassandra' in cmd:
            stack = 'cassandra'
        elif 'jenkins' in cmd:
            stack = 'jenkins'

        if stack:
            stacks[str(image)] = stack
            act.ok(stack)
            continue

        members = []
        def callback(i, layer_id, member):
            members.append(member)
            #print(member)
            if member.name.startswith('opt/docker/bin'):
                stacks[str(image)] = 'scala/play'
                return True
            elif member.name.endswith('.jar'):
                stacks[str(image)] = 'java'
                return True
            elif member.name.endswith('.py'):
                stacks[str(image)] = 'python'
                return True
            elif 'node_modules' in member.name:
                stacks[str(image)] = 'node'
                return True
            if len(members) > 4:
                return True

        inspect_files(url, image.team, image.artifact, image.tag, token, callback)
        act.ok(stacks.get(str(image)))
print(stacks)
