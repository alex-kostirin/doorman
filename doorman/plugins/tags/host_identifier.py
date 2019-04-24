# -*- coding: utf-8 -*-
import re

from doorman.plugins import AbstractTagsPlugin


class HostIdentifierTagsPlugin(AbstractTagsPlugin):
    def __init__(self, config):
        self._tags_regex = re.compile(config.get('DOORMAN_ENROL_TAG_HOST_IDENTIFIER_REGEX', r'(?P<tag>.*)'))

    def handle_request(self, request, **kwargs):
        host_identifier = request.get('host_identifier')
        match = self._tags_regex.match(host_identifier)
        if match:
            group_dict = match.groupdict()
            if 'tag' in group_dict:
                return [group_dict['tag']]
        return []
