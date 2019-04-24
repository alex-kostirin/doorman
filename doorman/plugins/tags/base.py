# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod

from doorman.compat import with_metaclass


class AbstractTagsPlugin(with_metaclass(ABCMeta)):

    @abstractmethod
    def handle_request(self, request, **kwargs):
        pass
