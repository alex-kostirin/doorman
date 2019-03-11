# -*- coding: utf-8 -*-
import datetime as dt
from json import dump as json_dump

from flask.logging import wsgi_errors_stream

from doorman.plugins import AbstractLogsPlugin
from doorman.utils import extract_results


class LogWSGIPlugin(AbstractLogsPlugin):
    def __init__(self, config):
        self.minimum_severity = config.get('DOORMAN_MINIMUM_OSQUERY_LOG_LEVEL')
        self.fp = wsgi_errors_stream

    @property
    def name(self):
        return "wsgi"

    def handle_status(self, data, **kwargs):
        if self.fp is None:
            return

        fp = self.fp
        minimum_severity = self.minimum_severity

        host_identifier = kwargs.get('host_identifier')
        created = dt.datetime.utcnow().isoformat()

        try:
            for item in data.get('data', []):
                if int(item['severity']) < minimum_severity:
                    continue

                if 'created' in item:
                    item['created'] = item['created'].isoformat()

                json_dump({
                    '@version': 1,
                    '@host_identifier': host_identifier,
                    '@timestamp': item.get('created', created),
                    '@message': item.get('message', ''),
                    'log_type': 'status',
                    'line': item.get('line', ''),
                    'message': item.get('message', ''),
                    'severity': item.get('severity', ''),
                    'filename': item.get('filename', ''),
                    'osquery_version': item.get('version'),  # be null
                    'created': created,
                }, fp)
                fp.write('\r\n')
        finally:
            fp.flush()

    def handle_result(self, data, **kwargs):
        if self.fp is None:
            return

        fp = self.fp

        host_identifier = kwargs.get('host_identifier')
        created = dt.datetime.utcnow().isoformat()

        try:
            for item in extract_results(data):
                json_dump({
                    '@version': 1,
                    '@host_identifier': host_identifier,
                    '@timestamp': item.timestamp.isoformat(),
                    'log_type': 'result',
                    'action': item.action,
                    'columns': item.columns,
                    'name': item.name,
                    'created': created,
                }, fp)
                fp.write('\r\n')
        finally:
            fp.flush()
