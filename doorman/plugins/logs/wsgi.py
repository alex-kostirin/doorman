# -*- coding: utf-8 -*-
import datetime as dt
from json import dumps as json_dump

from flask.logging import wsgi_errors_stream

from doorman.plugins import AbstractLogsPlugin
from doorman.utils import extract_results


class LogWSGIPlugin(AbstractLogsPlugin):
    def __init__(self, config):
        self.fp = wsgi_errors_stream
        self.minimum_severity = config.get('DOORMAN_MINIMUM_OSQUERY_LOG_LEVEL')
        self.log_status = config.get('DOORMAN_LOG_WSGI_PLUGIN_ENABLE_STATUS_LOG', False)
        self.log_result = config.get('DOORMAN_LOG_WSGI_PLUGIN_ENABLE_RESULT_LOG', True)

    @property
    def name(self):
        return "wsgi"

    def handle_status(self, data, **kwargs):
        if self.log_status:
            if self.fp is None:
                return

            host_identifier = kwargs.get('host_identifier', None)
            created = dt.datetime.utcnow().isoformat()

            try:
                for item in data.get('data', []):
                    if int(item['severity']) < self.minimum_severity:
                        continue
                    if 'created' in item:
                        item['created'] = item['created'].isoformat()

                    log_line = json_dump({
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
                    })
                    self.fp.write(log_line + '\r\n')
            finally:
                self.fp.flush()

    def handle_result(self, data, **kwargs):
        if self.log_result:
            if self.fp is None:
                return

            host_identifier = kwargs.get('host_identifier', None)
            created = dt.datetime.utcnow().isoformat()

            try:
                for item in extract_results(data):
                    log_line = json_dump({
                        '@version': 1,
                        '@host_identifier': host_identifier,
                        '@timestamp': item.timestamp.isoformat(),
                        'log_type': 'result',
                        'action': item.action,
                        'columns': item.columns,
                        'name': item.name,
                        'created': created,
                    })
                    self.fp.write(log_line + '\r\n')
            finally:
                self.fp.flush()
