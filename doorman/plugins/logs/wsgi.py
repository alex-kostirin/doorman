# -*- coding: utf-8 -*-
import datetime as dt
import time

from flask.logging import wsgi_errors_stream

from doorman.plugins import AbstractLogsPlugin
from doorman.utils import extract_results, quote


class LogWSGIPlugin(AbstractLogsPlugin):
    def __init__(self, config):
        self.fp = wsgi_errors_stream

    @property
    def name(self):
        return "wsgi"

    def join_fields(self, fields):
        parts = []
        for name, val in fields.items():
            if not isinstance(val, str):
                val = str(val)
            parts.append(name + '=' + quote(val))

        return ', '.join(parts)

    def handle_status(self, data, **kwargs):
        if self.fp is None:
            return

        # Write each status log on a different line
        try:
            for item in data.get('data', []):
                fields = {}
                fields.update(kwargs)
                fields.update({
                    'line': item.get('line', ''),
                    'message': item.get('message', ''),
                    'severity': item.get('severity', ''),
                    'filename': item.get('filename', ''),
                    'version': item.get('version'),  # be null
                })

                if 'created' in item:
                    fields['created'] = time.mktime(item['created'].timetuple())
                else:
                    fields['created'] = time.mktime(dt.datetime.utcnow().timetuple())

                self.fp.write(self.join_fields(fields) + '\n')
        finally:
            self.fp.flush()

    def handle_result(self, data, **kwargs):
        if self.fp is None:
            return

        # Process each result individually
        try:
            for item in extract_results(data):
                fields = {}
                fields.update(kwargs)

                if item.timestamp:
                    timestamp = time.mktime(item.timestamp.timetuple())
                else:
                    timestamp = time.mktime(dt.datetime.utcnow.timetuple())

                fields.update(name=item.name, timestamp=timestamp)

                base = self.join_fields(fields)

                # Write each added/removed entry on a different line
                curr_fields = {'result_type': item.action}
                for key, val in item.columns.items():
                    curr_fields['_'.join([item.action, key])] = val

                self.fp.write(base + ', ' + self.join_fields(curr_fields) + '\n')
        finally:
            self.fp.flush()
