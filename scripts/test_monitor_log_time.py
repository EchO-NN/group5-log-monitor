"""Real web access formats must retain their original timezone and event time."""
import ast
import datetime as dt
from pathlib import Path
import re
import unittest

tree=ast.parse((Path(__file__).with_name('monitoring')/'collect_guest.py').read_text())
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='parsed_time')
scope={'dt':dt,'re':re,'UTC':dt.timezone.utc}
exec(compile(ast.Module(body=[function],type_ignores=[]),'collect_guest.py','exec'),scope)


class LogTimeTests(unittest.TestCase):
    def test_nginx_combined_time_has_correct_utc_instant(self):
        line='192.168.33.15 - - [03/Nov/2026:14:30:12 +0800] "POST /login HTTP/1.1" 200 12'
        self.assertEqual(scope['parsed_time'](line),'2026-11-03T06:30:12+00:00')

    def test_missing_or_invalid_event_time_is_not_replaced_with_now(self):
        for line in ['POST /login','[33/Nov/2026:14:30:12 +0800] "GET /"']:
            self.assertIsNone(scope['parsed_time'](line))


if __name__=='__main__':unittest.main()
