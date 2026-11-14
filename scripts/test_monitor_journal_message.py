"""Binary and repeated journal fields must not stall all subsequent records."""
import ast
import json
from pathlib import Path
import unittest

tree=ast.parse((Path(__file__).with_name('monitoring')/'collect_guest.py').read_text())
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='journal_message')
scope={'json':json}
exec(compile(ast.Module(body=[function],type_ignores=[]),'collect_guest.py','exec'),scope)
message=scope['journal_message']


class JournalMessageTests(unittest.TestCase):
    def test_binary_message_is_searchable_and_original_bytes_are_preserved(self):
        raw=list(b'audit\x00\xff record')
        text,data=message(raw)
        self.assertIn('audit',text)
        self.assertEqual(data['journal_message_raw'],raw)
        self.assertIn('\ufffd',text)

    def test_repeated_text_fields_preserve_all_values(self):
        raw=['first','second']
        self.assertEqual(message(raw),('first\nsecond',{'journal_message_raw':raw}))

    def test_string_and_unexpected_value_types_do_not_crash(self):
        self.assertEqual(message('normal'),('normal',{}))
        for value in [None,42,[999],['text',1],{'unusual':True}]:
            text,data=message(value)
            self.assertIsInstance(text,str)
            self.assertEqual(data['journal_message_raw'],value)


if __name__=='__main__':unittest.main()
