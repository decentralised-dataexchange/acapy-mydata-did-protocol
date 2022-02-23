from asynctest import TestCase as AsyncTestCase

from ..util import str_to_bool

class TestDataAgreementV1Record(AsyncTestCase):

    def test_str_to_bool(self):

        assert str_to_bool("true") == True
        assert str_to_bool("t") == True
        assert str_to_bool("1") == True
        assert str_to_bool("true") == True

        assert str_to_bool("false") == False
        assert str_to_bool("f") == False
        assert str_to_bool("0") == False
        assert str_to_bool("false") == False

        with self.assertRaises(ValueError) as ctx:
            str_to_bool("")
        
        self.assertTrue("Cannot convert string to boolean" in str(ctx.exception))