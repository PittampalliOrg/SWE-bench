from swebench.harness.constants import TestStatus
from swebench.harness.log_parsers.python import parse_log_django


def test_parse_log_django_records_unittest_docstring_header_and_description():
    log = """test_invalid_redirect_repr (httpwrappers.tests.HttpResponseSubclassesTests)
If HttpResponseRedirect raises DisallowedRedirect, its __repr__() ... ok
test_decode (httpwrappers.tests.CookieTests)
Semicolons and commas are decoded. ... ok
test_file_interface (httpwrappers.tests.HttpResponseTests) ... ok
"""

    result = parse_log_django(log, test_spec=None)

    assert (
        result["test_invalid_redirect_repr (httpwrappers.tests.HttpResponseSubclassesTests)"]
        == TestStatus.PASSED.value
    )
    assert (
        result["If HttpResponseRedirect raises DisallowedRedirect, its __repr__()"]
        == TestStatus.PASSED.value
    )
    assert (
        result["test_decode (httpwrappers.tests.CookieTests)"]
        == TestStatus.PASSED.value
    )
    assert result["Semicolons and commas are decoded."] == TestStatus.PASSED.value
    assert (
        result["test_file_interface (httpwrappers.tests.HttpResponseTests)"]
        == TestStatus.PASSED.value
    )

