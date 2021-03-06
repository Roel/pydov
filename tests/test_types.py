"""Module grouping tests for the boring search module."""

import pytest

from pydov.types.boring import Boring
from pydov.types.grondwaterfilter import GrondwaterFilter

type_objects = [Boring,
                GrondwaterFilter]


@pytest.mark.parametrize("objecttype", type_objects)
def test_get_fields_sourcewfs(objecttype):
    """Test the get_fields method for fields of the WFS source.

    Test whether all returned fields have 'wfs' as their 'source'.

    """
    fields = objecttype.get_fields(source=('wfs',))
    for field in fields.values():
        assert field['source'] == 'wfs'


@pytest.mark.parametrize("objecttype", type_objects)
def test_get_fields_sourcexml(objecttype):
    """Test the Boring.get_fields method for fields of the XML source.

    Test whether all returned fields have 'xml' as their 'source'.

    """
    fields = objecttype.get_fields(source=('xml',))
    for field in fields.values():
        assert field['source'] == 'xml'
