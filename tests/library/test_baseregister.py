# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import pytest
from chipsec.library.registers.baseregister import BaseRegister
from chipsec.library.exceptions import UnimplementedAPIError
from tests.test_utils import MockFactory


class TestBaseRegister:
    """Test BaseRegister abstract class functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object."""
        return MockFactory.create_mock_chipsec_cs()

    @pytest.fixture
    def base_register(self, mock_cs):
        """Create BaseRegister instance."""
        return BaseRegister(mock_cs)

    @pytest.mark.unit
    def test_base_register_initialization(self, base_register, mock_cs):
        """Test BaseRegister initialization."""
        assert base_register.cs == mock_cs
        assert hasattr(base_register, 'cs')

    @pytest.mark.unit
    def test_get_def_abstract_method(self, base_register):
        """Test that get_def raises UnimplementedAPIError."""
        with pytest.raises(UnimplementedAPIError, match="get_def\\(\\) is not implemented"):
            base_register.get_def("test_register")

    @pytest.mark.unit
    def test_get_match_abstract_method(self, base_register):
        """Test that get_match raises UnimplementedAPIError."""
        with pytest.raises(UnimplementedAPIError, match="get_match\\(\\) is not implemented"):
            base_register.get_match("test_pattern")

    @pytest.mark.unit
    def test_abstract_methods_with_different_inputs(self, base_register):
        """Test abstract methods with various input types."""
        # Test get_def with different input types
        with pytest.raises(UnimplementedAPIError):
            base_register.get_def(123)

        with pytest.raises(UnimplementedAPIError):
            base_register.get_def(None)

        # Test get_match with different input types
        with pytest.raises(UnimplementedAPIError):
            base_register.get_match(456)

        with pytest.raises(UnimplementedAPIError):
            base_register.get_match(None)


class TestBaseRegisterSubclass:
    """Test that subclasses can properly implement BaseRegister methods."""

    class ConcreteRegister(BaseRegister):
        """Concrete implementation of BaseRegister for testing."""

        def get_def(self, reg_name: str):
            """Concrete implementation of get_def."""
            if reg_name == "existing_register":
                return {"name": reg_name, "value": 0x1234}
            return None

        def get_match(self, pattern: str):
            """Concrete implementation of get_match."""
            if "test" in pattern:
                return [{"name": "test_reg1"}, {"name": "test_reg2"}]
            return []

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object."""
        return MockFactory.create_mock_chipsec_cs()

    @pytest.fixture
    def concrete_register(self, mock_cs):
        """Create ConcreteRegister instance."""
        return self.ConcreteRegister(mock_cs)

    @pytest.mark.unit
    def test_concrete_get_def_existing(self, concrete_register):
        """Test concrete implementation of get_def with existing register."""
        result = concrete_register.get_def("existing_register")
        assert result is not None
        assert result["name"] == "existing_register"
        assert result["value"] == 0x1234

    @pytest.mark.unit
    def test_concrete_get_def_nonexistent(self, concrete_register):
        """Test concrete implementation of get_def with nonexistent register."""
        result = concrete_register.get_def("nonexistent_register")
        assert result is None

    @pytest.mark.unit
    def test_concrete_get_match_with_matches(self, concrete_register):
        """Test concrete implementation of get_match with pattern that matches."""
        result = concrete_register.get_match("test_pattern")
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "test_reg1"
        assert result[1]["name"] == "test_reg2"

    @pytest.mark.unit
    def test_concrete_get_match_no_matches(self, concrete_register):
        """Test concrete implementation of get_match with pattern that doesn't match."""
        result = concrete_register.get_match("no_match_pattern")
        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.unit
    def test_concrete_initialization(self, concrete_register, mock_cs):
        """Test that concrete subclass initializes properly."""
        assert concrete_register.cs == mock_cs
        assert hasattr(concrete_register, 'get_def')
        assert hasattr(concrete_register, 'get_match')


if __name__ == '__main__':
    pytest.main([__file__])
