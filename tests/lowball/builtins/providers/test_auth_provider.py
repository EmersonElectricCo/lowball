import pytest

from lowball.builtins.providers.auth_provider import DefaultAuthProvider, DefaultAuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import InvalidCredentialsException, MalformedAuthPackageException


class TestDefaultAuthProviderAuthPackage:
    @pytest.mark.parametrize("username, password", [
        (1, "userpassword"),
        ("user", 1)
    ])
    def test_init_raises_exception_when_bad_values_passed_in(self, username, password):
        with pytest.raises(TypeError):
            DefaultAuthPackage(username=username, password=password)

    def test_setting_username_to_non_string_raises_exception(self, default_auth_package, not_string):
        with pytest.raises(TypeError):
            default_auth_package.username = not_string

    def test_setting_password_to_non_string_raises_exception(self, default_auth_package, not_string):
        with pytest.raises(TypeError):
            default_auth_package.password = not_string


class TestDefaultAuthProvider:
    @pytest.mark.parametrize("username, password", [
        (1, "userpassword"),
        ("user", 1)
    ])
    def test_init_raises_exception_when_bad_values_passed_in(self, username, password):
        with pytest.raises(TypeError):
            DefaultAuthProvider(username=username, password=password)

    def test_setting_username_and_password_after_init_raises_exception(self):
        test_auth_provider = DefaultAuthProvider(username="admin", password="nimda")

        with pytest.raises(PermissionError):
            test_auth_provider.username = "somethingelse"

        with pytest.raises(PermissionError):
            test_auth_provider.password = "somethingelse"

    def test_auth_package_class_property_returns_expected_class(self, default_auth_provider):
        assert default_auth_provider.auth_package_class == DefaultAuthPackage

    def test_authenticate_returns_proper_data(self, default_auth_provider, default_auth_package):
        client_data = default_auth_provider.authenticate(default_auth_package)

        assert isinstance(client_data, ClientData)
        assert client_data.client_id == default_auth_provider.username
        assert client_data.roles == ["admin"]

    def test_passing_malformed_auth_package_to_authenticate_raises_exception(self, default_auth_provider,
                                                                             malformed_auth_package):
        with pytest.raises(MalformedAuthPackageException):
            default_auth_provider.authenticate(malformed_auth_package)

    def test_passing_invalid_auth_package_to_authenticate_raises_exception(self, default_auth_provider,
                                                                           invalid_auth_package):
        with pytest.raises(InvalidCredentialsException):
            default_auth_provider.authenticate(invalid_auth_package)

    def test_initialized_returns_true(self, default_auth_provider):
        assert default_auth_provider.initialized

    def test_get_client_returns_expected_client(self, default_auth_provider, get_client_expected_outcomes):

        client_id, expected_client_data = get_client_expected_outcomes

        client_data = default_auth_provider.get_client(client_id)

        if isinstance(expected_client_data, ClientData):
            assert isinstance(client_data, ClientData)
            assert client_data.to_dict() == expected_client_data.to_dict()
        else:
            assert client_data is None

