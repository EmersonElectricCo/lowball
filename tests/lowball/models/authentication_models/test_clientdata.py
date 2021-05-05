import pytest

from lowball.models.authentication_models import ClientData


class TestClientData:
    # INIT TESTS
    def test_passing_non_string_for_username_at_init_raises_exception(self, invalid_username, roles):
        with pytest.raises(TypeError):
            ClientData(client_id=invalid_username, roles=roles)

    def test_passing_empty_string_for_username_at_init_raises_exception(self, roles):
        with pytest.raises(ValueError):
            ClientData(client_id="", roles=roles)

    def test_passing_non_list_for_roles_at_init_raises_exception(self, valid_username, not_list):
        with pytest.raises(TypeError):
            ClientData(client_id=valid_username, roles=not_list)

    def test_passing_invalid_list_to_roles_at_init_raises_exception(self, valid_username, invalid_roles):
        with pytest.raises(ValueError):
            ClientData(client_id=valid_username, roles=invalid_roles)

    def test_successful_init_sets_data_properly(self, valid_username, roles):
        user = ClientData(client_id=valid_username, roles=roles)
        assert user.client_id == valid_username
        assert user.roles == roles

    # SETTER TESTS
    def test_setting_username_to_non_string_after_init_raises_exception(self, user, invalid_username):
        with pytest.raises(TypeError):
            user.client_id = invalid_username

    def test_setting_username_to_empty_string_after_init_raises_exception(self, user):
        with pytest.raises(ValueError):
            user.client_id = ""

    def test_setting_roles_to_non_list_after_init_raises_exception(self, user, not_list):
        with pytest.raises(TypeError):
            user.roles = not_list

    def test_setting_roles_to_invalid_roles_after_init_raises_exception(self, user, invalid_roles):
        with pytest.raises(ValueError):
            user.roles = invalid_roles

    def test_setting_username_to_valid_username_after_init_sets_data_properly(self, user):
        user.client_id = "other"
        assert user.client_id == "other"

    def test_setting_roles_to_roles_after_init_sets_data_properly(self, user):
        user.roles = ["admin", "lead", "analyst"]
        assert user.roles == ["admin", "lead", "analyst"]

    # TO_DICT TESTS
    def test_to_dict_formats_data_properly(self, user, expected_user_to_dict_return):
        assert user.to_dict() == expected_user_to_dict_return
