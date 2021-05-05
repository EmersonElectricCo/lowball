from pathlib import Path
from unittest.mock import call

import pytest
from ruamel.yaml import YAML

from lowball.builtins.providers import DefaultAuthDB


class TestAuthDBInit:
    def test_raise_clean_error_when_lacking_permissions_to_write_to_token_path(self, mkdir_raises_permission_error):
        with pytest.raises(PermissionError) as err:
            DefaultAuthDB()
        assert err.value.args[0] == "Lacking permissions to store tokens at configured route"


class TestAuthDBAttributes:
    def test_init_token_path_as_not_pathlike_object_raises_exception(self, not_pathlike):
        with pytest.raises(TypeError):
            DefaultAuthDB(token_path=not_pathlike)

    def test_token_path_attribute_access_returns_path_object(self, token_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        assert isinstance(test_auth_db.token_path, Path)

    def test_setting_token_path_to_not_pathlike_after_init_raises_exception(self, token_path, not_pathlike,
                                                                            mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)

        with pytest.raises(TypeError):
            test_auth_db.token_path = not_pathlike

    def test_token_path_gets_created_on_init(self, token_path, mocked_mkdir):
        DefaultAuthDB(token_path=token_path)
        Path.mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestDumpTokenMethod:
    def test_dumping_tokens_with_path_like_ids_throws_errors(self, pathlike_token, token_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)

        with pytest.raises(ValueError):
            test_auth_db._dump_token(token_data=pathlike_token)

    def test_generating_token_creates_token_properly(self, token, mocked_yaml_dump, token_path, mock_open_file, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        test_auth_db._dump_token(token_data=token)

        opened_token_file = open(token_path)
        YAML.dump.assert_called_once_with(token.to_dict(), opened_token_file)


class TestLoadTokenMethod:
    def test_loading_tokens_with_path_like_ids_throws_errors(self, pathlike_token_id, token_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)

        with pytest.raises(ValueError):
            test_auth_db._load_token(token_id=pathlike_token_id)

    def test_load_non_existent_token_returns_none(self, token_path, token_id, mock_nonexistent_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        token_data = test_auth_db._load_token(token_id=token_id)

        assert token_data is None

    def test_loading_corrupted_token_file_returns_none_and_deletes_token(self, token_path, token_id,
                                                                         corrupted_token_file, mock_existent_path,
                                                                         mock_internal_revoke_token, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        token_data = test_auth_db._load_token(token_id=token_id)

        DefaultAuthDB._delete_token.assert_called_once_with(token_id)
        assert token_data is None

    def test_loading_token_data_returns_proper_data(self, token_path, token_id, token_file, token,
                                                    mock_existent_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        token_data = test_auth_db._load_token(token_id=token_id)

        assert token_data == token


class TestDeleteTokenMethod:
    def test_deleting_tokens_with_path_like_ids_throws_errors(self, pathlike_token_id, token_path, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)

        with pytest.raises(ValueError):
            test_auth_db._delete_token(token_id=pathlike_token_id)

    def test_deleting_non_existent_token_does_not_throw_exception(self, token_path, token_id, mocked_mkdir,
                                                                  mock_unlink_non_existent_file):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        test_auth_db._delete_token(token_id=token_id)

        Path.unlink.assert_called_once()

    def test_deleting_valid_token_returns_true(self, token_path, token_id, mock_path_unlink, mocked_mkdir):
        test_auth_db = DefaultAuthDB(token_path=token_path)
        test_auth_db._delete_token(token_id=token_id)

        Path.unlink.assert_called_once()


class TestAuthDBMethods:
    def test_add_token_calls_internal_method_and_returns_true_for_success(self, default_auth_db, token,
                                                                          mock_default_auth_db_internals):
        default_auth_db.add_token(token)

        DefaultAuthDB._dump_token.assert_called_once_with(token)

    def test_lookup_token_returns_token_object(self, default_auth_db, token_id, mock_default_auth_db_internals,
                                               token):
        result = default_auth_db.lookup_token(token_id=token_id)

        DefaultAuthDB._load_token.assert_called_once_with(token_id)
        assert result == token

    def test_lookup_non_existent_token_returns_none(self, default_auth_db, token_id,
                                                    mock_internal_load_non_existent_token):
        result = default_auth_db.lookup_token(token_id=token_id)

        DefaultAuthDB._load_token.assert_called_once_with(token_id)
        assert result is None

    def test_revoke_token_calls_internal_method_and_returns_true(self, default_auth_db, token_identifier,
                                                                 mock_default_auth_db_internals, token_id):
        default_auth_db.revoke_token(token_id=token_identifier)

        DefaultAuthDB._delete_token.assert_called_once_with(token_id)

    def test_revoke_non_existent_token_returns_false(self, default_auth_db, token_identifier, token_id,
                                                     mock_internal_revoke_token):
        default_auth_db.revoke_token(token_id=token_identifier)

        DefaultAuthDB._delete_token.assert_called_once_with(token_id)

    def test_list_tokens_with_bad_token_path_returns_empty_list(self, default_auth_db, mock_nonexistent_path):
        result = default_auth_db.list_tokens()
        assert result == []

    def test_list_tokens_returns_expected_output(self, default_auth_db, mock_iterdir, mock_existent_path,
                                                 mock_load_multiple_tokens_internal, expected_list_tokens,
                                                 token_id1, token_id2, token_id3, token_id4, token_id5):
        calls = [
            call(default_auth_db.token_path.joinpath(token_id1)),
            call(default_auth_db.token_path.joinpath(token_id2)),
            call(default_auth_db.token_path.joinpath(token_id3)),
            call(default_auth_db.token_path.joinpath(token_id4)),
            call(default_auth_db.token_path.joinpath(token_id5)),
        ]
        token_list = default_auth_db.list_tokens()

        DefaultAuthDB._load_token.assert_has_calls(calls)
        assert token_list == expected_list_tokens

    def test_list_tokens_by_user_filters_tokens_properly(self, default_auth_db, mock_list_tokens,
                                                         expected_filter_by_user_result):
        result = default_auth_db.list_tokens_by_client_id(client_id="username")

        DefaultAuthDB.list_tokens.assert_called_once()
        assert result == expected_filter_by_user_result

    def test_list_tokens_by_roles_filters_tokens_properly(self, default_auth_db, mock_list_tokens,
                                                          expected_filter_by_role_result):
        result = default_auth_db.list_tokens_by_role(role="analyst")

        DefaultAuthDB.list_tokens.assert_called_once()
        assert result == expected_filter_by_role_result

    def test_cleanup_tokens_deletes_expired_tokens(self, default_auth_db, mock_list_tokens,
                                                   mock_default_auth_db_internals, token_id5, token_id4):
        calls = [
            call(token_id5),
            call(token_id4)
        ]

        default_auth_db.cleanup_tokens()

        DefaultAuthDB.list_tokens.assert_called_once()
        DefaultAuthDB._delete_token.assert_has_calls(calls)

    def test_revoke_all_tokens_makes_proper_calls(self, default_auth_db, mock_list_tokens,
                                                  mock_default_auth_db_internals,
                                                  token_id1, token_id2, token_id5, token_id3, token_id4):
        calls = [
            call(token_id1),
            call(token_id2),
            call(token_id5),
            call(token_id3),
            call(token_id4)
        ]

        default_auth_db.revoke_all()

        DefaultAuthDB.list_tokens.assert_called_once()
        DefaultAuthDB._delete_token.assert_has_calls(calls)
