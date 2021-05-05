from datetime import datetime

import pytest

from lowball.models.authentication_models import Token, valid_token_id, generate_token_id, TOKEN_ID_PATTERN
import re


class TestValidTokenID:

    @pytest.mark.parametrize("test_token_id,is_valid", [
        ("a"*16, True),
        ("a"*15, False),
        ("a"*17, False),
        ("0123456789abcdef", True),
        (None, False),
        (44747474744, False),
        ("aaaaaaaaaaaaaaa&", False)
    ])
    def test_valid_token_id_validates_tokens_correctly(self, test_token_id, is_valid):

        assert valid_token_id(test_token_id) == is_valid

class TestGenerateTokenID:

    def test_generate_token_id_creates_expected_string_format(self):
        for i in range(0, 1000):
            assert re.match(TOKEN_ID_PATTERN, generate_token_id()) is not None



class TestToken:
    @pytest.mark.parametrize("user, roles, created, expiration, issued_by, token_id", [
        (1, ["list", "of", "roles"], datetime(2020, 1, 1), datetime(2020, 2, 1), "issuer", "token_id"),
        ("user", 1, datetime(2020, 1, 1), datetime(2020, 2, 1), "issuer", "token_id"),
        ("user", ["list", "of", "roles"], 1, datetime(2020, 2, 1), "issuer", "token_id"),
        ("user", ["list", "of", "roles"], datetime(2020, 1, 1), 1, "issuer", "token_id"),
        ("user", ["list", "of", "roles"], datetime(2020, 1, 1), datetime(2020, 2, 1), 1, "token_id"),
        ("user", ["list", "of", "roles"], datetime(2020, 1, 1), datetime(2020, 2, 1), "issuer", 1),
    ])
    def test_init_raises_type_error_when_improper_data_passed_in(self, user, roles, created, expiration, issued_by,
                                                                 token_id):
        with pytest.raises(TypeError):
            Token(cid=user, r=roles, cts=created, ets=expiration, rcid=issued_by,
                  tid=token_id)

    def test_not_all_roles_strings_raises_value_error(self, username, created, expiration, issued_by, token_id, 
                                                      invalid_roles):
        with pytest.raises(ValueError):
            Token(cid=username, r=invalid_roles, cts=created, ets=expiration, rcid=issued_by,
                  tid=token_id)

    def test_to_dict_method_returns_proper_data(self, username, roles, created, expiration, issued_by, token_id,
                                                token_dict):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)
        assert token.to_dict() == token_dict

    def test_setting_user_to_bad_value_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                         token_id, not_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.client_id = not_string

    def test_setting_roles_to_bad_value_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                          token_id, not_list):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.roles = not_list
            
    def test_setting_roles_to_bad_value_after_init_raises_value_error(self, username, roles, created, expiration,
                                                                      issued_by, token_id, invalid_roles):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(ValueError):
            token.roles = invalid_roles

    def test_setting_created_to_not_datetime_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                               token_id, not_datetime):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.created = not_datetime

    def test_setting_expiration_to_not_datetime_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                                  token_id, not_datetime):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.expiration = not_datetime

    def test_setting_created_to_not_string_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                             token_id, not_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.created = not_string

    def test_setting_expiration_to_not_string_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                                token_id, not_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.expiration = not_string

    def test_setting_created_to_bad_string_raises_value_error(self, username, roles, created, expiration, issued_by,
                                                              token_id, bad_date_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(ValueError):
            token.created = bad_date_string

    def test_setting_expiration_to_bad_string_raises_value_error(self, username, roles, created, expiration, issued_by,
                                                                 token_id, bad_date_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(ValueError):
            token.expiration = bad_date_string

    def test_setting_issued_by_to_bad_value_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                              token_id, not_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.issued_by = not_string

    def test_setting_token_id_to_bad_value_raises_type_error(self, username, roles, created, expiration, issued_by,
                                                             token_id, not_string):
        token = Token(cid=username, r=roles, cts=created, ets=expiration, rcid=issued_by,
                      tid=token_id)

        with pytest.raises(TypeError):
            token.token_id = not_string

    @pytest.mark.parametrize("test_token_id", [
        ("a" * 15),
        ("a" * 17),
        ("aaaaaaaaaaaaaaa&")
    ])
    def test_setting_token_id_to_bad_string_raises_value_error(self, token, test_token_id):

        with pytest.raises(ValueError):
            token.token_id = test_token_id