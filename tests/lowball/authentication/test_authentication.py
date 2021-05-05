import pytest

from datetime import datetime
import jwt
from lowball.authentication.authentication import Authentication
from lowball.exceptions import InvalidAuthDataException, InvalidRequestingUserException, InvalidTokenLifeException, \
    InvalidTokenException, BadRequestException
from lowball.models.authentication_models import Token, ClientData


class TestAuthentication:
    def test_init_raises_type_error_when_invalid_arguments_passed_in(self):
        with pytest.raises(TypeError):
            Authentication(config="Not a Authentication Object")
    
    def test_setting_config_to_invalid_value_after_init_raises_type_error(self, auth_config, not_auth_config):
        test_auth = Authentication(config=auth_config)

        with pytest.raises(TypeError):
            test_auth.config = not_auth_config

    def test_create_token_creates_expected_tokens(self, token_create_rounds, auth):
        client_data, requesting_user, expiration, expected_expiration, expected_token_string = token_create_rounds

        token, token_data = auth.create_token(
            client_data.client_id,
            client_data.roles,
            requesting_client=requesting_user,
            expiration=expiration
        )
        assert token == expected_token_string
        assert isinstance(token_data, Token)
        assert token_data.roles == client_data.roles
        assert token_data.expiration == expected_expiration
        assert token_data.issued_by == client_data.client_id if requesting_user is None else requesting_user

    def test_expiration_greater_than_max_token_life_produces_value_error(self, client_data, requesting_user, auth,
                                                                         bad_expiration):
        with pytest.raises(InvalidTokenLifeException):
            auth.create_token(client_data.client_id, client_data.roles, requesting_client=requesting_user, expiration=bad_expiration)

    def test_decode_token_properly_decodes_token(self, auth, expected_token, expected_token_string):
        assert auth.decode_token(expected_token_string) == expected_token

    def test_validate_token_functions_as_expected(self, auth, expected_token_string, expired_token_string, invalid_expected_token_string):
        assert auth.validate_token(expected_token_string) == True
        assert auth.validate_token(expired_token_string) == False
        assert auth.validate_token(invalid_expected_token_string) == False

    def test_passing_bad_auth_data_into_create_token_produces_error(self, auth, not_auth_data, requesting_user,
                                                                    expiration):
        with pytest.raises(BadRequestException):
            auth.create_token(client_id=not_auth_data, roles=not_auth_data, requesting_client=requesting_user, expiration=expiration)

    def test_passing_bad_requesting_user_into_create_token_produces_error(self, auth, client_data, not_user,
                                                                          expiration):
        with pytest.raises(BadRequestException):
            auth.create_token(client_data.client_id, client_data.roles, requesting_client=not_user, expiration=expiration)

    def test_decode_token_raises_invalid_token_error_when_invalid_token_passed(self, auth, bad_token_rounds):

        with pytest.raises(InvalidTokenException):
            auth.decode_token(bad_token_rounds)