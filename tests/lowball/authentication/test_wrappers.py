import pytest

from flask import g, current_app

from lowball.authentication.wrappers import *
from lowball.exceptions import *


class TestValidateAuthHeaderFunction:
    # Failure case tests
    def test_passing_headers_without_auth_raises_exception(self, headers, request_no_headers):
        with pytest.raises(NoAuthHeaderException):
            validate_auth_header(headers)

    def test_passing_headers_with_invalid_auth_raises_exception(self, headers_invalid_auth, request_invalid_headers):
        with pytest.raises(InvalidAuthHeaderException):
            validate_auth_header(headers_invalid_auth)

    def test_passing_headers_with_expired_token_raises_exception(self, headers_with_token, request_token_expired):
        with pytest.raises(ExpiredTokenException):
            validate_auth_header(headers_with_token)

    def test_passing_headers_token_does_not_exist_in_database_raises_exception(self, headers_with_token,
                                                                               request_token_not_in_db):
        with pytest.raises(InvalidTokenException):
            validate_auth_header(headers_with_token)

    def test_passing_headers_token_data_does_not_match_database_token_raises_exception(self, headers_with_token,
                                                                                       request_unmatched_token):
        with pytest.raises(InvalidTokenException):
            validate_auth_header(headers_with_token)

    def test_making_request_with_no_authenticator_fails_gracefully(self, request_with_no_authdb, headers_with_token):
        with pytest.raises(NoAuthenticationDatabaseException):
            validate_auth_header(headers_with_token)

    # Success case tests
    def test_valid_auth_header_returns_proper_token_object(self, headers_with_token, request_valid_token, expected_token):
        decoded = validate_auth_header(headers_with_token)
        assert decoded == expected_token


class TestRequireAuthenticatedUserWrapper:
    def test_passing_invalid_tokens_raises_exception(self, request_invalid_headers):
        with pytest.raises(InvalidAuthHeaderException):
            @require_authenticated_user
            def test():
                pass

            test()

    def test_any_valid_token_is_accepted(self, request_any_role_token, expected_token):
        @require_authenticated_user
        def test():
            return True

        assert test()
        assert g.client_data == expected_token


class TestRequireAdminWrapper:
    def test_wrapper_raises_exception_when_no_admin_role_present(self, request_non_admin_token):
        with pytest.raises(InadequateRolesException):
            @require_admin
            def test():
                pass

            test()

    def test_wrapper_accepts_any_token_with_admin_role_included(self, request_admin_token, expected_token):
        @require_admin
        def test():
            return True

        assert test()
        assert g.client_data == expected_token


class TestRequireAnyOfTheseRolesWrapper:
    def test_wrapper_raises_exception_when_no_roles_present(self, request_token_no_roles):
        with pytest.raises(InadequateRolesException):
            @require_any_of_these_roles(roles=["admin", "lead", "analyst"])
            def test():
                pass

            test()

    def test_wrapper_works_with_any_combination_of_roles(self, request_admin_or_lead_or_analyst_token, expected_token):
        @require_any_of_these_roles(roles=["admin", "lead", "analyst"])
        def test():
            return True

        assert test()
        assert g.client_data == expected_token


class TestRequireAllOfTheseRolesWrapper:
    def test_wrapper_raises_exception_when_not_all_roles_present(self, request_not_all_roles_token):
        with pytest.raises(InadequateRolesException):
            @require_all_of_these_roles(roles=["admin", "lead", "analyst"])
            def test():
                pass

            test()

    def test_wrapper_accepts_token_with_all_roles(self, request_all_roles_token, expected_token):
        @require_all_of_these_roles(roles=["admin", "lead", "analyst"])
        def test():
            return True

        assert test()
        assert g.client_data == expected_token
