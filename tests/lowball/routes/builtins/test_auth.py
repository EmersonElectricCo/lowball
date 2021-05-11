import datetime
from unittest.mock import call

from flask import request

from lowball.exceptions import InadequateRolesException
from lowball.models.authentication_models import Token

class TestLogin:
    ROUTE = "/builtins/auth"

    # test no auth provider
    def test_user_login_attempt_fails_with_no_auth_provider(
            self, lowball_app_no_auth_provider, expected_no_auth_provider_error_response):
        response = lowball_app_no_auth_provider.post(self.ROUTE)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # test no auth db
    def test_user_login_attempt_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response):
        response = lowball_app_no_db.post(self.ROUTE)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # test auth provider no auth package class
    def test_user_login_attempt_fails_with_no_defined_auth_package_class(self,
                                                                         lowball_app_mock_providers):
        response = lowball_app_mock_providers.post(self.ROUTE, json={"some": "json"})

        assert response.status_code == 501
        assert response.json["message"] == "501 Not Implemented: auth_package_class not implemented"

    # test bad json input
    def test_user_login_attempt_fails_with_incorrect_auth_package_input(self,
                                                                        lowball_app_mock_providers,
                                                                        does_not_match_auth_package_request,
                                                                        mock_auth_package_class):
        response = lowball_app_mock_providers.post(self.ROUTE, json=does_not_match_auth_package_request)
        print(response.json)
        assert response.status_code == 400
        assert "The Authentication Request Did Not Supply The Required Data" in response.json["message"]

    # test success - calls authenticate and gets token data - calls authdb add token, returns data
    def test_user_login_attempt_success_flow(self,
                                             lowball_app_mock_providers,
                                             mock_auth_package_class,
                                             mock_authenticate_basic,
                                             success_request,
                                             mock_create_token,
                                             token,
                                             jwt_token,
                                             mock_add_token):
        response = lowball_app_mock_providers.post(self.ROUTE, json=success_request)
        assert response.status_code == 200
        assert "token" in response.json
        assert "token_data" in response.json
        assert response.json["token"] == jwt_token
        assert response.json["token_data"] == token.to_dict()
        lowball_app_mock_providers.application.auth_db.add_token.assert_called_once_with(token)
        lowball_app_mock_providers.application.authenticator.create_token.assert_called_once_with(client_id=token.client_id,
                                                                                                  roles=token.roles)


class TestLogout:
    ROUTE = "/builtins/auth"

    # test no auth db
    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.delete(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert not authenticated fails
    def test_self_update_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                               not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # test no auth db
    def test_user_logout_attempt_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response,
                                                             basic_header):
        response = lowball_app_no_db.delete(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # test calls revoke token with token id, returns 204 no data
    def test_user_logout_success_flow(self, lowball_app_mock_providers, basic_header, token,
                                      mock_decode_token, mock_lookup_token, mock_revoke_token):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=basic_header)
        assert response.status_code == 204
        assert not response.get_data(as_text=True)
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_called_once_with(token.token_id)


class TestWhoami:
    ROUTE = "/builtins/auth"

    # test no auth db
    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.get(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                  json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # success return full token
    def test_returns_decoded_token(self, lowball_app_mock_providers, token_request_rounds,
                                                     mock_lookup_token_filled):
        header, expected = token_request_rounds

        response = lowball_app_mock_providers.get(self.ROUTE, headers=header)
        assert response.status_code == 200
        assert response.json == expected.to_dict()


class TestGetCurrentClientTokens:
    ROUTE = "/builtins/auth/tokens"

    # test no auth db
    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.get(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                  json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_list_tokens_gets_user_tokens_with_no_filters_applied(self,
                                                               lowball_app_mock_providers,
                                                               mock_lookup_token_filled,
                                                               normal1_token1_request_header,
                                                               client_id_normal1,
                                                               mock_list_tokens_filled,
                                                               mock_list_tokens_by_client_id,
                                                               non_admin_client_list_token_expected_response
                                                               ):
        response = lowball_app_mock_providers.get(f"{self.ROUTE}", headers=normal1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in non_admin_client_list_token_expected_response)
        assert all(token_dict in non_admin_client_list_token_expected_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens_by_client_id.assert_called_once_with(client_id_normal1)

    def test_list_tokens_gets_correct_tokens_allowed_filters_applied(self,
                                                                      lowball_app_mock_providers,
                                                                      mock_lookup_token_filled,
                                                                      normal1_token1_request_header,
                                                                      client_id_normal1,
                                                                      mock_list_tokens_filled,
                                                                      mock_list_tokens_by_client_id,
                                                                      non_admin_client_list_token_expected_response_with_queries

                                                                      ):
        query, expected_response = non_admin_client_list_token_expected_response_with_queries

        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=normal1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in expected_response)
        assert all(token_dict in expected_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens_by_client_id.assert_called_once_with(client_id_normal1)


    def test_list_tokens_fails_when_invalid_types_returned_from_auth_db(self, mock_list_tokens_returns_bad_values,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        normal1_token1_request_header,
                                                                        client_id_normal1
                                                                        ):
        normal_response = lowball_app_mock_providers.get(f"{self.ROUTE}", headers=normal1_token1_request_header)

        assert normal_response.status_code == 500
        assert "auth_db.list_tokens did not return a list as expected" in normal_response.json["message"] or \
               "auth_db.list_tokens returned a list that included a non-Token object" in normal_response.json["message"]
        lowball_app_mock_providers.application.auth_db.list_tokens_by_client_id.assert_called_once_with(client_id_normal1)


class TestCreateToken:
    ROUTE = "/builtins/auth/tokens"

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 201
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

        # test no auth db

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.post(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    def test_failure_when_no_auth_provider_initialized_for_non_admin_token(self,
                                                                           lowball_app_no_auth_provider,
                                                                           expected_no_auth_provider_error_response,
                                                                           normal1_token1_request_header,
                                                                           mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.post(self.ROUTE, headers=normal1_token1_request_header)
        print(response.json)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    def test_create_token_fails_for_invalid_token_life(self,
                                                       create_token_request_bad_token_life_rounds,
                                                       lowball_app_mock_providers,
                                                       mock_lookup_token_filled,
                                                       admin1_token1_request_header,
                                                       expected_bad_token_life_response
                                                       ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=admin1_token1_request_header,
                                                   json=create_token_request_bad_token_life_rounds)
        assert response.status_code == 400
        assert expected_bad_token_life_response in response.json["message"]

    def test_create_token_fails_for_non_admin_client_when_request_is_for_another_client(self,
                                                                                        normal1_token1_request_header,
                                                                                        client_id_normal2,
                                                                                        lowball_app_mock_providers,
                                                                                        mock_lookup_token_filled
                                                                                        ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=normal1_token1_request_header,
                                                   json={"client_id": client_id_normal2})

        assert response.status_code == 401
        assert "Current Token Has Inadequate Roles for Requested Action" in response.json["message"]

    def test_create_token_fails_for_non_admin_client_when_get_client_is_not_implemented(self,
                                                                                        normal1_token1_request_header,
                                                                                        client_id_normal1,
                                                                                        lowball_app_mock_providers,
                                                                                        mock_lookup_token_filled,
                                                                                        mock_get_client_not_implemented
                                                                                        ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=normal1_token1_request_header,
                                                   json={"client_id": client_id_normal1})
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)

        print(response.json)
        assert response.status_code == 409
        assert "get_client is not implemented in this auth provider. Non admin clients are unable to create tokens" \
               in response.json["message"]

    def test_create_token_creates_expected_tokens_for_admin_clients(self,
                                                                    lowball_app_mock_providers,
                                                                    mock_lookup_token_filled,
                                                                    admin1_token1_request_header,
                                                                    admin_client_create_token_success_rounds,
                                                                    mock_add_token
                                                                    ):
        request_body, expected_token_string, expected_token_object = admin_client_create_token_success_rounds
        print(expected_token_object.to_dict())
        response = lowball_app_mock_providers.post(self.ROUTE, headers=admin1_token1_request_header, json=request_body)

        assert response.status_code == 201
        assert response.json["token"] == expected_token_string
        assert response.json["token_data"] == expected_token_object.to_dict()
        lowball_app_mock_providers.application.authenticator.create_token.assert_called_once_with(
            expected_token_object.client_id,
            expected_token_object.roles,
            expected_token_object.issued_by,
            expected_token_object.expiration
        )
        lowball_app_mock_providers.application.auth_db.add_token.assert_called_once_with(expected_token_object)

    def test_create_token_creates_expected_tokens_for_non_admin_clients(self,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        normal1_token1_request_header,
                                                                        normal_client_create_token_success_rounds,
                                                                        mock_add_token,
                                                                        mock_get_client_filled
                                                                        ):
        request_body, expected_token_string, expected_token_object = normal_client_create_token_success_rounds
        print(expected_token_object.to_dict())
        response = lowball_app_mock_providers.post(self.ROUTE, headers=normal1_token1_request_header, json=request_body)

        assert response.status_code == 201
        assert response.json["token"] == expected_token_string
        assert response.json["token_data"] == expected_token_object.to_dict()
        lowball_app_mock_providers.application.authenticator.create_token.assert_called_once_with(
            expected_token_object.client_id,
            expected_token_object.roles,
            expected_token_object.issued_by,
            expected_token_object.expiration
        )
        lowball_app_mock_providers.application.auth_db.add_token.assert_called_once_with(expected_token_object)

    def test_create_token_fails_for_non_admin_client_for_themselves_if_client_is_not_in_auth_provider(self,
                                                                                                      lowball_app_mock_providers,
                                                                                                      mock_lookup_token_filled,
                                                                                                      normal2_token1_request_header,
                                                                                                      client_id_normal2,
                                                                                                      mock_get_client_filled
                                                                                                      ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=normal2_token1_request_header)
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)
        assert response.status_code == 404
        assert "Client ID for requesting token not found in auth provider" in response.json["message"]

    def test_create_token_fails_for_non_admin_client_if_roles_not_in_clients_listed_roles(self,
                                                                                          lowball_app_mock_providers,
                                                                                          mock_lookup_token_filled,
                                                                                          normal1_token1_request_header,
                                                                                          client_id_normal1,
                                                                                          mock_get_client_filled,
                                                                                          base_role2
                                                                                          ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=normal1_token1_request_header,
                                                   json={"roles": base_role2})
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        assert response.status_code == 401
        assert "Current Token Has Inadequate Roles for Requested Action" in response.json["message"]


class TestDeleteCurrentClientTokens:
    ROUTE = "/builtins/auth/tokens"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.delete(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                     json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_client_calls_revoke_token_for_each_token_they_have(self, lowball_app_mock_providers,
                                                                          normal1_token1_request_header,
                                                                          client_id_normal1,
                                                                          mock_lookup_token_filled,
                                                                          mock_list_tokens_by_client_id,
                                                                          mock_revoke_token,
                                                                          token1_normal1,
                                                                          token2_normal1,
                                                                          token3_normal1_expired):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=normal1_token1_request_header,
                                                     json={})
        assert response.status_code == 204
        calls = [
            call(token1_normal1.token_id),
            call(token2_normal1.token_id),
            call(token3_normal1_expired.token_id)
        ]
        lowball_app_mock_providers.application.auth_db.list_tokens_by_client_id.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_has_calls(calls)

    def test_list_tokens_fails_when_invalid_types_returned_from_auth_db(self, mock_list_tokens_returns_bad_values,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        normal1_token1_request_header,
                                                                        client_id_normal1
                                                                        ):
        normal_response = lowball_app_mock_providers.delete(f"{self.ROUTE}", headers=normal1_token1_request_header)

        assert normal_response.status_code == 500
        assert "auth_db.list_tokens did not return a list as expected" in normal_response.json["message"] or \
               "auth_db.list_tokens returned a list that included a non-Token object" in normal_response.json["message"]
        lowball_app_mock_providers.application.auth_db.list_tokens_by_client_id.assert_called_once_with(client_id_normal1)


class TestGetAllTokens:
    ROUTE = "/builtins/auth/tokens/all"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.get(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                               not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                    json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                                               non_admin_headers):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=non_admin_headers,
                                                    json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_list_tokens_for_admin_client_gets_all_tokens_when_no_filters_applied(self, lowball_app_mock_providers,
                                                                                  mock_lookup_token_filled,
                                                                                  token_db, admin1_token1_request_header,
                                                                                  mock_list_tokens_filled):

        response = lowball_app_mock_providers.get(self.ROUTE, headers=admin1_token1_request_header)

        assert response.status_code == 200
        print(response.json)
        assert all(token.to_dict() in response.json for token in token_db.values())
        assert all(token_dict in [token.to_dict() for token in token_db.values()] for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()

    def test_list_tokens_for_admin_client_gets_correct_tokens_when_role_filters_applied(self, base_role1,
                                                                                        lowball_app_mock_providers,
                                                                                        mock_lookup_token_filled,
                                                                                        admin_list_token_roles_request_response,
                                                                                        admin1_token1_request_header,
                                                                                        mock_list_tokens_filled):

        query, expected_response = admin_list_token_roles_request_response

        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in expected_response)
        assert all(token_dict in expected_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()

    def test_list_tokens_for_admin_client_gets_correct_tokens_when_client_filters_applied(self,
                                                                                          lowball_app_mock_providers,
                                                                                          mock_lookup_token_filled,
                                                                                          admin_list_token_client_request_response,
                                                                                          admin1_token1_request_header,
                                                                                          mock_list_tokens_filled
                                                                                          ):
        query, expected_response = admin_list_token_client_request_response

        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in expected_response)
        assert all(token_dict in expected_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()

    def test_list_tokens_for_admin_client_gets_correct_tokens_when_exclude_expired_filter_set_to_true(self,
                                                                                                      lowball_app_mock_providers,
                                                                                                      mock_lookup_token_filled,
                                                                                                      admin1_token1_request_header,
                                                                                                      mock_list_tokens_filled,
                                                                                                      token_db_admin_exclude_expired_response
                                                                                                      ):

        query = "?exclude_expired=yes"
        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in token_db_admin_exclude_expired_response)
        assert all(token_dict in token_db_admin_exclude_expired_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()

    def test_list_tokens_for_admin_client_gets_correct_tokens_when_multiple_filters_applied(self,
                                                                                            lowball_app_mock_providers,
                                                                                            mock_lookup_token_filled,
                                                                                            admin1_token1_request_header,
                                                                                            mock_list_tokens_filled,
                                                                                            admin_list_token_multi_query_request_response
                                                                                            ):
        query, expected_response = admin_list_token_multi_query_request_response

        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)
        assert isinstance(response.json, list)
        assert response.status_code == 200
        assert all(token_dict in response.json for token_dict in expected_response)
        assert all(token_dict in expected_response for token_dict in response.json)
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()

    def test_list_tokens_fails_when_invalid_types_returned_from_auth_db(self, mock_list_tokens_returns_bad_values,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        admin1_token1_request_header
                                                                        ):
        normal_response = lowball_app_mock_providers.get(f"{self.ROUTE}", headers=admin1_token1_request_header)

        assert normal_response.status_code == 500
        assert "auth_db.list_tokens did not return a list as expected" in normal_response.json["message"] or \
               "auth_db.list_tokens returned a list that included a non-Token object" in normal_response.json["message"]
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()


class TestDeleteAllTokens:
    ROUTE = "/builtins/auth/tokens/all"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.delete(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                  json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=non_admin_headers,
                                                  json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_calls_revoke_all_when_no_filters_supplied(self, lowball_app_mock_providers,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled,
                                                       mock_list_tokens_filled,
                                                       mock_list_tokens_by_client_id,
                                                       mock_revoke_all
                                                       ):
        response = lowball_app_mock_providers.delete(self.ROUTE, headers=admin1_token1_request_header,
                                                     json={})
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_db.revoke_all.assert_called_once()

    def test_calls_revoke_token_with_correct_tokens_client_filter_applied(self,
                                                                          lowball_app_mock_providers,
                                                                          admin1_token1_request_header,
                                                                          mock_lookup_token_filled,
                                                                          mock_list_tokens_filled,
                                                                          admin_delete_token_client_request_response,
                                                                          mock_revoke_token
                                                                          ):
        query, expected_tokens = admin_delete_token_client_request_response
        response = lowball_app_mock_providers.delete(f"{self.ROUTE}{query}", headers=admin1_token1_request_header,
                                                     json={})
        assert response.status_code == 204
        calls = [
            call(token.token_id) for token in expected_tokens
        ]
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_has_calls(calls)

    def test_calls_revoke_token_with_correct_tokens_role_filter_applied(self,
                                                                          lowball_app_mock_providers,
                                                                          admin1_token1_request_header,
                                                                          mock_lookup_token_filled,
                                                                          mock_list_tokens_filled,
                                                                          admin_delete_token_roles_request_response,
                                                                          mock_revoke_token
                                                                          ):
        query, expected_tokens = admin_delete_token_roles_request_response
        response = lowball_app_mock_providers.delete(f"{self.ROUTE}{query}", headers=admin1_token1_request_header,
                                                     json={})
        assert response.status_code == 204
        calls = [
            call(token.token_id) for token in expected_tokens
        ]
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_has_calls(calls)

    def test_calls_revoke_token_with_correct_tokens_multiple_filters(self, lowball_app_mock_providers,
                                                                          admin1_token1_request_header,
                                                                          mock_lookup_token_filled,
                                                                          mock_list_tokens_filled,
                                                                          admin_delete_token_multi_query_request_response,
                                                                          mock_revoke_token
                                                                          ):
        query, expected_tokens = admin_delete_token_multi_query_request_response
        response = lowball_app_mock_providers.delete(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)

        assert response.status_code == 204
        calls = [
            call(token.token_id) for token in expected_tokens
        ]
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_has_calls(calls)

    def test_list_tokens_fails_when_invalid_types_returned_from_auth_db(self, mock_list_tokens_returns_bad_values,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        admin1_token1_request_header,
                                                                        admin_delete_token_multi_query_request_response
                                                                        ):
        query, expected_tokens = admin_delete_token_multi_query_request_response
        normal_response = lowball_app_mock_providers.delete(f"{self.ROUTE}{query}", headers=admin1_token1_request_header)

        assert normal_response.status_code == 500
        assert "auth_db.list_tokens did not return a list as expected" in normal_response.json["message"] or \
               "auth_db.list_tokens returned a list that included a non-Token object" in normal_response.json["message"]
        lowball_app_mock_providers.application.auth_db.list_tokens.assert_called_once()


class TestCleanupTokens:
    ROUTE = "/builtins/auth/tokens/cleanup"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.post(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response


    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    # success route
    def test_cleanup_token_calls_the_cleanup_tokens_function_on_success(self,
                                                                        lowball_app_mock_providers,
                                                                        admin1_token1_request_header,
                                                                        mock_lookup_token_filled,
                                                                        mock_cleanup_tokens
                                                                        ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_db.cleanup_tokens.assert_called_once()


class TestGetToken:
    ROUTE = "/builtins/auth/tokens/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anytoken")
        response = lowball_app_no_db.get(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   token_id,
                                                                   not_authenticated_or_token_expired_header):
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.get(route, headers=not_authenticated_or_token_expired_header)
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_attempt_fails_when_invalid_token_id_format(self,
                                                        lowball_app_mock_providers,
                                                        mock_lookup_token_filled,
                                                        mock_list_tokens_filled,
                                                        invalid_token_ids,
                                                        admin1_token1_request_header
                                                        ):
        route = self.ROUTE.format(invalid_token_ids)
        response = lowball_app_mock_providers.get(route, headers=admin1_token1_request_header)

        assert response.status_code == 400
        assert "Invalid token id format" in response.json["message"]

    def test_not_found_when_token_id_not_found(self,
                                               lowball_app_mock_providers,
                                               mock_lookup_token_filled,
                                               mock_list_tokens_filled,
                                               admin1_token1_request_header
                                               ):
        route = self.ROUTE.format("amissingtokenidI")
        response = lowball_app_mock_providers.get(route, headers=admin1_token1_request_header)
        assert call("amissingtokenidI") in lowball_app_mock_providers.application.auth_db.lookup_token.mock_calls
        assert response.status_code == 404

    def test_admin_client_success_when_looking_up_token_for_other_client(self,
                                                                         lowball_app_mock_providers,
                                                                         mock_lookup_token_filled,
                                                                         admin1_token1_request_header,
                                                                         mock_list_tokens_filled,
                                                                         expected_lookup_token_response_for_admin
                                                                         ):
        token_id, expected_response = expected_lookup_token_response_for_admin
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.get(route, headers=admin1_token1_request_header)
        assert call(token_id) in lowball_app_mock_providers.application.auth_db.lookup_token.mock_calls
        assert response.status_code == 200
        assert response.json == expected_response

    def test_non_admin_client_failure_when_looking_up_token_for_other_client(self,
                                                                             lowball_app_mock_providers,
                                                                             mock_lookup_token_filled,
                                                                             mock_list_tokens_filled,
                                                                             normal1_token1_request_header,
                                                                             token2_normal2
                                                                             ):
        route = self.ROUTE.format(token2_normal2.token_id)
        response = lowball_app_mock_providers.get(route, headers=normal1_token1_request_header)
        assert response.status_code == 401
        assert "Current Token Has Inadequate Roles for Requested Action" in response.json["message"]

    def test_success_when_client_looks_up_token_owned_by_client(self,
                                                                lowball_app_mock_providers,
                                                                mock_lookup_token_filled,
                                                                mock_list_tokens_filled,
                                                                normal1_token1_request_header,
                                                                normal1_token_ids_request_response
                                                                ):
        token_id, expected_response = normal1_token_ids_request_response
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.get(route, headers=normal1_token1_request_header)

        assert call(token_id) in lowball_app_mock_providers.application.auth_db.lookup_token.mock_calls
        assert response.status_code == 200
        assert response.json == expected_response


class TestDeleteToken:
    ROUTE = "/builtins/auth/tokens/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.delete(self.ROUTE.format("anytokenid"), headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   token_id):
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.delete(route, headers=not_authenticated_or_token_expired_header,
                                                     json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_attempt_fails_when_invalid_token_id_format(self,
                                                        lowball_app_mock_providers,
                                                        mock_lookup_token_filled,
                                                        mock_list_tokens_filled,
                                                        invalid_token_ids,
                                                        admin1_token1_request_header
                                                        ):
        route = self.ROUTE.format(invalid_token_ids)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header)

        assert response.status_code == 400
        assert "Invalid token id format" in response.json["message"]

    # admin
    def test_not_found_when_token_id_is_not_found(self,
                                                  lowball_app_mock_providers,
                                                  mock_lookup_token_filled,
                                                  mock_list_tokens_filled,
                                                  admin1_token1_request_header
                                                  ):
        route = self.ROUTE.format("amissingtokenidI")
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header)

        assert response.status_code == 404

    def test_attempt_succeeds_for_admin_client_with_any_token(self,
                                                              lowball_app_mock_providers,
                                                              mock_lookup_token_filled,
                                                              admin1_token1_request_header,
                                                              mock_list_tokens_filled,
                                                              expected_lookup_token_response_for_admin,
                                                              mock_revoke_token
                                                              ):
        token_id, expected_response = expected_lookup_token_response_for_admin
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header)
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_called_once_with(token_id)
        assert response.status_code == 204

    def test_attempt_unauthorized_for_non_admin_client_with_non_owned_token(self,
                                                                            lowball_app_mock_providers,
                                                                            mock_lookup_token_filled,
                                                                            mock_list_tokens_filled,
                                                                            normal1_token1_request_header,
                                                                            token2_normal2
                                                                            ):
        route = self.ROUTE.format(token2_normal2.token_id)
        response = lowball_app_mock_providers.delete(route, headers=normal1_token1_request_header)
        assert response.status_code == 401
        assert "Current Token Has Inadequate Roles for Requested Action" in response.json["message"]

    def test_attempt_success_for_any_client_with_owned_token(self,
                                                             lowball_app_mock_providers,
                                                             mock_lookup_token_filled,
                                                             mock_list_tokens_filled,
                                                             normal1_token1_request_header,
                                                             normal1_token_ids_request_response,
                                                             mock_revoke_token
                                                             ):
        token_id, expected_response = normal1_token_ids_request_response
        route = self.ROUTE.format(token_id)
        response = lowball_app_mock_providers.delete(route, headers=normal1_token1_request_header)
        lowball_app_mock_providers.application.auth_db.revoke_token.assert_called_once_with(token_id)

        assert response.status_code == 204


class TestGetCurrentClient:
    ROUTE = "/builtins/auth/clients"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.get(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                  json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.get(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    def test_not_found_if_client_not_found(self,
                                           lowball_app_mock_providers,
                                           normal2_token1_request_header,
                                           client_id_normal2,
                                           mock_lookup_token_filled,
                                           mock_get_client_filled
                                           ):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=normal2_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    def test_success_outputs_for_client_data(self,
                                             lowball_app_mock_providers,
                                             mock_lookup_token_filled,
                                             mock_get_client_filled,
                                             get_current_client_request_response_rounds
                                             ):
        header, client_id,expected_response = get_current_client_request_response_rounds

        response = lowball_app_mock_providers.get(self.ROUTE, headers=header)
        print(response.json)
        assert response.status_code == 200
        assert response.json == expected_response
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id)


class TestClientSelfUpdate:
    ROUTE = "/builtins/auth/clients"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.post(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_self_update_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                               not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                    json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # fail client not found
    def test_self_update_attempt_fails_when_client_not_found(self,
                                                             lowball_app_mock_providers,
                                                             basic_header,
                                                             mock_get_client_not_found,
                                                             mock_decode_token,
                                                             mock_lookup_token,
                                                             mock_self_update_class,
                                                             ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=basic_header)
        assert response.status_code == 404
        assert "Client not found" in response.json["message"]

    # test no auth provider
    def test_self_update_attempt_fails_with_no_auth_provider_present(
            self, lowball_app_no_auth_provider, expected_no_auth_provider_error_response, basic_header,
            mock_decode_token, mock_lookup_token):
        response = lowball_app_no_auth_provider.post(self.ROUTE, headers=basic_header)
        print(response.json)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # test no client self update package class
    def test_self_update_attempt_fails_with_no_self_update_package_class_defined(self,
                                                                                 lowball_app_mock_providers,
                                                                                 basic_header,
                                                                                 mock_decode_token,
                                                                                 mock_lookup_token,
                                                                                 mock_get_client_found
                                                                                 ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=basic_header)

        assert response.status_code == 501
        assert response.json["message"] == "501 Not Implemented: self_update_client_package_class not implemented"

    # test bad json/patch data
    def test_self_update_attempt_fails_with_invalid_patch_data(self,
                                                               lowball_app_mock_providers,
                                                               basic_header,
                                                               mock_decode_token,
                                                               mock_lookup_token,
                                                               mock_self_update_class,
                                                               expected_bad_package_data_error_response,
                                                               does_not_match_self_update_package_request,
                                                               mock_get_client_found):
        response = lowball_app_mock_providers.post(self.ROUTE,
                                                    headers=basic_header,
                                                    json=does_not_match_self_update_package_request)

        assert response.status_code == 400
        assert response.json["message"] == expected_bad_package_data_error_response

    def test_self_update_success_flow(self,
                                      lowball_app_mock_providers,
                                      basic_header,
                                      mock_decode_token,
                                      mock_lookup_token,
                                      mock_self_update_class,
                                      basic_client_data,
                                      mock_self_update_rounds,
                                      success_request,
                                      mock_get_client_found
                                      ):
        response = lowball_app_mock_providers.post(self.ROUTE, json=success_request, headers=basic_header)
        print(response.json)
        assert response.status_code == 200
        assert response.json == basic_client_data.to_dict()
        lowball_app_mock_providers.application.auth_provider.client_self_update.assert_called_once()


class TestCreateClient:
    ROUTE = "/builtins/auth/clients/create"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.post(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    # fail no auth provider
    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.post(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no package class
    def test_attempt_fails_when_auth_provider_does_not_have_an_implemented_client_creation_package(
            self,
            lowball_app_mock_providers,
            admin1_token1_request_header,
            mock_lookup_token_filled,
    ):
        response = lowball_app_mock_providers.post(self.ROUTE, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 501
        assert "create_client_package_class" in response.json["message"]

    # fail bad input
    def test_attempt_fails_when_auth_provided_package_data_is_invalid(self,
                                                                      lowball_app_mock_providers,
                                                                      admin1_token1_request_header,
                                                                      mock_lookup_token_filled,
                                                                      mock_get_client_filled,
                                                                      expected_bad_package_data_error_response,
                                                                      does_not_match_update_package_request,
                                                                      mock_create_client_class
                                                                      ):
        response = lowball_app_mock_providers.post(self.ROUTE,
                                                   headers=admin1_token1_request_header,
                                                   json=does_not_match_update_package_request)

        assert response.status_code == 400
        assert response.json["message"] == expected_bad_package_data_error_response

    # success output
    def test_success_returns_expected_output(self,
                                             lowball_app_mock_providers,
                                             admin1_token1_request_header,
                                             mock_lookup_token_filled,
                                             basic_client_data,
                                             mock_create_client_rounds,
                                             success_request,
                                             mock_create_client_class
                                             ):
        response = lowball_app_mock_providers.post(self.ROUTE,
                                                   json=success_request,
                                                   headers=admin1_token1_request_header)
        print(response.json)
        assert response.status_code == 201
        assert response.json == basic_client_data.to_dict()
        lowball_app_mock_providers.application.auth_provider.create_client.assert_called_once()


class TestClientRegistration:
    ROUTE = "/builtins/auth/clients/register"

    # test no auth provider
    def test_self_registration_attempt_fails_with_no_auth_provider(
            self, lowball_app_no_auth_provider, expected_no_auth_provider_error_response):
        response = lowball_app_no_auth_provider.post(self.ROUTE)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # test no package class
    def test_self_registration_attempt_fails_with_no_defined_registration_package_class(self,
                                                                                        lowball_app_mock_providers):
        response = lowball_app_mock_providers.post(self.ROUTE, json={"some": "json"})

        assert response.status_code == 501
        assert response.json["message"] == "501 Not Implemented: client_registration_package_class not implemented"

    # test not implemented
    def test_self_registration_attempt_fails_with_self_registration_not_implemented(self,
                                                                                    lowball_app_mock_providers,
                                                                                    mock_self_register_class,
                                                                                    success_request):
        response = lowball_app_mock_providers.post(self.ROUTE, json=success_request)
        assert response.status_code == 501
        assert response.json["message"] == "501 Not Implemented: client_self_register not implemented"

    # test bad json data
    def test_self_registration_attempt_fails_with_invalid_json_data(self,
                                                                    lowball_app_mock_providers,
                                                                    mock_self_register_class,
                                                                    does_not_match_self_register_package_request,
                                                                    expected_bad_package_data_error_response):
        response = lowball_app_mock_providers.post(self.ROUTE, json=does_not_match_self_register_package_request)
        assert response.status_code == 400
        assert response.json["message"] == expected_bad_package_data_error_response

    def test_self_registration_success_flow(self, lowball_app_mock_providers, mock_self_register_class,
                                            success_request, mock_self_register_rounds, basic_client_data):
        response = lowball_app_mock_providers.post(self.ROUTE, json=success_request)
        print(response.json)
        assert response.status_code == 201
        assert response.json == basic_client_data.to_dict()
        lowball_app_mock_providers.application.auth_provider.client_self_register.assert_called_once()


class TestGetAllClients:

    ROUTE = "/builtins/auth/clients/all"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        response = lowball_app_no_db.get(self.ROUTE, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_gets_correct_client_with_role_filter_applied(self,
                                                          lowball_app_mock_providers,
                                                          admin1_token1_request_header,
                                                          mock_lookup_token_filled,
                                                          mock_list_tokens_filled,
                                                          mock_list_clients_filled,
                                                          get_clients_request_response_rounds,
                                                          mock_revoke_token
                                                          ):
        query, expected_clients = get_clients_request_response_rounds
        response = lowball_app_mock_providers.get(f"{self.ROUTE}{query}", headers=admin1_token1_request_header,
                                                     json={})
        assert response.status_code == 200
        assert isinstance(response.json, list)
        assert all(client.to_dict() in response.json for client in expected_clients)
        assert all(client_dict in [client.to_dict() for client in expected_clients] for client_dict in response.json)
        lowball_app_mock_providers.application.auth_provider.list_clients.assert_called_once()

    def test_gets_all_clients_when_no_filters_applied(self, lowball_app_mock_providers,
                                                      mock_lookup_token_filled,
                                                      token_db, admin1_token1_request_header,
                                                      mock_list_tokens_filled,
                                                      mock_list_clients_filled,
                                                      client_db):

        response = lowball_app_mock_providers.get(self.ROUTE, headers=admin1_token1_request_header)

        assert response.status_code == 200
        print(response.json)
        assert isinstance(response.json, list)
        assert all(client.to_dict() in response.json for client in client_db.values())
        assert all(client_dict in [client.to_dict() for client in client_db.values()] for client_dict in response.json)
        lowball_app_mock_providers.application.auth_provider.list_clients.assert_called_once()

    def test_get_clients_fails_when_invalid_types_returned_from_auth_provider(self, mock_list_clients_returns_bad_values,
                                                                        lowball_app_mock_providers,
                                                                        mock_lookup_token_filled,
                                                                        admin1_token1_request_header
                                                                        ):
        normal_response = lowball_app_mock_providers.get(self.ROUTE, headers=admin1_token1_request_header)

        assert normal_response.status_code == 500
        assert "auth_provider.list_clients did not return a list of client data objects as expected" in normal_response.json["message"]
        lowball_app_mock_providers.application.auth_provider.list_clients.assert_called_once()


class TestGetClient:

    ROUTE = "/builtins/auth/clients/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.get(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.get(route, headers=not_authenticated_or_token_expired_header,
                                                  json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers):
        response = lowball_app_mock_providers.get(self.ROUTE, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.get(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    def test_not_found_if_client_not_found(self,
                                           lowball_app_mock_providers,
                                           admin1_token1_request_header,
                                           client_id_normal2,
                                           mock_lookup_token_filled,
                                           mock_get_client_filled
                                           ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.get(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    def test_failure_if_no_auth_provider(self,
                                         lowball_app_no_auth_provider,
                                         expected_no_auth_provider_error_response,
                                         admin1_token1_request_header,
                                         mock_lookup_token_filled,
                                         client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_no_auth_provider.get(route, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    def test_success_outputs_for_client_data(self,
                                             lowball_app_mock_providers,
                                             mock_lookup_token_filled,
                                             mock_get_client_filled,
                                             get_client_request_response_rounds
                                             ):
        header, client_id, expected_response = get_client_request_response_rounds
        route = self.ROUTE.format(client_id)

        response = lowball_app_mock_providers.get(route, headers=header)
        print(response.json)
        assert response.status_code == 200
        assert response.json == expected_response
        assert call(client_id) in lowball_app_mock_providers.application.auth_provider.get_client.mock_calls


class TestUpdateClient:

    ROUTE = "/builtins/auth/clients/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.post(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=not_authenticated_or_token_expired_header,
                                                    json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=non_admin_headers,
                                                    json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    # fail no auth provider
    def test_failure_when_no_auth_provider_initialized(self, lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled,
                                                       client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_no_auth_provider.post(route, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_attempt_fails_when_client_does_not_exist(self,
                                                      lowball_app_mock_providers,
                                                      admin1_token1_request_header,
                                                      client_id_normal2,
                                                      mock_lookup_token_filled,
                                                      mock_get_client_filled
                                                      ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    def test_attempt_fails_when_no_update_package_defined(self,
                                                          lowball_app_mock_providers,
                                                          admin1_token1_request_header,
                                                          client_id_normal1,
                                                          mock_lookup_token_filled,
                                                          mock_get_client_filled
                                                          ):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 501
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        assert "update_client_package_class" in response.json["message"]

    def test_attempt_fails_when_invalid_data_input(self,
                                                   lowball_app_mock_providers,
                                                   admin1_token1_request_header,
                                                   mock_lookup_token_filled,
                                                   mock_get_client_filled,
                                                   client_id_normal1,
                                                   expected_bad_package_data_error_response,
                                                   does_not_match_update_package_request,
                                                   mock_update_client_class
                                                   ):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_mock_providers.post(route,
                                                    headers=admin1_token1_request_header,
                                                    json=does_not_match_update_package_request)
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        assert response.status_code == 400
        assert response.json["message"] == expected_bad_package_data_error_response

    # success flow multiple output
    def test_attempt_successful_and_expected_output(self,
                                                    lowball_app_mock_providers,
                                                    admin1_token1_request_header,
                                                    mock_lookup_token_filled,
                                                    mock_get_client_filled,
                                                    client_id_normal1,
                                                    mock_self_update_class,
                                                    basic_client_data,
                                                    mock_update_client_rounds,
                                                    success_request,
                                                    mock_update_client_class
                                                    ):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_mock_providers.post(route,
                                                    json=success_request,
                                                    headers=admin1_token1_request_header)
        print(response.json)
        assert response.status_code == 200
        assert response.json == basic_client_data.to_dict()
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.update_client.assert_called_once()


class TestDeleteClient:
    ROUTE = "/builtins/auth/clients/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.delete(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_mock_providers.delete(route, headers=not_authenticated_or_token_expired_header,
                                                     json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.delete(route, headers=non_admin_headers,
                                                     json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self, lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.delete(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    # success route
    def test_calls_delete_successfully(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal1,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled,
                                       mock_delete_client_simple
                                       ):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header, json={})
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.delete_client.assert_called_once_with(client_id_normal1)


class TestEnableClient:
    ROUTE = "/builtins/auth/clients/{}/enable"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.post(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self,
                                                                   lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.post(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    # success route
    def test_calls_enable_successfully(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal1,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled,
                                       mock_enable_client_simple
                                       ):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.enable_client.assert_called_once_with(client_id_normal1)

class TestDisableClient:

    ROUTE = "/builtins/auth/clients/{}/disable"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.post(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_mock_providers.post(route, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled):
        response = lowball_app_no_auth_provider.post(self.ROUTE, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    # success route
    def test_calls_disable_successfully(self,
                                        lowball_app_mock_providers,
                                        admin1_token1_request_header,
                                        client_id_normal1,
                                        mock_lookup_token_filled,
                                        mock_get_client_filled,
                                        mock_disable_client_simple
                                        ):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.disable_client.assert_called_once_with(
            client_id_normal1)


class TestRemoveClientRoles:

    ROUTE = "/builtins/auth/clients/{}/roles"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid")
        response = lowball_app_no_db.delete(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_mock_providers.delete(route, headers=not_authenticated_or_token_expired_header,
                                                   json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.delete(route, headers=non_admin_headers,
                                                   json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled,
                                                       client_id_normal1):
        route = self.ROUTE.format(client_id_normal1)

        response = lowball_app_no_auth_provider.delete(route, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    def test_calls_delete_roles_with_client_roles(self,
                                                  lowball_app_mock_providers,
                                                  admin1_token1_request_header,
                                                  client_id_normal1,
                                                  client_data_normal1,
                                                  mock_get_client_filled,
                                                  mock_lookup_token_filled,
                                                  mock_delete_roles
                                                  ):

        route = self.ROUTE.format(client_id_normal1)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header)

        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.delete_roles.assert_called_once_with(client_id_normal1, client_data_normal1.roles)
    
    
class TestRemoveClientRole:
    
    ROUTE = "/builtins/auth/clients/{}/roles/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid", "anyrole")
        response = lowball_app_no_db.delete(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")

        response = lowball_app_mock_providers.delete(route, headers=not_authenticated_or_token_expired_header,
                                                     json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")
        response = lowball_app_mock_providers.delete(route, headers=non_admin_headers,
                                                     json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled,
                                                       client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")

        response = lowball_app_no_auth_provider.delete(route, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2, "anyrole")
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)
    
    def test_calls_delete_roles_with_role(self,
                                          lowball_app_mock_providers,
                                          admin1_token1_request_header,
                                          client_id_normal1,
                                          mock_lookup_token_filled,
                                          mock_get_client_filled,
                                          base_role1,
                                          mock_delete_roles
                                          ):
        role = base_role1[0]
        route = self.ROUTE.format(client_id_normal1, role)
        response = lowball_app_mock_providers.delete(route, headers=admin1_token1_request_header)
        
        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.delete_roles.assert_called_once_with(client_id_normal1, base_role1)


class TestAddClientRole:
    ROUTE = "/builtins/auth/clients/{}/roles/{}"

    def test_fails_with_no_auth_database(self, lowball_app_no_db, expected_no_auth_db_response, basic_header):
        route = self.ROUTE.format("anyclientid", "anyrole")
        response = lowball_app_no_db.post(route, headers=basic_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_db_response

    # assert authenticated
    def test_attempt_fails_when_not_authenticated_or_token_expired(self, lowball_app_mock_providers,
                                                                   not_authenticated_or_token_expired_header,
                                                                   client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")

        response = lowball_app_mock_providers.post(route, headers=not_authenticated_or_token_expired_header,
                                                     json={})
        assert response.status_code != 200
        assert any([
            "Token Has Expired" in response.json["message"],
            "No token provided" in response.json["message"],
            "Token Is Invalid" in response.json["message"]
        ])

    # assert authenticated admin
    def test_attempt_fails_when_authenticated_but_not_admin(self, lowball_app_mock_providers,
                                                            non_admin_headers, client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")
        response = lowball_app_mock_providers.post(route, headers=non_admin_headers,
                                                     json={})
        assert response.status_code == 401
        assert "Unauthorized" in response.json["message"]

    def test_failure_when_no_auth_provider_initialized(self,
                                                       lowball_app_no_auth_provider,
                                                       expected_no_auth_provider_error_response,
                                                       admin1_token1_request_header,
                                                       mock_lookup_token_filled,
                                                       client_id_normal1):
        route = self.ROUTE.format(client_id_normal1, "anyrole")

        response = lowball_app_no_auth_provider.post(route, headers=admin1_token1_request_header)
        assert response.status_code == 503
        assert response.json["message"] == expected_no_auth_provider_error_response

    # fail no client
    def test_not_found_when_not_client(self,
                                       lowball_app_mock_providers,
                                       admin1_token1_request_header,
                                       client_id_normal2,
                                       mock_lookup_token_filled,
                                       mock_get_client_filled
                                       ):
        route = self.ROUTE.format(client_id_normal2, "anyrole")
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header, json={})
        print(response.json)
        assert response.status_code == 404
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal2)

    def test_calls_delete_roles_with_role(self,
                                          lowball_app_mock_providers,
                                          admin1_token1_request_header,
                                          client_id_normal1,
                                          mock_lookup_token_filled,
                                          mock_get_client_filled,
                                          base_role1,
                                          mock_add_roles
                                          ):
        role = base_role1[0]
        route = self.ROUTE.format(client_id_normal1, role)
        response = lowball_app_mock_providers.post(route, headers=admin1_token1_request_header)

        assert response.status_code == 204
        lowball_app_mock_providers.application.auth_provider.get_client.assert_called_once_with(client_id_normal1)
        lowball_app_mock_providers.application.auth_provider.add_roles.assert_called_once_with(client_id_normal1,
                                                                                                  base_role1)

