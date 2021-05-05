
import pytest
from unittest.mock import mock_open, patch

from lowball.models.config_models import *


class TestMetaConfig:
    @pytest.mark.parametrize("name, base_route, description, tags", [
        (1, "/base/route", "description", ["list", "of", "tags"]),
        ("APP_NAME", 1, "description", ["list", "of", "tags"]),
        ("APP_NAME", "/base/route", 1, ["list", "of", "tags"]),
        ("APP_NAME", "/base/route", "description", 1)
    ])
    def test_init_raises_type_error_with_incorrect_types_passed_in(self, name, base_route, description, tags):
        with pytest.raises(TypeError):
            MetaConfig(name=name, base_route=base_route, description=description, tags=tags)

    def test_init_raises_value_error_with_invalid_tag_values(self, invalid_tags):
        with pytest.raises(ValueError):
            MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=invalid_tags)

    def test_init_raised_value_error_with_invalid_base_route_values(self, invalid_base_route):
        with pytest.raises(ValueError):
            MetaConfig(name="APP_NAME", base_route=invalid_base_route, description="description", tags=["tag", "list"])

    def test_to_dict_method_formats_data_properly(self):
        test_meta = MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"])
        assert test_meta.to_dict() == {"name": "APP_NAME", "base_route": "/base/route", "description": "description", "tags": ["tag", "list"]}

    def test_tags_can_be_set_to_none_on_init(self):
        test_meta = MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=None)
        assert test_meta.to_dict() == {"name": "APP_NAME", "base_route": "/base/route", "description": "description",
                                       "tags": []}


class TestAuthenticationConfig:
    @pytest.mark.parametrize("default_token_life, max_token_life, secret", [
        ("not an int", 31536000, "supersecrettokensecret"),
        (1800, "not an int", "supersecrettokensecret"),
        (1800, 31536000, 1),
    ])
    def test_init_raises_type_error_with_incorrect_types_passed_in(self, default_token_life, max_token_life, secret):
        with pytest.raises(TypeError):
            AuthenticationConfig(default_token_life=default_token_life, max_token_life=max_token_life,
                                 token_secret=secret)

    def test_setting_default_token_life_to_bad_value_after_init_raises_type_error(self, default_token_life,
                                                                                  max_token_life, token_secret,
                                                                                  not_like_int):
        test_auth = AuthenticationConfig(default_token_life=default_token_life, max_token_life=max_token_life,
                                           token_secret=token_secret)
        with pytest.raises(TypeError):
            test_auth.default_token_life = not_like_int

    def test_setting_max_token_life_to_bad_value_after_init_raises_type_error(self, default_token_life, max_token_life,
                                                                              token_secret, not_like_int):
        test_auth = AuthenticationConfig(default_token_life=default_token_life, max_token_life=max_token_life,
                                           token_secret=token_secret)
        with pytest.raises(TypeError):
            test_auth.max_token_life = not_like_int

    def test_setting_token_secret_to_bad_value_after_init_raises_type_error(self, default_token_life, max_token_life,
                                                                            token_secret, not_string):
        test_auth = AuthenticationConfig(default_token_life=default_token_life, max_token_life=max_token_life,
                                           token_secret=token_secret)
        with pytest.raises(TypeError):
            test_auth.token_secret = not_string

    def test_to_dict_method_formats_data_properly(self, default_token_life, max_token_life, token_secret,
                                                  auth_config_dict):
        test_auth = AuthenticationConfig(default_token_life=default_token_life, max_token_life=max_token_life,
                                           token_secret=token_secret)
        assert test_auth.to_dict() == auth_config_dict


class TestConfig:
    @pytest.mark.parametrize("meta, authentication, application, auth_provider, auth_db, logging", [
        (1, AuthenticationConfig(default_token_life=1800, max_token_life=3600, token_secret="supersecret", ignore_auth=False), {}, {}, {}, {}),
        (MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"]), 1, {}, {}, {}, {}),
        (MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"]), AuthenticationConfig(default_token_life=1800, max_token_life=3600, token_secret="supersecret"), 1, {}, {}, {}),
        (MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"]), AuthenticationConfig(default_token_life=1800, max_token_life=3600, token_secret="supersecret"), {}, 1, {}, {}),
        (MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"]), AuthenticationConfig(default_token_life=1800, max_token_life=3600, token_secret="supersecret"), {}, {}, 1, {}),
        (MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"]), AuthenticationConfig(default_token_life=1800, max_token_life=3600, token_secret="supersecret"), {}, {}, {}, 1)
    ])
    def test_init_raises_type_error_with_incorrect_types_passed_in(self, meta, authentication, application,
                                                                   auth_provider, auth_db, logging):
        with pytest.raises(TypeError):
            Config(meta=meta, authentication=authentication, application=application, auth_provider=auth_provider,
                   auth_db=auth_db, logging=logging)

    def test_to_dict_returns_proper_data(self, auth_db_config, auth_provider_config, logging_config, application_config,
                                         meta_config, authentication_config, config_dict):
        test_config = Config(meta=meta_config, authentication=authentication_config, application=application_config,
                               auth_provider=auth_provider_config, auth_db=auth_db_config, logging=logging_config)
        assert test_config.to_dict() == config_dict

    def test_attribute_access_returns_proper_data_type(self, auth_db_config, auth_provider_config, logging_config,
                                                       application_config, meta_config, authentication_config):
        test_config = Config(meta=meta_config, authentication=authentication_config, application=application_config,
                               auth_provider=auth_provider_config, auth_db=auth_db_config, logging=logging_config)

        assert isinstance(test_config.meta, MetaConfig)
        assert isinstance(test_config.authentication, AuthenticationConfig)


class TestLoadingConfig:
    def test_loading_config_from_object_raises_type_error_when_not_dict_passed_in(self, not_dict):
        with pytest.raises(TypeError):
            config_from_object(not_dict)

    def test_loading_config_from_object_returns_proper_config_object(self, json_config_object):
        test_config = config_from_object(json_config_object)
        assert isinstance(test_config, Config)
        assert test_config.meta.to_dict() == json_config_object["meta"]
        assert test_config.application == json_config_object["application"]
        assert test_config.auth_provider == json_config_object["auth_provider"]
        assert test_config.auth_db == json_config_object["auth_db"]
        assert test_config.logging == json_config_object["logging"]

    def test_loading_config_from_file_file_raises_type_error_when_pathlike_object_not_passed_in(self, not_pathlike):
        with pytest.raises(TypeError):
            config_from_file(not_pathlike)

    def test_loading_config_from_json_file_returns_proper_config_object(self, json_config_path, json_file_read_data, config_dict):
        mocked_open_func = mock_open(read_data=json_file_read_data)

        with patch("lowball.models.config_models.config.open", mocked_open_func):
            test_config = config_from_file(json_config_path)

        mocked_open_func.assert_any_call(json_config_path, "r")
        assert isinstance(test_config, Config)
        assert config_dict == test_config.to_dict()


    def test_loading_config_from_yaml_file_returns_proper_config_object(self, yaml_config_path, yaml_file_read_data, config_dict):
        mocked_open_func = mock_open(read_data=yaml_file_read_data)

        with patch("lowball.models.config_models.config.open", mocked_open_func):
            test_config = config_from_file(yaml_config_path)

        mocked_open_func.assert_any_call(yaml_config_path, "r")
        assert isinstance(test_config, Config)
        assert config_dict == test_config.to_dict()
