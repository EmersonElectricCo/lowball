class TestGetStatusRoute:

    ROUTE = "/builtins/status"

    def test_auth_provider_initialized_exception_auth_db_none_produces_proper_results(self, lowball_app_no_db,
                                                                                      mock_initialized_exception):
        data = lowball_app_no_db.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_no_db.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is False
        assert data.get_json(force=True)["auth_provider_initialized"] is False

    def test_auth_provider_initialized_non_bool_auth_db_none_produces_proper_results(self, lowball_app_no_db,
                                                                                     mock_initialized_non_bool):
        data = lowball_app_no_db.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_no_db.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is False
        assert data.get_json(force=True)["auth_provider_initialized"] is False

    def test_auth_provider_initialized_bool_auth_db_none_produces_proper_results(self, lowball_app_no_db,
                                                                                 mock_initialized_bool):
        data = lowball_app_no_db.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_no_db.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is False
        assert data.get_json(force=True)["auth_provider_initialized"] is mock_initialized_bool

    def test_auth_provider_initialized_exception_auth_db_not_none_produces_proper_results(self, lowball_app_no_auth_provider,
                                                                                          mock_initialized_exception):
        data = lowball_app_no_auth_provider.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_no_auth_provider.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is True
        assert data.get_json(force=True)["auth_provider_initialized"] is False

    def test_auth_provider_initialized_non_bool_auth_db_not_none_produces_proper_results(self, lowball_app_no_auth_provider,
                                                                                         mock_initialized_non_bool):
        data = lowball_app_no_auth_provider.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_no_auth_provider.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is True
        assert data.get_json(force=True)["auth_provider_initialized"] is False

    def test_auth_provider_initialized_bool_auth_db_not_none_produces_proper_results(self, lowball_app_mock_providers,
                                                                                     mock_initialized_bool):
        data = lowball_app_mock_providers.get(self.ROUTE)
        assert data.status_code == 200
        assert data.get_json(force=True)["name"] == lowball_app_mock_providers.application.lowball_config.meta.name
        assert data.get_json(force=True)["auth_db_initialized"] is True
        assert data.get_json(force=True)["auth_provider_initialized"] is mock_initialized_bool
