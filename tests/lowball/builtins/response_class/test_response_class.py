import json

from flask import Response

from lowball.builtins.response_class import LowballResponse


class TestLowballResponseClassForceType:
    def test_forces_type_properly_for_dicts(self, dict_return_value, client_with_response_class, expected_dict_return):
        forced_response = LowballResponse.force_type(dict_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == expected_dict_return

    def test_forces_type_properly_for_sequence_types(self, sequence_return_value, client_with_response_class):
        forced_response = LowballResponse.force_type(sequence_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == b'[1,2,3]\n'
    
    def test_forces_type_properly_for_ints(self, int_return_value):
        forced_response = LowballResponse.force_type(int_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == str(int_return_value).encode()
        
    def test_forces_type_properly_for_floats(self, float_return_value):
        forced_response = LowballResponse.force_type(float_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == str(float_return_value).encode()
        
    def test_forces_type_properly_for_complex_type(self, complex_return_value):
        forced_response = LowballResponse.force_type(complex_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == str(complex_return_value).encode()
    
    def test_forces_type_properly_for_memoryviews(self, memoryview_return_value):
        forced_response = LowballResponse.force_type(memoryview_return_value)
        assert isinstance(forced_response, LowballResponse)
        assert forced_response.data == bytes(memoryview_return_value)

    def test_passes_response_object_to_super(self, response_return_value, mocked_response_force_type):
        forced_response = LowballResponse.force_type(response_return_value)
        assert isinstance(forced_response, LowballResponse)
        Response.force_type.assert_called_once_with(response=response_return_value, environ=None)
