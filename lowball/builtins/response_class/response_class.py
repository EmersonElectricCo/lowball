from flask import Response, jsonify


class LowballResponse(Response):
    """
    Child class of Flask Response object used to create Default JSON Responses
    """

    @classmethod
    def force_type(cls, return_value, environ=None):
        """Force all native Python types into proper responses.

        Extension of Parent class force_type to intercept and convert dict objects to json compliant objects

        :param return_value: data that is being returned from the view function.
        :type environ: dict
        :param environ: @super
        :rtype: LowballResponse
        :return: Response object
        """
        # These types are JSON-compliant, just pass them to jsonify
        if isinstance(return_value, (dict, list, tuple)):
            return jsonify(return_value)

        # These types need to be converted to lists before being jsonified
        elif isinstance(return_value, (set, frozenset, range)):
            return jsonify(list(return_value))
        
        # Convert these types to strings and set them as response data
        elif isinstance(return_value, (int, float, complex)):
            return LowballResponse(response=str(return_value))

        # Convert memoryview to bytes and set as response data
        elif isinstance(return_value, memoryview):
            return LowballResponse(response=bytes(return_value))

        # For all other return types (this will only ever be Response objects, or custom objects),
        # pass along data to base class `force_type`
        else:
            return super(LowballResponse, cls).force_type(response=return_value, environ=environ)
