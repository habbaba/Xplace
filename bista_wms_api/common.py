import json
import werkzeug.wrappers

import logging
import datetime

from odoo.tools import date_utils
from odoo.http import JsonRequest, Response

_logger = logging.getLogger(__name__)


def default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, bytes):
        return str(o)


def valid_response(data, status=200):
    """Valid Response
    This will be return when the http request was successfully processed."""
    data = {
        "count": len(data) if not isinstance(data, str) else 1,
        "status": True,
        "data": data
    }
    return werkzeug.wrappers.Response(
        status=status, content_type="application/json; charset=utf-8", response=json.dumps(data, default=default),
    )


def invalid_response(typ, message=None, status=200):
    """Invalid Response

    This will be the return value whenever the server runs into an error
    either from the client or the server.

    :param str typ: type of error,
    :param str message: message that will be displayed to the user,
    :param int status: integer HTTP status code that will be sent in response body & header.
    """
    # return json.dumps({})
    return werkzeug.wrappers.Response(
        status=status,
        content_type="application/json; charset=utf-8",
        response=json.dumps(
            {
                "code": status,
                "message": str(message) if str(message) else "wrong arguments (missing validation)",
                "status": False
            },
            default=datetime.datetime.isoformat,
        ),
    )


def extract_arguments(limit="80", offset=0, order="id", domain="", fields=[]):
    """Parse additional data  sent along request."""
    limit = int(limit)
    expresions = []
    if domain:
        expresions = [tuple(preg.replace(":", ",").split(",")) for preg in domain.split(",")]
        expresions = json.dumps(expresions)
        expresions = json.loads(expresions, parse_int=True)
    if fields:
        fields = fields.split(",")

    if offset:
        offset = int(offset)
    return [expresions, fields, offset, limit, order]


def _json_response(self, result=None, error=None):
    response = {
        'jsonrpc': '2.0',
        'id': self.jsonrequest.get('id')
    }
    if error is not None:
        response['error'] = error
    if result is not None:
        # Start of customization
        if isinstance(result, werkzeug.wrappers.Response):
            return result
        try:
            rest_result = json.loads(result)
            if isinstance(rest_result, dict) and 'rest_api_flag' in rest_result and rest_result.get('rest_api_flag'):
                response.update(rest_result)
                response['result'] = None
            else:
                response['result'] = result
        except Exception as e:
            response['result'] = result
        # End of customization
        # response['result'] = result

    mime = 'application/json'
    body = json.dumps(response, default=date_utils.json_default)

    return Response(
        body, status=error and error.pop('http_status', 200) or 200,
        headers=[('Content-Type', mime), ('Content-Length', len(body))]
    )


setattr(JsonRequest, '_json_response', _json_response)  # overwrite the method


def convert_data_str(data):

    # Convert any data that is NOT [str, dictionary, array, tuple or bool] TO str
    if type(data) not in [str, dict, list, tuple, bool]:
        data = str(data)

    # Convert dictionary values that are NOT str TO str
    elif isinstance(data, dict):
        for key in data:
            if not isinstance(data[key], str) and not isinstance(data[key], list):
                data[key] = str(data[key])

            if isinstance(data[key], list):
                for index, elem in enumerate(data[key]):
                    if not isinstance(elem, str):
                        data[key][index] = str(elem)

    # Convert list elements that are NOT str TO str
    elif isinstance(data, list):
        for index, elem in enumerate(data):
            if not isinstance(elem, str):
                data[index] = str(elem)

    return data
