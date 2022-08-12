import json
import logging

import werkzeug.wrappers

from odoo import http
from odoo.addons.bista_wms_api.common import invalid_response, valid_response
from odoo.exceptions import AccessDenied, AccessError
from odoo.http import request

_logger = logging.getLogger(__name__)


class AccessToken(http.Controller):
    """."""

    @http.route(["/api/auth/token"], methods=["DELETE"], type="http", auth="none", csrf=False)
    def delete(self, **post):
        """Delete a given token"""
        token = request.env["api.access_token"]
        access_token = post.get("access_token")

        access_token = token.search([("token", "=", access_token)], limit=1)
        if not access_token:
            error = "Access token is missing in the request header or invalid token was provided"
            return invalid_response(status=200, message=error, typ="")
        for token in access_token:
            token.unlink()
        # Successful response:
        return valid_response([{"message": "access token %s successfully deleted" % (access_token,), "delete": True}])
