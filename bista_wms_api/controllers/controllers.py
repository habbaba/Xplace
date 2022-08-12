# -*- coding: utf-8 -*-
import json
import logging
import functools

from odoo import http
from odoo.exceptions import AccessDenied, AccessError
from odoo.http import request, content_disposition, serialize_exception as _serialize_exception
from odoo.addons.bista_wms_api.common import invalid_response, valid_response, convert_data_str
from odoo.tools.safe_eval import safe_eval, time
from odoo.tools import html_escape
from odoo.addons.web.controllers.main import ReportController
from datetime import datetime

import werkzeug.wrappers
from werkzeug.urls import url_encode, url_decode, iri_to_uri

import werkzeug.wrappers

_logger = logging.getLogger(__name__)


def validate_token(func):
    """."""

    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        """."""
        access_token = request.httprequest.headers.get("access_token")
        if not access_token:
            return invalid_response("access_token_not_found", "missing access token in request header", 200)
        access_token_data = (
            request.env["api.access_token"].sudo().search([("token", "=", access_token)], order="id DESC", limit=1)
        )

        if access_token_data.find_one_or_create_token(user_id=access_token_data.user_id.id) != access_token:
            return invalid_response("access_token", "token seems to have expired or invalid", 200)

        request.session.uid = access_token_data.user_id.id
        request.uid = access_token_data.user_id.id
        return func(self, *args, **kwargs)

    return wrap


class BistaWmsApi(http.Controller):
    """Warehouse Management System Controller"""

    @http.route("/api/auth/login", methods=["GET", "POST"], type="json", auth="none", csrf=False)
    def auth_login(self, **post):
        """The token URL to be used for getting the access_token.

        str post[db]: db of the system, in which the user logs in to.

        str post[login]: username of the user

        str post[password]: password of the user

        :param list[str] str post: **post must contain db, login and password.
        :returns: https response
            if failed error message in the body in json format and
            if successful user's details with the access_token.
        """
        _token = request.env["api.access_token"]
        params = ["db", "login", "password"]
        req_data = json.loads(request.httprequest.data.decode())  # convert the bytes format to dict format
        req_params = {key: req_data.get(key) for key in params if req_data.get(key)}
        db, username, password = (
            req_params.get("db"),
            req_params.get("login"),
            req_params.get("password"),
        )
        _credentials_includes_in_body = all([db, username, password])
        if not _credentials_includes_in_body:
            # The request post body is empty the credentials maybe passed via the headers.
            headers = request.httprequest.headers
            db = headers.get("db")
            username = headers.get("login")
            password = headers.get("password")
            _credentials_includes_in_headers = all([db, username, password])
            if not _credentials_includes_in_headers:
                # Empty 'db' or 'username' or 'password:
                return invalid_response(
                    "missing error", "Either of the following are missing [db, username,password]", 200,
                )
        # Login in odoo database:
        session_info = []
        try:
            request.session.authenticate(db, username, password)
            session_info = request.env['ir.http'].session_info().get('server_version_info', [])
        except AccessError as aee:
            return invalid_response("Access error", "Error: %s" % aee.name)
        except AccessDenied as ade:
            return invalid_response("Access denied", "Login, password or db invalid")
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid {}".format(e)
            error = "invalid_database"
            _logger.error(info)
            return invalid_response(typ=error, message=info, status=200)

        uid = request.session.uid
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(status=200, typ=error, message=info)

        # Generate tokens
        access_token = _token.find_one_or_create_token(user_id=uid, create=True)

        data = {
            "uid": uid,
            "user_context": convert_data_str(request.session.get_context()) if uid else {},
            "company_id": request.env.user.company_id.id if uid else None,
            "company_ids": convert_data_str(request.env.user.company_ids.ids) if uid else None,
            "partner_id": request.env.user.partner_id.id,
            "access_token": access_token,
            "company_name": request.env.user.company_name,
            # "currency": request.env.user.currency_id.name,
            "country": request.env.user.country_id.name,
            "contact_address": request.env.user.contact_address,
            # "customer_rank": request.env.user.customer_rank,
            "session_info": session_info,
        }
        response_data = {
            **{
                "status": True,
                "count": len(data) if not isinstance(data, str) else 1,
            },
            **data
        }
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(response_data)
        )

    @validate_token
    @http.route("/api/get_product_list", type="http", auth="none", methods=["GET"], csrf=False)
    def get_product_list(self, **payload):
        """ NOTE: DEPRECATED API for now, Gets the specific time frame from request and returns product details."""

        product_template_obj = request.env['product.template']

        payload_data = payload

        product_list_data = []
        response_data = {'rest_api_flag': True}

        domain = []

        if 'create_date' in payload_data:
            if payload_data['create_date']:
                domain.append(('create_date', '>=', payload_data['create_date']))

        if 'write_date' in payload_data:
            if payload_data['write_date']:
                domain.append(('write_date', '>=', payload_data['write_date']))

        products = product_template_obj.sudo().search(domain, order="id ASC")

        if products:
            for product in products:
                product_list_data.append({
                    'id': product.id,
                    'name': product.name,
                    'list_price': product.list_price,
                    'uom_id': [str(product.uom_id.id or ""), product.uom_id.name or ""],
                    'create_uid': [str(product.create_uid.id or ""), product.create_uid.name or ""],
                    'create_date': product.create_date,
                    'write_uid': [str(product.write_uid.id or ""), product.write_uid.name or ""],
                    'write_date': product.write_date,
                })
            response_data.update({'data': product_list_data})

            if response_data:
                # return valid_response(response_data)
                return valid_response(product_list_data)
            else:
                return invalid_response('not_found', 'Product data not found.')
        else:
            return invalid_response('not_found', 'No product record found.')

    @staticmethod
    def _get_picking_fields(self):
        stock_picking_type_obj = request.env['stock.picking.type'].search([])
        res = []
        # domains = {
        #     # 'count_picking_draft': [('state', '=', 'draft')],
        #     # 'count_picking_waiting': [('state', 'in', ('confirmed', 'waiting'))],
        #     'count_picking_ready': [('state', '=', 'assigned')],
        #     # 'count_picking': [('state', 'in', ('assigned', 'waiting', 'confirmed'))],
        #     # 'count_picking_late': [('scheduled_date', '<', time.strftime(DEFAULT_SERVER_DATETIME_FORMAT)),
        #     #                        ('state', 'in', ('assigned', 'waiting', 'confirmed'))],
        #     # 'count_picking_backorders': [('backorder_id', '!=', False),
        #     #                              ('state', 'in', ('confirmed', 'assigned', 'waiting'))],
        # }
        # for field in domains:
        #     data = request.env['stock.picking'].read_group(domains[field] + [
        #         ('company_id', '=', request.env.user.company_id.id),
        #         ('state', 'not in', ('done', 'cancel')),
        #         ('picking_type_id', 'in', stock_picking_type_obj.ids)
        #     ], ['picking_type_id'], ['picking_type_id'])
        #     count = {
        #         # stock_picking_type_obj.browse(x['picking_type_id'][0]).name.lower().replace(" ", "_"): x['picking_type_id_count']
        #         x['picking_type_id'][0]: x['picking_type_id_count'] for x in data if x['picking_type_id']
        #     }
        #     # res.append(count)
        #     for record in stock_picking_type_obj.search([('company_id', '=', request.env.user.company_id.id)],
        #                                                 order='sequence'):
        #         # record[field] = count.get(record.id, 0)
        #         res.append({
        #             "id": record.id,
        #             "name": record.name,
        #             "code": record.code,
        #             "qty": count.get(record.id, 0),
        #             "sequence": record.sequence,
        #             # record.name.lower().replace(" ", "_"): count.get(record.id, 0)
        #         })

        # NOTE: New code for returning Ready, Waiting & Late pickings.
        for record in stock_picking_type_obj.search([('company_id', '=', request.env.user.company_id.id)],
                                                    order='sequence'):
            res.append({
                "id": record.id,
                "name": record.name,
                "code": record.code,
                "sequence": record.sequence,
                "count_picking_draft": record.count_picking_draft,
                "count_picking_waiting": record.count_picking_waiting,
                "count_picking_ready": record.count_picking_ready,
                "count_picking_late": record.count_picking_late,
                "count_picking": record.count_picking,
                "count_picking_backorders": record.count_picking_backorders,
            })
        return res

    @validate_token
    @http.route("/api/get_dashboard_today_stock_and_receipt", type="http", auth="none", methods=["GET"], csrf=False)
    def get_dashboard_today_stock_and_receipt(self, **payload):
        """Get Stock, Transfers & Receipt for Current Date for Dashboard."""

        _logger.info("/api/get_dashboard_today_stock_and_receipt payload: %s", payload)

        try:
            product_template_obj = request.env['product.template'].search([('type', 'in', ['consu', 'product'])])

            res = {}

            sum_qty_available = 0
            # sum_virtual_available = 0
            sum_incoming_qty = 0
            sum_outgoing_qty = 0

            domain = [
                ('date', '>=', datetime.now().strftime('%Y-%m-%d 00:00:00')),
                ('date', '<=', datetime.now().strftime('%Y-%m-%d 23:59:59'))
            ]

            # stock_move_line_obj = request.env['stock.move.line']
            stock_move_line_objs = request.env['stock.move.line'].search(domain)

            # sum_incoming_qty = stock_move_line_obj.search_count(
            #     domain + [('picking_id.picking_type_id.code', '=', 'incoming')]
            # )
            # sum_outgoing_qty = stock_move_line_obj.search_count(
            #     domain + [('picking_id.picking_type_id.code', '=', 'outgoing')]
            # )

            for stock_move_line_obj in stock_move_line_objs:
                if stock_move_line_obj.picking_id.picking_type_id.code == "incoming":
                    sum_incoming_qty += stock_move_line_obj.qty_done
                elif stock_move_line_obj.picking_id.picking_type_id.code == "outgoing":
                    sum_outgoing_qty += stock_move_line_obj.qty_done

            for prod_temp in product_template_obj:
                sum_qty_available += prod_temp.qty_available
                # sum_virtual_available += prod_temp.virtual_available
                # sum_incoming_qty += prod_temp.incoming_qty
                # sum_outgoing_qty += prod_temp.outgoing_qty

            res.update({
                'sum_qty_available': sum_qty_available,
                # 'sum_virtual_available': sum_virtual_available,
                'sum_incoming_qty': sum_incoming_qty,
                'sum_outgoing_qty': sum_outgoing_qty
            })

            res.update({"to_process_count": self._get_picking_fields(self)})

            return valid_response(res)
        except Exception as e:
            _logger.exception("Error while getting stock, transfers & receipt of dashboard for payload: %s", payload)
            error_msg = 'Error while getting stock, transfers & receipt of dashboard.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route("/api/get_picking_move_ids", type="http", auth="none", methods=["GET"], csrf=False)
    def get_picking_move_ids(self, **payload):
        """
            NOTE: DEPRECATED API for now, might be used later on.
            Gets the name of a stock_picking record from request and
            returns that specific stock_picking record's operations details.
            @:param barcode
            @:returns only the stock.move records related to the stock.picking record.
        """

        response_data = {}
        payload_data = payload

        if 'barcode' in payload_data:
            if payload_data['barcode']:
                stock_picking_obj = request.env['stock.picking'].sudo().search(
                    [('name', '=', payload_data.get('barcode'))])
                if stock_picking_obj:
                    move_ids = stock_picking_obj.move_ids_without_package.sudo().read(
                        ['name', 'product_uom_qty', 'quantity_done'])
                    response_data.update({
                        'id': stock_picking_obj.id,
                        'name': stock_picking_obj.name,
                        'move_ids': move_ids
                    })
                    return valid_response(response_data)
                else:
                    return invalid_response('not_found', 'No Picking record found.')
            else:
                return invalid_response('not_found', 'No barcode was provided.', 200)
        else:
            # ToDo: return all data in Ready state instead of invalid_response()
            return invalid_response('not_found', 'No barcode was provided.', 200)

    @validate_token
    @http.route("/api/get_picking_detail", type="http", auth="none", methods=["GET"], csrf=False)
    def get_picking_detail(self, **payload):
        """
            Gets the name of a stock_picking record from request and
            returns that specific stock_picking record's details.
            If name of a stock_picking not in request then returns
            all the stock_picking record details of ready state.
        """

        _logger.info("/api/get_picking_detail payload: %s", payload)

        try:
            response_data = []
            payload_data = payload
            stock_picking = request.env['stock.picking']
            stock_picking_objs = False

            if 'barcode' in payload_data or 'picking_id' in payload_data or 'picking_type_id' in payload_data:
                domain = [('state', '=', 'assigned')]
                if 'barcode' in payload_data:
                    if payload_data['barcode']:
                        stock_picking_objs = stock_picking.sudo().search([('name', '=', payload_data.get('barcode'))])
                elif 'picking_id' in payload_data:
                    if payload_data['picking_id']:
                        stock_picking_objs = stock_picking.sudo().browse(int(payload_data['picking_id']))
                elif 'picking_type_id' in payload_data:
                    if payload_data['picking_type_id']:
                        stock_picking_objs = stock_picking.sudo().search([
                            ('state', '=', 'assigned'), ('picking_type_id', '=', int(payload_data.get('picking_type_id')))
                        ])
            else:
                stock_picking_objs = stock_picking.sudo().search([
                    ('state', '=', 'assigned'), ('company_id', '=', request.env.user.company_id.id)
                ])

            if stock_picking_objs:
                for stock_picking_obj in stock_picking_objs:
                    move = []
                    move_line = []
                    sale_id = stock_picking_obj.sale_id.id if stock_picking_obj.sale_id else 0
                    purchase_id = stock_picking_obj.purchase_id.id if stock_picking_obj.purchase_id else 0
                    for move_id in stock_picking_obj.move_ids_without_package:
                        move.append({
                            'id': move_id.id,
                            'product_id': move_id.product_id.id,
                            'product': move_id.product_id.display_name,
                            'product_code': move_id.product_id.default_code or "",
                            'description_picking': move_id.description_picking or "",
                            'product_uom_qty': move_id.product_uom_qty,
                            'state': dict(move_id._fields['state'].selection).get(move_id.state),
                        })

                    # move_ids = stock_picking_obj.move_ids_without_package.read([
                    #     'name', 'description_picking', 'product_uom_qty', 'state'
                    # ])
                    # for move_id in move_ids:
                    #     move_id['state'] = dict(stock_picking_obj.move_ids_without_package._fields['state'].selection).get(move_id['state'])
                    for line_id in stock_picking_obj.move_line_ids:
                        quant_line = []

                        stock_quants = request.env['stock.quant'].search([
                            ('product_id', '=', line_id.product_id.id), ('quantity', '>=', 0)
                        ])
                        product_stock_quant_ids = stock_quants.filtered(
                            lambda q: q.company_id in request.env.companies and q.location_id.usage == 'internal'
                        )

                        for quant_id in product_stock_quant_ids:
                            quant_line.append({
                                'id': quant_id.id,
                                'location': quant_id.location_id.complete_name,
                                'lot_serial': quant_id.lot_id.name if quant_id.lot_id else "",
                                'on_hand_quantity': quant_id.quantity,
                            })
                        move_line.append({
                            'id': line_id.id,
                            'product_id': line_id.product_id.id,
                            'product': line_id.product_id.name,
                            'product_code': line_id.product_id.default_code or "",
                            'product_uom_qty': line_id.product_uom_qty,
                            'quantity_done': line_id.qty_done,
                            'quant_ids': quant_line,
                        })
                    response_data.append({
                        'id': stock_picking_obj.id,
                        'name': stock_picking_obj.name,
                        'source_doc': stock_picking_obj.origin if stock_picking_obj.origin else "",
                        'schedule_date': stock_picking_obj.scheduled_date or "",
                        'deadline': stock_picking_obj.date_deadline or "",
                        'done_date': stock_picking_obj.date_done or "",
                        'partner_id': [str(stock_picking_obj.partner_id.id or ""),
                                       stock_picking_obj.partner_id.name or ""],
                        'location_id': [str(stock_picking_obj.location_id.id or ""),
                                        stock_picking_obj.location_id.display_name or ""],
                        'location_dest_id': [str(stock_picking_obj.location_dest_id.id or ""),
                                             stock_picking_obj.location_dest_id.display_name or ""],
                        'operation_type_id': [str(stock_picking_obj.picking_type_id.id or ""),
                                              stock_picking_obj.picking_type_id.name or ""],
                        'priority': dict(stock_picking_obj._fields['priority'].selection).get(stock_picking_obj.priority),
                        'company': stock_picking_obj.company_id.name,
                        'move_ids': move,
                        'move_line_ids': move_line,
                        'sale_id': sale_id,
                        'purchase_id': purchase_id,
                        'state': stock_picking_obj.state,
                        'shipping_policy': stock_picking_obj.move_type,
                        'create_uid': [str(stock_picking_obj.create_uid.id or ""), stock_picking_obj.create_uid.name or ""],
                        'create_date': stock_picking_obj.create_date,
                        'write_uid': [str(stock_picking_obj.write_uid.id or ""), stock_picking_obj.write_uid.name or ""],
                        'write_date': stock_picking_obj.write_date,
                    })
                return valid_response(response_data)
            else:
                return invalid_response('not_found', 'No Picking record found.')
        except Exception as e:
            _logger.exception("Error while getting picking details for payload: %s", payload)
            error_msg = 'Error while getting picking details.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route('/api/report/download', type='http', auth="none", methods=["GET"], csrf=False)
    def api_report_download(self, report_name=None, report_type=None, options=None, context=None):
        """This function is used by 'action_manager_report.js' in order to trigger the download of
        a pdf/controller report.

        @:param report_name: a javascript array JSON.stringified containing report internal url
        @:param report_type: a string that contains the report type to print.
        @:param options: a JSON containing the details options for printing a report.
        @:returns: Response with an attachment header

        """
        _logger.info("/api/report/download report_name: %s, report_type: %s, options: %s, context: %s",
                     report_name, report_type, options, context)
        try:
            if report_name and report_type:
                data = "[" + report_name + "," + report_type + "]"
                requestcontent = json.loads(data)
                url, type = requestcontent[0], requestcontent[1]
                reportname = '???'
                try:
                    if type in ['qweb-pdf', 'qweb-text']:
                        converter = 'pdf' if type == 'qweb-pdf' else 'text'
                        extension = 'pdf' if type == 'qweb-pdf' else 'txt'

                        pattern = '/report/pdf/' if type == 'qweb-pdf' else '/report/text/'
                        reportname = url.split(pattern)[1].split('?')[0]

                        docids = None
                        if '/' in reportname:
                            reportname, docids = reportname.split('/')

                            # NOTE: Check if the picking id exists for Picking Operation & Delivery Slip reports
                            if docids and reportname in ['stock.report_deliveryslip', 'stock.report_picking']:
                                ids = [int(x) for x in docids.split(",")]
                                stock_picking_obj = request.env['stock.picking'].search([('id', 'in', ids)])
                                if not stock_picking_obj:
                                    return invalid_response('bad_request', 'Provided picking not found.', 200)

                        if docids:
                            # Generic report:
                            response = ReportController.report_routes(self, reportname=reportname, docids=docids,
                                                                      converter=converter, context=context)
                        else:
                            # Particular report:
                            # data = dict(url_decode(url.split('?')[1]).items())  # decoding the args represented in JSON
                            # data = dict(url_decode(options).items())  # decoding the args represented in JSON
                            # data = json.loads(options)
                            if 'context' in data:
                                # context, data_context = json.loads(context or '{}'), json.loads(data.pop('context'))
                                context, data_context = json.loads(context or '{}'), json.loads(options)
                                context = json.dumps({**context, **data_context})
                            response = ReportController.report_routes(self, reportname=reportname, converter=converter,
                                                                      context=context, **json.loads(options))

                        report = request.env['ir.actions.report']._get_report_from_name(reportname)
                        filename = "%s.%s" % (report.name, extension)

                        if docids:
                            ids = [int(x) for x in docids.split(",")]
                            obj = request.env[report.model].browse(ids)
                            if report.print_report_name and not len(obj) > 1:
                                report_name = safe_eval(report.print_report_name, {'object': obj, 'time': time})
                                filename = "%s.%s" % (report_name, extension)
                        response.headers.add('Content-Disposition', content_disposition(filename))
                        return response
                    else:
                        _logger.exception("The report_type in request is not defined properly.")
                        return invalid_response('bad_request',
                                                'The report_type in request is not defined properly.', 200)
                except Exception as e:
                    _logger.exception("Error while generating report %s", reportname)
                    # se = _serialize_exception(e)
                    # error = {
                    #     'code': 200,
                    #     'message': "Odoo Server Error",
                    #     'data': se
                    # }
                    # return request.make_response(html_escape(json.dumps(error)))
                    error_message = "Error while generating report '" + reportname + "'"
                    return invalid_response('bad_request', error_message, 200)
            else:
                return invalid_response('bad_request', 'Report Name or Type was not provided.', 200)
        except Exception as e:
            _logger.exception("Error while generating Report for report_name: %s, report_type: %s, options: %s, context: %s",
                     report_name, report_type, options, context)
            error_msg = 'Error while generating Report.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route('/api/label/download', type='http', auth="none", methods=["GET"], csrf=False)
    def api_label_download(self, picking_id, context=None):
        _logger.info("/api/label/download picking_id: %s, context: %s", picking_id, context)

        try:
            picking_id = int(picking_id)
            context = json.loads(context)
            stock_picking_obj = request.env['stock.picking'].sudo().browse(picking_id)

            stock_picking_obj_move_lines = stock_picking_obj.move_ids_without_package.move_line_ids

            stock_picking_move_lines_products = []

            for move_line in stock_picking_obj_move_lines:
                stock_picking_move_lines_products.append(move_line.product_id.id)

            new_context = dict(context, **{
                "allowed_company_ids": request.env.user.company_ids.ids,
                "contact_display": "partner_address", "active_model": "stock.picking",
                "active_id": picking_id, "active_ids": [picking_id],
                "default_product_ids": stock_picking_move_lines_products,
                "default_move_line_ids": stock_picking_obj_move_lines.ids,
                "default_picking_quantity": "picking"
            })

            # NOTE: create new layout wizard through code & get the id to pass in the options
            prod_label_wiz = request.env['product.label.layout'].sudo().with_context(new_context).create({
                "print_format": 'dymo',
                "product_ids": [(6, 0, stock_picking_move_lines_products)],
                "picking_quantity": 'picking'
            })

            prod_label_wiz_rec = request.env['product.label.layout'].browse(prod_label_wiz.id)

            prod_label_wiz_process_data = prod_label_wiz_rec.with_context(context).process()

            if prod_label_wiz_process_data.get('report_name') and prod_label_wiz_process_data.get('report_type') and prod_label_wiz_process_data.get('data'):
                report_name = '"/report/pdf/' + prod_label_wiz_process_data['report_name'] + '"'
                report_type = '"' + prod_label_wiz_process_data['report_type'] + '"'
                options = prod_label_wiz_process_data['data']

                return self.api_report_download(report_name=report_name, report_type=report_type,
                                                options=json.dumps(options), context=json.dumps(new_context))
            else:
                return invalid_response(typ='bad_request', status=200,
                                        message="Error while generating Product Labels. Please contact Administrator")
        except Exception as e:
            _logger.exception("Error while generating labels for picking_id: %s", picking_id)
            # se = _serialize_exception(e)
            # _logger.exception(se)
            error_msg = 'Error while generating Product Labels.'
            # if "name" in e:
            #     error_msg += "Reason:\n" + e.name
            # error_msg = error_msg.replace('\n', ' ')
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route("/api/user_detail", type="http", auth="none", methods=["GET"], csrf=False)
    def get_user_detail(self, **payload):
        _logger.info("/api/user_detail GET payload: %s", payload)

        try:
            access_token = request.httprequest.headers.get("access-token")
            user_id = request.env['api.access_token'].sudo().search([('token', '=', access_token)], limit=1).user_id
            if user_id and request.httprequest.method == 'GET':
                user_details = {
                    'name': user_id.name,
                    'email': user_id.login,
                    'image': user_id.image_1920.decode("utf-8") or ""
                }
                # NOTE: ADD to_process_count to the User Profile
                user_details.update({"to_process_count": self._get_picking_fields(self)})
                return valid_response(user_details)
            else:
                return invalid_response('not_found', 'No User Data Found.')
        except Exception as e:
            _logger.exception("Error while getting user data for payload: %s", payload)
            error_msg = 'Error while getting user data.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route("/api/get_product_detail", type="http", auth="none", methods=["GET"], csrf=False)
    def get_product_detail(self, **payload):
        """
            Gets the barcode of a product from request and
            returns that specific product's location and quantity.
        """
        _logger.info("/api/get_product_detail payload: %s", payload)

        try:
            payload_data = payload
            product_product = request.env['product.product']
            stock_lot = request.env['stock.production.lot']
            if 'barcode' in payload_data:
                if payload_data['barcode']:
                    # get product.product object search by barcode
                    product_product_objs = product_product.search([
                        ('barcode', '=', payload_data.get('barcode'))], limit=1)
                    if product_product_objs:
                        product_template_objs = product_product_objs.product_tmpl_id
                        product_template_img = product_template_objs.image_1920.decode("utf-8")
                    elif not product_product_objs:
                        # get product.product object from stock.production.lot
                        product_product_objs = stock_lot.sudo().search([
                            ('name', '=', payload_data.get('barcode'))], limit=1).product_id
                        if product_product_objs:
                            product_template_objs = product_product_objs.product_tmpl_id
                            product_template_img = product_template_objs.image_1920.decode("utf-8")
                        else:
                            return invalid_response('not_found', 'No product found for this barcode.')
                else:
                    return invalid_response('not_found', 'No product found for this barcode.')
            else:
                product_template_objs = request.env['product.template'].search([('type', 'in', ['consu', 'product'])])
                product_template_img = ""

            if product_template_objs:
                response_data = []
                stock_putaway = request.env['stock.putaway.rule']
                stock_storage_capacity = request.env['stock.storage.category.capacity']

                for product in product_template_objs:
                    barcode = []
                    for product_variant in product.product_variant_ids:
                        if product_variant.barcode:
                            barcode.append(product_variant.barcode)
                    stock_quants = request.env['stock.quant'].search([
                        ('product_id.product_tmpl_id', '=', product.id), ('quantity', '>=', 0),
                        ('location_id.usage', '=', 'internal'),
                        ('company_id', '=', request.env.user.company_id.id)
                    ]).mapped('quantity')

                    putaway_count = stock_putaway.sudo().search_count([
                        ('company_id', '=', request.env.user.company_id.id),
                        '|', ('product_id.product_tmpl_id', '=', product.id),
                        ('category_id', '=', product.categ_id.id)
                    ])
                    storage_capacity_count = stock_storage_capacity.sudo().search_count([
                        ('product_id', 'in', product.product_variant_ids.ids),
                        ('company_id', '=', request.env.user.company_id.id)
                    ])
                    lot_serial = stock_lot.search([('product_id', 'in', product.product_variant_ids.ids)]).mapped('name')

                    response_data.append({
                        'id': product.id,
                        'product_name': product.name,
                        'product_code': product.default_code or "",
                        'barcode': barcode + lot_serial,
                        'prod_barcode': barcode,
                        'lot_serial_number': lot_serial,
                        'expiration_date': product.use_expiration_date if 'use_expiration_date' in product._fields else False,
                        'inventory_location': product.property_stock_inventory.complete_name or "",
                        'variant': product.product_variant_count,
                        'on_hand': sum(stock_quants) if stock_quants else 0,
                        'purchase_unit': product.purchased_product_qty,
                        'sold_unit': product.sales_count,
                        'putaway': putaway_count,
                        'storage_capacity': storage_capacity_count,
                        'product_in': product.nbr_moves_in,
                        'product_out': product.nbr_moves_out,
                        'image': product_template_img or ""
                    })
                return valid_response(response_data)
            else:
                return invalid_response('not_found', 'No product found.')
        except Exception as e:
            _logger.exception("Error while getting product details for payload: %s", payload)
            error_msg = 'Error while getting product details.'
            return invalid_response('bad_request', error_msg, 200)


    #######################################
    # POST APIs
    #######################################

    @validate_token
    @http.route("/api/post_picking_validate", type="json", auth="none", methods=["POST"], csrf=False)
    def post_picking_validate(self, **payload):
        _logger.info("/api/post_picking_validate payload: %s", payload)

        try:
            params = ["picking_id", "move_line_ids"]

            req_data = payload if len(payload) > 0 else json.loads(
                request.httprequest.data.decode())  # convert the bytes format to dict format
            req_params = {key: req_data.get(key) for key in params if req_data.get(key)}
            picking_id, move_line_ids = (
                req_params.get("picking_id"),
                req_params.get("move_line_ids")
            )
            _data_included_in_body = all([picking_id, move_line_ids])
            if not _data_included_in_body:
                # ToDo: Check if it is a batch sync, change response.
                if 'batch_validate' in req_data:
                    return {'code': "post_data_error", 'message': "Data is not valid, please check again",
                            'picking_id': req_data['picking_id']}
                return invalid_response("post_data_error", "Data is not valid, please check again", 200)
            else:
                _logger.info("Updating Stock Picking Transfers")
                stock_picking = request.env['stock.picking']
                stock_move = request.env['stock.move']
                stock_move_line = request.env['stock.move.line']
                stock_prod_lot = request.env['stock.production.lot']

                stock_picking_obj = stock_picking.sudo().search([('id', '=', req_params.get("picking_id"))])

                if stock_picking_obj.state == 'done':
                    # ToDo: Check if it is a batch sync, change response.
                    if 'batch_validate' in req_data:
                        return {'code': "already_validated", 'message': "This picking is already done.",
                                'picking_id': stock_picking_obj.id}
                    return invalid_response("already_validated", "This picking is already done.", 200)

                # if stock_picking_obj.picking_type_id.code == 'incoming':  # for Receipts
                #     stock_picking_obj.move_line_ids.unlink()

                if move_line_ids:
                    for move_line in move_line_ids:

                        lot_detail = stock_prod_lot.sudo().search([
                            ('name', '=', move_line.get('lot_id')),
                            ('product_id', '=', move_line.get('product_id')),
                            ('company_id', '=', request.env.user.company_id.id)
                        ], limit=1)

                        lot_id = False
                        lot_name = False

                        if not lot_detail:
                            lot_detail = stock_prod_lot.create({
                                'name': move_line.get('lot_id'),
                                'product_id': move_line.get('product_id'),
                                'company_id': request.env.user.company_id.id,
                            })

                        if stock_picking_obj.picking_type_id.code in ['outgoing',
                                                                      'internal']:  # for Delivery Orders and Internal transfer
                            lot_id = lot_detail.id
                        if stock_picking_obj.picking_type_id.code == 'incoming':  # for Receipts
                            if stock_picking_obj.picking_type_id.use_existing_lots:  # Use Existing lots enabled
                                lot_id = lot_detail.id
                            else:  # Use Create New lots enabled
                                lot_name = move_line.get('lot_id')

                        if move_line.get("id"):  # if move.line id exists in the system.
                            move_line_obj = stock_move_line.sudo().browse(move_line.get("id"))

                            move_line_obj.product_uom_qty = 0
                            move_line_obj.qty_done = move_line.get('quantity_done')
                            move_line_obj.lot_id = lot_id
                            move_line_obj.lot_name = lot_name

                            # if stock_picking_obj.picking_type_id.code == 'outgoing':  # for Delivery Orders
                            #     move_line_obj.lot_id = lot_detail[0].id
                            # if stock_picking_obj.picking_type_id.code == 'incoming':  # for Receipts
                            #     if stock_picking_obj.picking_type_id.use_existing_lots:  # Use Existing lots enabled
                            #         move_line_obj.lot_id = lot_detail[0].id
                            #     else:  # Use Create New lots enabled
                            #         move_line_obj.lot_name = move_line.get('lot_id')

                        else:  # if move.line id does not exist, create new record.
                            move_obj = stock_move.sudo().search([
                                ('picking_id', '=', req_params.get("picking_id")),
                                ('product_id', '=', move_line.get('product_id')),
                            ])
                            vals = {
                                'picking_id': stock_picking_obj.id,
                                'move_id': move_obj.id,
                                'product_id': move_obj.product_id.id,
                                # 'product_uom_qty': move_line.get('quantity_done'),
                                'qty_done': move_line.get('quantity_done'),
                                'product_uom_id': move_obj.product_uom.id,
                                'location_id': move_obj.location_id.id,
                                'location_dest_id': move_obj.location_dest_id.id,
                                'lot_id': lot_id,
                                'lot_name': lot_name,
                            }
                            request.env['stock.move.line'].create(vals)

                    # stock_picking_obj.state = 'done'
                    stock_picking_obj.with_context(skip_immediate=True, skip_sms=True,
                                                   skip_backorder=True, picking_ids_not_to_backorder=stock_picking_obj.ids
                                                   ).button_validate()

                    # ToDo: Check if it is a batch sync, change response.
                    if 'batch_validate' in req_data:
                        return {'message': "Transfer is validated.", 'picking_id': stock_picking_obj.id}
                    return valid_response({'message': "Transfer is validated.", 'picking_id': stock_picking_obj.id})

                else:
                    # ToDo: Check if it is a batch sync, change response.
                    if 'batch_validate' in req_data:
                        return {'code': "move_line_ids_empty", 'message': "Move lines are empty.",
                                'picking_id': stock_picking_obj.id}
                    return invalid_response("move_line_ids_empty", "Move lines are empty.", 200)
        except Exception as e:
            _logger.exception("Error while validating picking for payload: %s", payload)
            error_msg = 'Error while Validating Picking.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route("/api/batch_post_picking_validate", type="json", auth="none", methods=["POST"], csrf=False)
    def batch_post_picking_validate(self, **payload):
        _logger.info("/api/batch_post_picking_validate payload: %s", payload)

        try:
            req_data = json.loads(request.httprequest.data.decode())  # convert the bytes format to `list of dict` format
            batch_res = []
            for data in req_data['data']:
                data['batch_validate'] = True
                batch_res.append(self.post_picking_validate(**data))
            return valid_response(batch_res)
        except Exception as e:
            _logger.exception("Error while validating batch picking for payload: %s", payload)
            error_msg = 'Error while updating user data.'
            return invalid_response('bad_request', error_msg, 200)

    @validate_token
    @http.route("/api/user_detail", type="json", auth="none", methods=["POST"], csrf=False)
    def post_user_detail(self, **payload):
        _logger.info("/api/user_detail POST payload: %s", payload)

        try:
            access_token = request.httprequest.headers.get("access-token")
            user_id = request.env['api.access_token'].sudo().search([('token', '=', access_token)], limit=1).user_id
            if user_id and request.httprequest.method == 'POST':
                req_data = json.loads(request.httprequest.data.decode())  # convert the bytes format to `list of dict` format
                if 'name' in req_data['data'].keys() or 'image' in req_data['data'].keys():
                    if 'name' in req_data['data'].keys():
                        name = req_data['data']['name']
                        if name != user_id.name:
                            user_id.name = name
                    if 'image' in req_data['data'].keys():
                        image = req_data['data']['image']
                        if image != user_id.image_1920:
                            user_id.image_1920 = image
                    return valid_response({'message': "User Data Updated."})
                return invalid_response("no_user_data", "No name or image found.", 200)
        except Exception as e:
            _logger.exception("Error while updating user data for payload: %s", payload)
            error_msg = 'Error while updating user data.'
            return invalid_response('bad_request', error_msg, 200)
