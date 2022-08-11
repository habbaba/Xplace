from odoo import fields, models, api
from datetime import date, datetime


class BundleWizard(models.TransientModel):
    _name = "bundle.wizard"

    ni_pack_name = fields.Many2one('product.template', string="Pack", required=True,)
    ni_quantity = fields.Integer(string="Quantity", default=1)

    def add_pack(self):
        active_id = self.env.context.get('active_id')

        product_id = self.env['product.product'].search([('product_tmpl_id', '=', self.ni_pack_name.id)])

        if self.env.context.get('active_model') == 'sale.order':
            sale_order_line_obj = self.env['sale.order.line']
            sale_order_line_obj.create({
                'order_id': active_id,
                'product_id': product_id.id,
                'product_uom_qty': self.ni_quantity,
            })

        if self.env.context.get('active_model') == 'purchase.order':
            purchase_order_line_obj = self.env['purchase.order.line']
            purchase_order_line_obj.create({
                'order_id': active_id,
                'name': product_id.name,
                'display_type': '',
                'date_planned': fields.Datetime.now(),
                'product_id': product_id.id,
                'price_unit': product_id.list_price,
                'product_qty': self.ni_quantity,
                'product_uom': product_id.uom_po_id.id,
            })
