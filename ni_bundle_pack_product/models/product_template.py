from odoo import fields, models, api, _
from odoo.exceptions import ValidationError
from odoo.addons import decimal_precision as dp


class ProductProduct(models.Model):
    _inherit = 'product.template'

    ni_is_product_pack = fields.Boolean(string="Is Product Pack")
    ni_cal_pack_price = fields.Boolean(string="Calculate Pack Price")
    ni_bundle_product_ids = fields.One2many('bundle.product', 'ni_product_id', string="Bundle Products")

    list_price = fields.Float(
        'Sales Price', compute='_compute_list_price',
        digits=dp.get_precision('Product Price'),
        help="Price at which the product is sold to customers.")

    @api.model
    def _compute_list_price(self):
        for product_id in self:
            print('price++++++++++++++++++++++++', product_id, product_id.ni_cal_pack_price)
            print('price++++++++++++++++++++++++', product_id.list_price, type(product_id.list_price))
            if product_id.ni_cal_pack_price:
                if product_id.ni_bundle_product_ids:
                    total_list_price = 0.0
                    for bundle_product in product_id.ni_bundle_product_ids:
                        total_list_price = total_list_price + bundle_product.name.list_price
                    product_id.list_price = total_list_price
                else:
                    product_id.list_price = 1.0
            else:
                product_id.list_price = 1.0


    @api.model
    def create(self, vals):
        res = super(ProductProduct, self).create(vals)
        if vals.get('ni_is_product_pack'):
            if vals.get('attribute_line_ids'):
                raise ValidationError(
                    _('You cannot create the variant of the Product which is Pack!!!'))

        return res

    # @api.model
    def write(self, vals):
        res = super(ProductProduct, self).write(vals)
        if self.ni_is_product_pack:
            if self.attribute_line_ids:
                raise ValidationError(
                    _('You cannot create the variant of the Product which is Pack!!!'))

        return res
