{
    'name': "Product Pack (Bundle) or Combo Products",
    'summary': """Bundle Pack Product""",
    'description': """
Bundle / Pack Product 
Combo Products
""",
    "category":  "Manufacturing",
    "version":  "15.0.1.1",
    "sequence":  1,
    "images": ['static/description/Banner.gif'],
    "author":  "Nevioo Technologies",
    "license": 'OPL-1',
    'depends': ['base', "product", "sale_management", "purchase", "stock"],
    'data': [
        'security/ir.model.access.csv',
        'wizard/view_bundle_wizard.xml',
        'views/view_product_template.xml',
        'views/view_bundle_product.xml',
        'views/view_sale_order.xml',
        'views/view_purchase_order.xml',


    ],
    'qweb': [],
    "application":  True,
    "installable":  True,
    "auto_install":  False
}