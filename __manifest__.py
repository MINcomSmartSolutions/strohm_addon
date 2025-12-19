{
    'name': "Ladeabrechnung Integration",
    'summary': "Integration for Ladeabrechnung",
    'description': """
        1. Company country should be set to Germany for the module to function correctly.
        2. Company's Fiscal Localization should be set to Germany for invoicing.
        3. The module is designed to work with the Odoo Community Edition (CE) version 18.0.
    """,
    'version': '18.0.1.0.17',
    'category': 'Services',
    'author': 'MINcom Smart Solutions GmbH',
    'website': 'https://min2sol.com',
    'license': 'LGPL-3',
    'depends': [
        'account',
        'auth_totp',
        'base',
        'base_automation',
        'l10n_de',
        'l10n_din5008',
        'uom',
        'portal',
        'payment',
        'sale',
        'sale_management'
    ],
    'data': [
        'views/portal_assets.xml',
        'security/ir.model.access.csv',
        'data/user_automations.xml',
        'data/invoice_sale_automations.xml',
        'data/partner_user_integrity_cron.xml',
        'data/billing_cron.xml',
        'data/disable_2fa.xml',
        'data/uom_data.xml',
        'data/mail_templates.xml',
        'views/portal_templates.xml',
        'views/strohm_portal_templates.xml',
        'views/account_move_internal_extra_fields.xml',
        'views/charging_invoice_simple.xml',
        'views/sale_order_internal_extra_fields.xml',
        'views/partner_internal_billing_frequency.xml',
        'views/partner_actions.xml',
    ],
    'assets': {
        # Odoo website primary variables (colors, fonts, etc.)
        'web._assets_primary_variables': [
            'strohm_addon/static/src/scss/primary_variables.scss',
        ],
        # Bootstrap variable overrides (must be prepended)
        'web._assets_frontend_helpers': [
            ('prepend', 'strohm_addon/static/src/scss/bootstrap_overridden.scss'),
        ],
        # Custom styles and JS loaded on frontend
        'web.assets_frontend': [
            'strohm_addon/static/src/scss/custom_styles.scss',
            'strohm_addon/static/src/js/portal_popovers.js',
        ],
    },
    'external_dependencies': {
        'python': [
            'cryptography',
            'python-dotenv',
            'pydantic',
            'email-validator',
            'requests'
        ],
    },
    'hasiap':False,
    'application': False,
    'installable': True,
    'auto_install': False,
    'post_init_hook': '_set_parameters_init_hook',
}
