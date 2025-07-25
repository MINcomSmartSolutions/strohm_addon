# noinspection PyStatementEffect
{
    'name': "Ladeabrechnung Integration",
    'summary': "Integration for Ladeabrechnung",
    'description': """
        1. Company country should be set to Germany for the module to function correctly.
        2. Company's Fiscal Localization should be set to Germany for invoicing.
        3. The module is designed to work with the Odoo Community Edition (CE) version 18.0.
    """,
    'version': '18.0.1.0.0',
    'category': 'Services',
    'author': 'MINcom Smart Solutions GmbH',
    'website': 'https://min2sol.com',
    'depends': [
        'account',
        'auth_totp',
        'auth_totp_portal',
        'base',
        'base_automation',
        'l10n_de',
        'portal',
        'payment',
        'sale'
    ],
    'data': [
        'views/portal_templates.xml',
        'views/charging_session_invoice.xml',
        # 'views/account_portal_templates.xml',
        'security/ir.model.access.csv',
        'data/user_automations.xml',
        'data/partner_user_integrity_cron.xml',
        'data/uom_data.xml',
    ],
    'external_dependencies': {
        'python': [
            'cryptography',
            'python-dotenv',
            'pydantic',
            'email-validator'
        ],
    },
    'application': False,
    'installable': True,
    'auto_install': False,
    'post_init_hook': '_set_parameters_init_hook',
}
