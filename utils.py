import logging

_logger = logging.getLogger(__name__)


def strohm_init_parameters(env):
    """
    Shared initialization logic for config parameters and system setup.
    Can be called from both init hooks and controllers to ensure consistent configuration.

    Args:
        env: Odoo environment object
    """
    # Set default language and timezone context
    env.context = dict(env.context, lang='de_DE')
    env.context = dict(env.context, tz='Europe/Berlin')

    # Disable default digest emails
    try:
        env['ir.config_parameter'].set_param('digest.default_digest_emails', 'False')
        _logger.info("Disabled digest.default_digest_emails")
    except Exception as e:
        _logger.warning("Failed to disable digest.default_digest_emails: %s", e)

    # Disable default digest ID
    try:
        env['ir.config_parameter'].set_param('digest.default_digest_id', '0')
        _logger.info("Disabled digest.default_digest_id")
    except Exception as e:
        _logger.warning("Failed to disable digest.default_digest_id: %s", e)

    # Deactivate any existing digests
    try:
        digests = env['digest.digest'].search([])
        if digests:
            digests.write({'state': 'deactivated'})
            _logger.info(f"Deactivated {len(digests)} digest records")
    except Exception as e:
        _logger.warning("Failed to deactivate digest.digest records: %s", e)

    # Disable portal API key generation
    try:
        env['ir.config_parameter'].sudo().set_param('portal.allow_api_keys', 'False')
        _logger.info("Successfully disabled portal API key generation")
    except Exception as e:
        _logger.warning("Failed to disable portal API key generation: %s", e)


    try:
        env['ir.config_parameter'].set_param('report.url', 'http://localhost:8069')
        _logger.info("Set report.url to http://localhost:8069")
    except Exception as e:
        _logger.warning("Failed to set report.url: %s", e)

    # Check if de_DE language is enabled
    try:
        lang = env['res.lang'].sudo().search([('code', '=', 'de_DE')], limit=1)
        if not lang:
            _logger.warning("German language (de_DE) not found, please install it")
        elif not lang.active:
            lang.sudo().write({'active': True})
            _logger.info("German language (de_DE) activated")
        else:
            _logger.info("German language (de_DE) is already active")
    except Exception as e:
        _logger.warning("Failed to check/activate de_DE language: %s", e)

    # Check current company and its fiscal country
    try:
        company = env.company
        if not company:
            company = env['res.company'].sudo().search([], limit=1)

        if company:
            _logger.info(f"Using company: {company.name} (id: {company.id})")
            if company.country_id.code != 'DE':
                _logger.warning(
                    f"Company {company.name} does not have Germany set as fiscal country. "
                    f"Current: {company.country_id.name or 'Not set'}"
                )
            else:
                _logger.info(f"Company {company.name} has correct fiscal country: {company.country_id.name}")
        else:
            _logger.warning("No company found in environment")
    except Exception as e:
        _logger.warning("Failed to check company fiscal country: %s", e)


def ensure_standard_products(env):
    """
    Ensure standard charging products exist in the system.
    This is typically called during controller initialization.

    Args:
        env: Odoo environment object

    Returns:
        dict: Dictionary of standard products or None if failed
    """
    try:
        _logger.info("Ensuring standard charging products exist")
        charging_model = env['charging.session.invoice'].sudo()
        standard_products = charging_model.ensure_standard_products()
        _logger.info("Standard charging products initialized successfully")
        return standard_products
    except Exception as e:
        _logger.error(f"Failed to initialize standard products: {str(e)}", exc_info=True)
        return None

