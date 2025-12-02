/**
 * Initialize Bootstrap Popovers and Tooltips for the portal
 * This is a plain JS file (not an Odoo module) that initializes Bootstrap components
 */
(function () {
    'use strict';

    function initBootstrapComponents() {
        // Initialize all popovers
        const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
        popoverTriggerList.forEach(function (popoverTriggerEl) {
            // Check if Popover class exists (Bootstrap 5)
            if (typeof Popover !== 'undefined') {
                new Popover(popoverTriggerEl);
            } else if (typeof bootstrap !== 'undefined' && bootstrap.Popover) {
                new bootstrap.Popover(popoverTriggerEl);
            }
        });

        // Initialize all tooltips
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltipTriggerList.forEach(function (tooltipTriggerEl) {
            // Check if Tooltip class exists (Bootstrap 5)
            if (typeof Tooltip !== 'undefined') {
                new Tooltip(tooltipTriggerEl);
            } else if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
                new bootstrap.Tooltip(tooltipTriggerEl);
            }
        });
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initBootstrapComponents);
    } else {
        // DOM already loaded, run immediately
        initBootstrapComponents();
    }

    // Also run after any dynamic content loads (for SPA-like behavior)
    // This handles cases where content is loaded via AJAX
    document.addEventListener('shown.bs.modal', initBootstrapComponents);
})();

