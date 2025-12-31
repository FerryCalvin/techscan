"""API v1 Blueprint - Versioned API endpoints.

All new API endpoints should be added here under /api/v1/ prefix.
Old endpoints are kept for backward compatibility with deprecation warnings.
"""

from flask import Blueprint, request, jsonify, Response
import logging

# Create versioned blueprint
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# ============ Scan Endpoints ============

@api_v1.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan a single domain for technologies.
    
    Query params:
        domain: Domain to scan (required)
        force: Force fresh scan (skip cache)
        debug: Include debug info in response
        quick: Use quick scan mode
        deep: Use deep scan mode
        fast_full: Use fast full scan mode
    """
    from ..routes.scan import scan as original_scan
    return original_scan()


@api_v1.route('/bulk', methods=['POST'])
def bulk_scan():
    """Scan multiple domains.
    
    JSON body:
        domains: List of domains to scan
        mode: Scan mode (quick, full, deep)
    """
    from ..routes.scan import bulk_scan_wrapper
    return bulk_scan_wrapper()


@api_v1.route('/bulk/<batch_id>', methods=['GET'])
def get_bulk_status(batch_id: str):
    """Get status of a bulk scan batch."""
    from ..routes.scan import get_bulk_batch_status
    return get_bulk_batch_status(batch_id)


# ============ Domain Endpoints ============

@api_v1.route('/domains', methods=['GET'])
def list_domains():
    """List all scanned domains with pagination."""
    from ..routes.search import api_domains
    return api_domains()


@api_v1.route('/domains/<domain>', methods=['GET'])
def get_domain(domain: str):
    """Get details for a specific domain."""
    from ..routes.search import api_domain_detail
    # Inject domain into request args
    return api_domain_detail(domain)


@api_v1.route('/domains/<domain>', methods=['DELETE'])
def delete_domain(domain: str):
    """Delete a domain and its scan history."""
    from ..routes.search import api_delete_domain
    return api_delete_domain(domain)


# ============ Technology Endpoints ============

@api_v1.route('/technologies', methods=['GET'])
def list_technologies():
    """List all detected technologies."""
    from ..routes.tech import api_all_technologies
    return api_all_technologies()


@api_v1.route('/technologies/<tech_name>/domains', methods=['GET'])
def get_tech_domains(tech_name: str):
    """Get all domains using a specific technology."""
    from ..routes.tech import api_tech_domains
    return api_tech_domains(tech_name)


# ============ Statistics Endpoints ============

@api_v1.route('/stats', methods=['GET'])
def get_stats():
    """Get system statistics."""
    from ..routes.system import metrics
    return metrics()


@api_v1.route('/stats/top-technologies', methods=['GET'])
def top_technologies():
    """Get top detected technologies."""
    from ..routes.search import api_top_tech
    return api_top_tech()


# ============ Health Endpoints ============

@api_v1.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    from ..routes.system import health as system_health
    return system_health()


@api_v1.route('/version', methods=['GET'])
def version():
    """Get API version info."""
    from ..routes.system import version as system_version
    return system_version()


# ============ Deprecation Helper ============

def add_deprecation_warning(response: Response, new_path: str) -> Response:
    """Add deprecation headers to response."""
    response.headers['X-API-Deprecated'] = 'true'
    response.headers['X-API-Sunset'] = '2025-12-31'
    response.headers['X-API-New-Endpoint'] = new_path
    return response
