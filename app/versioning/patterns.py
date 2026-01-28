"""Version detection patterns database.

Each technology has multiple detection signals:
- js_var: JavaScript global variable (most accurate)
- url_pattern: URL/filename regex patterns
- meta_pattern: Meta tag patterns
- comment_pattern: HTML comment patterns
- hash: File hash fingerprints (future)

Priority order for choosing version:
1. js_var (highest confidence)
2. url_pattern (medium confidence)
3. meta_pattern (medium confidence)
4. comment_pattern (lower confidence)
"""

from typing import Dict, List, TypedDict, Optional


class SignalPattern(TypedDict, total=False):
    """Version detection signal pattern."""

    type: str  # 'js_var', 'url', 'meta', 'comment', 'hash'
    pattern: str  # Regex pattern with capture group for version
    variable: str  # JS variable name (for js_var type)
    confidence: float  # 0.0 - 1.0


class TechnologyVersionConfig(TypedDict, total=False):
    """Version detection configuration for a technology."""

    name: str
    signals: List[SignalPattern]
    version_format: str  # Expected format: 'semver', 'major.minor', 'custom'
    aliases: List[str]  # Alternative names


# ============================================================================
# VERSION PATTERNS DATABASE
# ============================================================================

VERSION_PATTERNS: Dict[str, TechnologyVersionConfig] = {
    # -------------------------------------------------------------------------
    # jQuery Family - DISTINCT technologies with separate version variables
    # -------------------------------------------------------------------------
    "jquery": {
        "name": "jQuery",
        "signals": [
            {"type": "js_var", "variable": "jQuery.fn.jquery", "confidence": 1.0},
            {"type": "js_var", "variable": "jQuery.prototype.jquery", "confidence": 1.0},
            {"type": "url", "pattern": r"/jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
            {"type": "url", "pattern": r"jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)", "confidence": 0.85},
            {"type": "comment", "pattern": r"jQuery\s+v?(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    "jquery_ui": {
        "name": "jQuery UI",
        "signals": [
            {"type": "js_var", "variable": "$.ui.version", "confidence": 1.0},
            {"type": "js_var", "variable": "jQuery.ui.version", "confidence": 1.0},
            {"type": "url", "pattern": r"/jquery-ui[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", "confidence": 0.9},
            {"type": "url", "pattern": r"jquery-ui(?:\.min)?\.(?:js|css)\?ver=(\d+\.\d+\.\d+)", "confidence": 0.85},
            {"type": "comment", "pattern": r"jQuery UI\s+[-v]?\s*(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    "jquery_migrate": {
        "name": "jQuery Migrate",
        "signals": [
            {"type": "js_var", "variable": "jQuery.migrateVersion", "confidence": 1.0},
            {"type": "js_var", "variable": "$.migrateVersion", "confidence": 1.0},
            {"type": "url", "pattern": r"/jquery-migrate[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
            {"type": "url", "pattern": r"jquery-migrate(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)", "confidence": 0.85},
            {"type": "comment", "pattern": r"jQuery Migrate\s+v?(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # Frontend Frameworks
    # -------------------------------------------------------------------------
    "react": {
        "name": "React",
        "signals": [
            {"type": "js_var", "variable": "React.version", "confidence": 1.0},
            {"type": "url", "pattern": r"/react[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
            {"type": "comment", "pattern": r"React\s+v?(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    "vue": {
        "name": "Vue.js",
        "signals": [
            {"type": "js_var", "variable": "Vue.version", "confidence": 1.0},
            {"type": "url", "pattern": r"/vue[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
            {"type": "comment", "pattern": r"Vue(?:\.js)?\s+v?(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    "angular": {
        "name": "Angular",
        "signals": [
            {"type": "js_var", "variable": "angular.version.full", "confidence": 1.0},
            {"type": "js_var", "variable": "ng.VERSION.full", "confidence": 1.0},
            {"type": "url", "pattern": r"/angular[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # CMS
    # -------------------------------------------------------------------------
    "wordpress": {
        "name": "WordPress",
        "signals": [
            {
                "type": "meta",
                "pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+(\d+\.\d+(?:\.\d+)?)["\']',
                "confidence": 1.0,
            },
            {"type": "comment", "pattern": r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", "confidence": 0.8},
            {"type": "url", "pattern": r'/wp-includes/[^"\']*\?ver=(\d+\.\d+(?:\.\d+)?)', "confidence": 0.6},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # WordPress Plugins
    # -------------------------------------------------------------------------
    "elementor": {
        "name": "Elementor",
        "signals": [
            {"type": "url", "pattern": r'/elementor/assets/[^"\']*\?ver=(\d+\.\d+\.\d+)', "confidence": 0.9},
            {"type": "meta", "pattern": r"Elementor\s+v?(\d+\.\d+\.\d+)", "confidence": 0.8},
        ],
        "version_format": "semver",
    },
    "yoast_seo": {
        "name": "Yoast SEO",
        "signals": [
            {"type": "comment", "pattern": r"Yoast (?:WordPress )?SEO plugin v(\d+\.\d+(?:\.\d+)?)", "confidence": 1.0},
            {"type": "comment", "pattern": r"Yoast SEO\s+v?(\d+\.\d+(?:\.\d+)?)", "confidence": 0.9},
        ],
        "version_format": "semver",
    },
    "wpml": {
        "name": "WordPress Multilingual Plugin (WPML)",
        "signals": [
            {"type": "url", "pattern": r'/sitepress-multilingual-cms/[^"\']*\?ver=(\d+\.\d+\.\d+)', "confidence": 0.9},
            {"type": "js_var", "variable": "icl_vars.current_language_version", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # CSS Frameworks
    # -------------------------------------------------------------------------
    "bootstrap": {
        "name": "Bootstrap",
        "signals": [
            {"type": "js_var", "variable": "bootstrap.Modal.VERSION", "confidence": 1.0},
            {"type": "js_var", "variable": "jQuery.fn.modal.Constructor.VERSION", "confidence": 0.9},
            {"type": "url", "pattern": r"/bootstrap[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", "confidence": 0.9},
            {"type": "comment", "pattern": r"Bootstrap\s+v?(\d+\.\d+\.\d+)", "confidence": 0.7},
        ],
        "version_format": "semver",
    },
    "tailwind": {
        "name": "Tailwind CSS",
        "signals": [
            {"type": "url", "pattern": r"/tailwindcss[@.-]?(\d+\.\d+\.\d+)(?:\.min)?\.css", "confidence": 0.9},
            {"type": "comment", "pattern": r"tailwindcss\s+v?(\d+\.\d+\.\d+)", "confidence": 0.8},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # JavaScript Libraries
    # -------------------------------------------------------------------------
    "moment": {
        "name": "Moment.js",
        "signals": [
            {"type": "js_var", "variable": "moment.version", "confidence": 1.0},
            {"type": "url", "pattern": r"/moment[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
            {"type": "url", "pattern": r"moment(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)", "confidence": 0.85},
        ],
        "version_format": "semver",
    },
    "lodash": {
        "name": "Lodash",
        "signals": [
            {"type": "js_var", "variable": "_.VERSION", "confidence": 1.0},
            {"type": "url", "pattern": r"/lodash[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", "confidence": 0.9},
        ],
        "version_format": "semver",
    },
    "swiper": {
        "name": "Swiper",
        "signals": [
            {"type": "js_var", "variable": "Swiper.version", "confidence": 1.0},
            {"type": "url", "pattern": r'/swiper[/.-]?v?(\d+)[^"\']*\.(?:js|css)', "confidence": 0.8},
            {"type": "url", "pattern": r"swiper(?:\.min)?\.(?:js|css)\?ver=(\d+\.\d+\.\d+)", "confidence": 0.85},
        ],
        "version_format": "semver",
    },
    "core_js": {
        "name": "core-js",
        "signals": [
            {"type": "js_var", "variable": "__core-js_shared__.versions", "confidence": 1.0},
            {"type": "url", "pattern": r"/core-js[@.-]?(\d+\.\d+\.\d+)", "confidence": 0.9},
        ],
        "version_format": "semver",
    },
    # -------------------------------------------------------------------------
    # Analytics & Marketing
    # -------------------------------------------------------------------------
    "google_analytics": {
        "name": "Google Analytics",
        "signals": [
            {"type": "url", "pattern": r"gtag/js", "confidence": 0.5},  # Version: GA4 if present
            {"type": "js_var", "variable": "ga.getAll", "confidence": 0.5},  # UA
        ],
        "version_format": "custom",  # GA4 vs UA
    },
    "site_kit": {
        "name": "Site Kit",
        "signals": [
            {"type": "meta", "pattern": r"Site Kit by Google\s+(\d+\.\d+\.\d+)", "confidence": 1.0},
            {"type": "url", "pattern": r'/google-site-kit/[^"\']*\?ver=(\d+\.\d+\.\d+)', "confidence": 0.9},
        ],
        "version_format": "semver",
    },
    "monsterinsights": {
        "name": "MonsterInsights",
        "signals": [
            {
                "type": "url",
                "pattern": r'/google-analytics-for-wordpress/[^"\']*\?ver=(\d+\.\d+\.\d+)',
                "confidence": 0.95,
            },
        ],
        "version_format": "semver",
    },
}


def get_pattern_for_tech(tech_name: str) -> Optional[TechnologyVersionConfig]:
    """Get version patterns for a technology by name.

    Searches by exact key match and also by name field.

    Args:
        tech_name: Technology name to search for

    Returns:
        TechnologyVersionConfig or None if not found
    """
    # Direct key match
    key = tech_name.lower().replace(" ", "_").replace("-", "_").replace(".", "_")
    if key in VERSION_PATTERNS:
        return VERSION_PATTERNS[key]

    # Search by name field
    tech_lower = tech_name.lower()
    for config in VERSION_PATTERNS.values():
        if config.get("name", "").lower() == tech_lower:
            return config

    return None


def normalize_tech_key(tech_name: str) -> str:
    """Normalize technology name to pattern key format."""
    return tech_name.lower().replace(" ", "_").replace("-", "_").replace(".", "_")
