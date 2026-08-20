"""Strict, allow-list validation for organization branding values.

Branding (``brand_primary_color``, ``brand_logo_url``) is attacker-controllable —
any org admin can set it — and it is rendered into generated HTML reports, where
the color is interpolated INSIDE a ``<style>`` block. HTML-escaping is NOT
sufficient in a CSS context (``}``, ``;``, ``</style>`` and ``url(...)`` are not
HTML-special), so we validate against a strict allow-list instead of trying to
sanitize arbitrary CSS:

* a color must be a plain hex value (``#rgb`` / ``#rgba`` / ``#rrggbb`` /
  ``#rrggbbaa``) — nothing else can pass, so it can never terminate the CSS
  declaration or the ``<style>`` element, nor introduce ``url()`` / ``expression()``
  / ``javascript:`` / an SVG payload;
* a logo URL must be an ``http(s)`` URL or a raster ``data:image/*`` URI — never
  ``javascript:``, ``data:text/html`` or ``data:image/svg+xml`` (SVG can carry
  script), and never a bare ``url(...)`` payload.

The same helpers are used at BOTH boundaries: the API/schema layer rejects a bad
value on write, and the report layer falls back to a safe default on render (so a
legacy value written before this validation existed still cannot break out).
"""

import re

#: Default accent used when no valid brand color is configured. Mirrors the
#: report's own historic fallback so validation and rendering agree.
DEFAULT_ACCENT = "#0d9488"

# #rgb, #rgba, #rrggbb, #rrggbbaa — anchored, hex digits only. No whitespace,
# semicolons, braces, angle brackets, parentheses, or keywords can appear.
_HEX_COLOR_RE = re.compile(r"\A#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\Z")

# Logo URL: http(s), no whitespace or quote/angle characters that could break the
# surrounding attribute.
_HTTP_URL_RE = re.compile(r"\Ahttps?://[^\s'\"<>]{1,900}\Z", re.IGNORECASE)

# Inline logo: base64 raster data URI only. SVG is intentionally excluded (it can
# carry script), as are data:text/* and any non-image media type.
_DATA_IMG_RE = re.compile(
    r"\Adata:image/(?:png|jpe?g|gif|webp);base64,[A-Za-z0-9+/=]{1,4000}\Z",
    re.IGNORECASE,
)


def is_hex_color(value: object) -> bool:
    """True iff ``value`` is a plain hex color string (any case)."""
    return isinstance(value, str) and bool(_HEX_COLOR_RE.match(value.strip()))


def safe_color(value: object, default: str = DEFAULT_ACCENT) -> str:
    """Return ``value`` iff it is a valid hex color, else ``default``.

    The result is guaranteed to be a bare hex color, so interpolating it into a
    CSS declaration or ``<style>`` block can never break out of the intended
    property. Never returns attacker-controlled text.
    """
    if isinstance(value, str) and _HEX_COLOR_RE.match(value.strip()):
        return value.strip().lower()
    return default


def is_safe_logo_url(value: object) -> bool:
    """True iff ``value`` is a safe http(s) URL or a raster ``data:image/*`` URI."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    return bool(_HTTP_URL_RE.match(v) or _DATA_IMG_RE.match(v))


def safe_logo_url(value: object) -> str:
    """Return ``value`` iff it is a safe logo URL, else ``""`` (omit the logo)."""
    if isinstance(value, str) and is_safe_logo_url(value):
        return value.strip()
    return ""
