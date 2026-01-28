from typing import List, Dict, Any

TECH_NAME_REWRITES = {
    "WPML": "WordPress Multilingual Plugin (WPML)",
    "Hello Elementor": "Hello Elementor Theme",
    "Apache": "Apache HTTP Server",
    "Nginx": "Nginx",
}


def canonicalize_tech_name(name: str | None) -> str | None:
    if not name:
        return None
    return TECH_NAME_REWRITES.get(name, name)


def deduplicate_techs(techs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate technologies by merging similar items (e.g. usage of aliases).

    Heuristic:
    1. Sort by confidence (desc) then name length (desc).
    2. If a tech is a substring of another existing tech in the same category,
       and has lower or equal confidence, drop it.
    """
    if not techs:
        return []

    # Canonicalize names first
    for t in techs:
        if t.get("name"):
            t["name"] = canonicalize_tech_name(t["name"])

    # Sort: highest confidence first, then longest name
    # We use a tuple sort key: (confidence, name_length) descending
    sorted_techs = sorted(
        techs, key=lambda x: (x.get("confidence", 0) or 0, len(x.get("name", "") or "")), reverse=True
    )

    kept: List[Dict[str, Any]] = []

    for cand in sorted_techs:
        cand_name = (cand.get("name") or "").strip()
        if not cand_name:
            continue

        cand_cats = set(cand.get("categories") or [])
        is_redundant = False

        for existing in kept:
            ex_name = (existing.get("name") or "").strip()
            # Check for name overlap (one contains the other) - prioritize longer name (which is 'existing' usually due to sort,
            # but if confidence was higher for short name, we might see short name first.
            # Actually, standardizing on the more descriptive name is usually better.

            # Simple substring match
            if cand_name.lower() in ex_name.lower() or ex_name.lower() in cand_name.lower():
                # Check for category overlap - if they share ANY category, consider them same tech family
                ex_cats = set(existing.get("categories") or [])
                if not cand_cats.isdisjoint(ex_cats) or (not cand_cats and not ex_cats):
                    # Found overlap.
                    # We merge details into 'existing' because it appeared first in our sort (higher confidence/len).

                    # Merge version if missing in existing
                    if not existing.get("version") and cand.get("version"):
                        existing["version"] = cand["version"]

                    # Merge categories
                    for c in cand_cats:
                        if c not in ex_cats:
                            existing.setdefault("categories", []).append(c)

                    # If the candidate name is actually LONGER than existing (and we kept existing due to confidence),
                    # we might prefer the longer name?
                    # E.g. "Apache" (100%) vs "Apache HTTP Server" (50%).
                    # Sorted list has "Apache" first.
                    # existing="Apache", cand="Apache HTTP Server".
                    # We should swap name if cand is longer/more descriptive?
                    # Let's trust canonicalize_tech_name to handle explicit aliases.
                    # For unknown ones, longer is usually better.
                    if len(cand_name) > len(ex_name):
                        existing["name"] = cand_name

                    is_redundant = True
                    break

        if not is_redundant:
            kept.append(cand)

    return kept
