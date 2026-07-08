"""
Unit tests for app.domain.directory_service — query construction logic.
"""
from app.domain.directory_service import build_directory_query


def test_empty_query_when_no_filters():
    query = build_directory_query()
    assert query == {}


def test_single_filter_maps_to_profile_subfield():
    query = build_directory_query(state="Uttar Pradesh")
    assert query == {"profile.state": "Uttar Pradesh"}


def test_multiple_filters_combine():
    query = build_directory_query(state="Uttar Pradesh", blood_group="O+")
    assert query["profile.state"] == "Uttar Pradesh"
    assert query["profile.blood_group"] == "O+"


def test_search_text_builds_or_clause_across_fields():
    query = build_directory_query(q="Lucknow")
    assert "$or" in query
    assert len(query["$or"]) == len(
        ["profile.name", "profile.city", "profile.state", "profile.organisation", "profile.occupation", "profile.about"]
    )
    for clause in query["$or"]:
        field, condition = list(clause.items())[0]
        assert condition["$regex"] == "Lucknow"
        assert condition["$options"] == "i"


def test_search_text_is_regex_escaped():
    """A malicious or accidental regex metacharacter must not break the query."""
    query = build_directory_query(q="a.b*c(d")
    first_clause = query["$or"][0]
    condition = list(first_clause.values())[0]
    # re.escape should have escaped the special characters
    assert "\\." in condition["$regex"] or "\\*" in condition["$regex"]


def test_blank_search_text_is_ignored():
    query = build_directory_query(q="   ")
    assert "$or" not in query


def test_filters_and_search_combine():
    query = build_directory_query(q="engineer", occupation="Engineer")
    assert "$or" in query
    assert query["profile.occupation"] == "Engineer"
