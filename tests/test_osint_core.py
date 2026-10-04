import pytest

def test_query_sanitization(): 
    username = "  alecto_user  "
    clean_username = username.strip()
    assert clean_username == "alecto_user"
    assert len(clean_username) > 0

def test_endpoint_route_structure():
    target_domain = "example.com"
    endpoint = f"/api/v1/search?domain={target_domain}"
    assert endpoint.startswith("/api/v1/search")
    assert "domain=example.com" in endpoint
