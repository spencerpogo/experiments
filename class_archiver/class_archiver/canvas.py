import os
import re

import scrapy


# taken from https://github.com/psf/requests/blob/23540c93cac97c763fe59e843a08fa2825aa80fd/src/requests/utils.py#L917
def parse_header_links(value):
    """Return a list of parsed link headers proxies.

    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"

    :rtype: list
    """

    links = []
    replace_chars = " '\""

    value = value.strip(replace_chars)
    if not value:
        return links

    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ""

        link = {"url": url.strip("<> '\"")}

        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links


class CanvasScrapyClient:
    canvas_domain: str
    token: str

    __slots__ = (
        "canvas_domain",
        "token",
    )

    def __init__(self, canvas_domain, token):
        self.canvas_domain = canvas_domain
        self.token = token

    @classmethod
    def from_env_token(cls, canvas_domain):
        try:
            canvas_token = os.environ["CANVAS_TOKEN"]
            assert canvas_token
        except (KeyError, AssertionError) as e:
            raise AssertionError(
                f"from_env_token expects the CANVAS_TOKEN environment variable to be set"
            ) from e
        return cls(canvas_domain=canvas_domain, token=canvas_token)

    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def base_url(self):
        return f"https://{self.canvas_domain}"

    def endpoint(self, path):
        return self.base_url() + path

    def api_courses_endpoint(self, course_id, path):
        assert course_id.isalnum(), f"expected course_id to be alnum, got {course_id!r}"
        # path should include leading /
        return self.endpoint(f"/api/v1/courses/{course_id}{path}")

    def request(self, url, callback, *args, **kwargs):
        return scrapy.FormRequest(
            url,
            callback,
            *args,
            **kwargs,
            headers={
                # we won't bother to set Accept or Content-Type
                **self.auth_headers(),
                **kwargs.get("headers", {}),
            },
        )

    def follow_pagination(self, response, callback):
        links = parse_header_links(response.headers.get("link", "").decode())
        next_links = [l for l in links if l.get("rel") == "next"]
        assert len(next_links) <= 1, f"got multiple next links: {links!r}"
        if next_links:
            yield self.request(next_links[0]["url"], callback)
