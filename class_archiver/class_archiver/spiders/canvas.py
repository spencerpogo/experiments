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


class CanvasModulesSpider(scrapy.Spider):
    name = "canvas"
    allowed_domains = []

    def __init__(self, *args, **kwargs):
        super(CanvasModulesSpider, self).__init__(*args, **kwargs)
        self.allowed_domains = [self.canvas_domain]
        self.token = os.environ["CANVAS_TOKEN"]
    
    @classmethod
    def update_settings(cls, settings):
        super().update_settings(settings)
        # ensure we never get rate limited
        settings.set("CONCURRENT_REQUESTS_PER_DOMAIN", 1, priority="spider")

    def canvas_endpoint(self, endpoint):
        return f"https://{self.canvas_domain}/api/v1/{endpoint}"

    def canvas_request(self, url, callback, *args, **kwargs):
        return scrapy.http.JsonRequest(
            url,
            callback,
            *args,
            **kwargs,
            headers={
                "Authorization": f"Bearer {self.token}",
            },
        )

    def start_requests(self):
        yield self.canvas_request(
            self.canvas_endpoint(f"courses/{self.course_id}/modules"), self.parse_modules_list
        )

    def parse_modules_list(self, response):
        modules = response.json()
        assert isinstance(modules, list), f"expected list of modules, got {modules!r}"
        for mod in modules:
            assert mod["unlock_at"] is None, f"unhandled unlock_at in {mod!r}"
            module_id = mod["id"]
            yield self.canvas_request(
                mod["items_url"],
                self.parse_module_items,
                cb_kwargs={"module": mod},
            )

    def parse_module_items(self, response, module):
        items = response.json()
        assert isinstance(items, list), f"expected items list, got {items!r}"
        for it in items:
            ty = it["type"]
            if ty == "File":
                yield self.canvas_request(it["url"], self.parse_file)
            else:
                raise NotImplementedError(f"Item type {ty!r} not implemented")

        links = parse_header_links(response.headers.get("link", "").decode())
        next_links = [l for l in links if l.get("rel") == "next"]
        assert len(next_links) <= 1, f"got multiple next links: {links!r}"
        if next_links:
            yield self.canvas_request(
                next_links[0]["url"],
                self.parse_module_items,
                cb_kwargs={"module": module}
            )
    
    def parse_file(self, response):
        raise NotImplementedError()
    
    def parse_assignment(self, response):
        assignment = response.json()
        desc = Selector(text=assignment["description"])
        for f in desc.css(".instructure_file_link"):
            # could just fetch the URL in data-api-endpoint and pass it to parse_file
            #  but we can save a request by parsing the HTML attributes directly
            