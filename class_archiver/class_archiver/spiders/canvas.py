import logging

import scrapy
from scrapy.selector import Selector

from ..canvas import CanvasScrapyClient
from ..items import CanvasAssignmentItem, CanvasFileItem, ModuleItem, ModuleSubitemItem


class CanvasModulesSpider(scrapy.Spider):
    name = "canvas"
    allowed_domains = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_domains.append(self.canvas_domain)
        self.canvas = CanvasScrapyClient.from_env_token(self.canvas_domain)

    @classmethod
    def update_settings(cls, settings):
        super().update_settings(settings)
        # ensure we never get rate limited
        settings.set("CONCURRENT_REQUESTS_PER_DOMAIN", 1, priority="spider")

    def start_requests(self):
        for mod in {"scrapy.downloadermiddlewares.redirect", "scrapy.core.scraper"}:
            logging.getLogger(mod).setLevel(logging.INFO)
            pass
        yield self.canvas.request(
            self.canvas.api_courses_endpoint(self.course_id, "/modules"),
            self.parse_modules_list,
        )

    def parse_modules_list(self, response):
        modules = response.json()
        assert isinstance(modules, list), f"expected list of modules, got {modules!r}"
        for mod in modules:
            assert mod["unlock_at"] is None, f"unhandled unlock_at in {mod!r}"
            module_id = mod["id"]
            yield self.canvas.request(mod["items_url"], self.parse_module_items)
            yield ModuleItem(
                id=int(module_id),
                name=mod["name"],
                position=mod["position"],
                items_count=mod["items_count"],
                items_url=mod["items_url"],
            )

        yield from self.canvas.follow_pagination(response, self.parse_modules_list)

    def parse_module_items(self, response):
        items = response.json()
        assert isinstance(items, list), f"expected items list, got {items!r}"
        for it in items:
            ty = it["type"]
            if ty == "File":
                yield self.canvas.request(it["url"], self.parse_file)
            elif ty == "Assignment":
                yield self.canvas.request(it["url"], self.parse_assignment)
            elif ty == "Page":
                yield self.canvas.request(it["url"], self.parse_page)

            r = ModuleSubitemItem()
            if ty in {"File", "Discussion", "Assignment", "Quiz", "ExternalTool"}:
                r["content_id"] = it["content_id"]
            elif ty not in {"Page", "SubHeader", "ExternalUrl"}:
                raise AssertionError(
                    f"unexpected module item type: {it['type']!r} {it}"
                )

            for k in {"title", "position", "indent", "type"}:
                r[k] = it[k]
            if "external_url" in it:
                r["external_url"] = it["external_url"]
            yield r

        yield from self.canvas.follow_pagination(response, self.parse_module_items)

    def parse_file(self, response):
        f = response.json()
        assert isinstance(f, dict), f"expected dict from file response, got {f!r}"
        assert (
            "url" in f
        ), f"missing download url: {__import__('json').dumps(f, indent=4)}"
        return CanvasFileItem(
            id=f["id"],
            # in general "filename" is the URL-encoded version of "display_name"
            # we'll change the semantics slightly for our purposes (we are fine with
            #  storing filenames with spaces on disk)
            filename=f["display_name"],
            download_url=f["url"],
        )

    def parse_assignment(self, response):
        assignment = response.json()
        desc = assignment["description"]
        for f in Selector(text=desc).css(".instructure_file_link"):
            # could just fetch the URL in data-api-endpoint and pass it to parse_file
            #  but we can save a request by parsing the HTML attributes directly
            assert (
                f.attrib["data-api-returntype"] == "File"
            ), f"unexpected data-api-returntype: {f.attrib!r}"

            endpoint = f.attrib["data-api-endpoint"]
            endpoint_parts = endpoint.split(f"/courses/{self.course_id}/files/")
            assert (
                len(endpoint_parts) == 2
            ), f"unexpected data-api-endpoint format: {endpoint!r}"
            yield self.canvas.request(endpoint, self.parse_file)

        r = CanvasAssignmentItem()
        for k in {"id", "name", "description", "due_at"}:
            r[k] = assignment[k]
        for k in {"quiz_id", "discussion_topic"}:
            if k in assignment:
                r[k] = assignment[k]
        yield r

    def parse_page(self, response):
        page = response.json()
        body = page["body"]

        for f in Selector(text=body).css(".instructure_file_link"):
            # could just fetch the URL in data-api-endpoint and pass it to parse_file
            #  but we can save a request by parsing the HTML attributes directly
            assert (
                f.attrib["data-api-returntype"] == "File"
            ), f"unexpected data-api-returntype: {f.attrib!r}"

            endpoint = f.attrib["data-api-endpoint"]
            endpoint_parts = endpoint.split(f"/courses/{self.course_id}/files/")
            assert (
                len(endpoint_parts) == 2
            ), f"unexpected data-api-endpoint format: {endpoint!r}"
            yield self.canvas.request(endpoint, self.parse_file)

        r = CanvasPageItem()
        for k in {"id", "url", "body"}:
            r[k] = page[k]
        yield r
