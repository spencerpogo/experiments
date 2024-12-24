import json
import logging
from urllib.parse import parse_qs, urlparse

import scrapy

from ..canvas import CanvasScrapyClient


class PanoptoSpider(scrapy.Spider):
    name = "panopto"
    allowed_domains = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we will use dont_filter for all panopto requests because allowed_domains
        #  cannot be modified dynamically and we don't know it in advance (have to get
        #  it from canvas)
        self.allowed_domains.append(self.canvas_domain)
        self.canvas = CanvasScrapyClient.from_env_token(self.canvas_domain)
        self.panopto_url = None

    def start_requests(self):
        for mod in {"scrapy.downloadermiddlewares.redirect", "scrapy.core.scraper"}:
            # logging.getLogger(mod).setLevel(logging.INFO)
            pass
        yield self.canvas.request(
            self.canvas.api_courses_endpoint(
                self.course_id, "/external_tools/visible_course_nav_tools"
            ),
            self.parse_panopto_nav_item,
        )

    def parse_panopto_nav_item(self, response):
        nav_items = response.json()
        panopto_items = [i for i in nav_items if i["name"] == "Panopto Video"]
        assert len(panopto_items) <= 1, f"got multiple panopto navitems: {nav_items!r}"
        if not panopto_items:
            return
        (panopto_tool,) = panopto_items

        yield self.canvas.request(
            self.canvas.api_courses_endpoint(
                self.course_id, "/external_tools/sessionless_launch"
            ),
            method="GET",
            formdata={
                "id": str(panopto_tool["id"]),
                "launch_type": "course_navigation",
            },
            callback=self.parse_panopto_launch,
        )

    def parse_panopto_launch(self, response):
        launch = response.json()
        yield self.canvas.request(launch["url"], self.parse_panopto_tool_page)

    def parse_panopto_tool_page(self, response):
        with open("a.html", "w") as f:
            f.write(response.text)
        # for now, use dont_filter so we don't have to intercept the redirect and add
        #  to allowed_domains
        yield scrapy.FormRequest.from_response(
            response,
            formxpath="//form[@data-tool-id]",
            dont_filter=True,
            callback=self.parse_panopto_home,
        )

    def request_sessions_page(self, folder_id, page):
        params = {
            "bookmarked": False,
            "endDate": None,
            "folderID": folder_id,
            "getFolderData": True,
            "includeArchived": True,
            "includeArchivedStateCount": True,
            "isSharedWithMe": False,
            "isSubscriptionsPage": False,
            "maxResults": 25,
            "query": None,
            "sessionListOnlyArchived": False,
            "sortAscending": False,
            "sortColumn": 1,
            "startDate": None,
        }
        # fetch page 0
        yield scrapy.http.JsonRequest(
            f"{self.panopto_url}/Panopto/Services/Data.svc/GetSessions",
            method="POST",
            data={"queryParameters": {**params, "page": 0}},
            dont_filter=True,
            callback=self.parse_panopto_settings_page,
            cb_kwargs={"folder_id": folder_id, "page": page}
        )

    def parse_panopto_home(self, response):
        # must use request URL because fragment is stripped from response URL
        url = response.request.url
        parsed = urlparse(url)
        assert parsed.path.startswith(
            "/Panopto"
        ), f"expected root of path to be /Panopto in URL {url} {parsed}"
        assert parsed.scheme, f"panopto url missing scheme {url} {parsed}"
        assert parsed.netloc, f"panopto url missing netloc {url} {parsed}"
        panopto_domain = parsed.netloc
        self.allowed_domains.append(panopto_domain)
        self.panopto_url = f"{parsed.scheme}://{panopto_domain}"

        query = parse_qs(parsed.fragment)
        try:
            folder_ids = query.get("folderID")
            (folder_id,) = folder_ids
            folder_id = json.loads(folder_id)
        except Exception as e:
            raise AssertionError(
                f"failed to parse folder from panopto home url {url!r}"
            ) from e
        assert isinstance(
            folder_id, str
        ), f"unexpected JSON type from loading folder ID from {url}"

        yield from self.request_sessions_page(folder_id, 0)

    def parse_panopto_settings_page(self, response, folder_id, page):
        print(json.dumps(response.json(), indent=4))
