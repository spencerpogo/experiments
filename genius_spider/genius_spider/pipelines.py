# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html
from urllib.parse import urlparse, unquote_plus

import scrapy
from scrapy.http import Request
from scrapy.http.request import NO_CALLBACK
from scrapy.pipelines.files import FilesPipeline
from itemadapter import ItemAdapter

from .items import GeniusSong


class GeniusSpiderPipeline:
    def process_item(self, item, spider):
        return item


class DummyFileItem(scrapy.Item):
    file_urls = scrapy.Field()


class GeniusImagePipeline(FilesPipeline):
    def get_media_requests(self, item, info):
        if isinstance(item, GeniusSong):
            return [Request(item["art_thumb_url"], callback=NO_CALLBACK)]
        return []

    def file_path(self, request, response=None, info=None, *, item=None):
        # currently, genius image urls only have one path component.
        # gracefully handle multi-component paths with a quick replace.
        return (
            "images/"
            + unquote_plus(urlparse(request.url).path.strip("/"))
            .replace("/", "-")
            .strip()
        )

    def item_completed(self, results, item, info):
        if isinstance(item, GeniusSong):
            ok_results = [r for ok, r in results if ok]
            if len(ok_results) != 1:
                raise AssertionError(
                    f"expected 1 ok result, got {len(ok_results)}: {results!r}"
                )
            (r,) = ok_results
            if r["url"] != item["art_thumb_url"]:
                raise AssertionError()
            item["art_thumb_path"] = ok_results[0]["path"]
            return item
        return super().item_completed(results, item, info)
