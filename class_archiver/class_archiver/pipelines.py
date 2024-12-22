# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html

import re

# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
import scrapy
from scrapy.pipelines.files import FilesPipeline
from scrapy.http.request import NO_CALLBACK

from .items import CanvasFileItem
from .spiders.canvas import CanvasModulesSpider


class CanvasFilesPipeline(FilesPipeline):
    def get_media_requests(self, item, info):
        if isinstance(item, CanvasFileItem):
            assert isinstance(
                info.spider, CanvasModulesSpider
            ), f"unknown spider {info.spider!r} returned CanvasFileItem"
            yield scrapy.Request(
                item["download_url"],
                headers={"Authorization": f"Bearer {info.spider.token}"},
                dont_filter=True,  # allow redirects to offsite domains
                callback=NO_CALLBACK,
            )
        return []

    def file_path(self, request, response=None, info=None, *, item=None):
        assert isinstance(info.spider, CanvasModulesSpider)
        course_id = info.spider.course_id
        clean_filename = re.sub(r"[/\\?%*:|\"<>\x7F\x00-\x1F]", "-", item["filename"])
        return f"canvas-files/{course_id}/{item['id']}_{clean_filename}"

    def item_completed(self, results, item, info):
        if isinstance(item, CanvasFileItem):
            ok_results = [r for ok, r in results if ok]
            if len(ok_results) != 1:
                raise AssertionError(
                    f"expected 1 ok result, got {len(ok_results)}: {results!r}"
                )
            (r,) = ok_results
            if r["url"] != item["download_url"]:
                raise AssertionError()
            item["file_path"] = ok_results[0]["path"]
            return item
        return super().item_completed(results, item, info)
