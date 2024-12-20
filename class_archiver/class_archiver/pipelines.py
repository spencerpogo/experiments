# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
import scrapy
from scrapy.http.request import NO_CALLBACK

from .items import CanvasFileItem


class ClassArchiverPipeline:
    def get_media_requests(self, item, info):
        if isinstance(item, CanvasFileItem):
            yield scrapy.Request(item["download_url"], callback=NO_CALLBACK)
        return []

    def file_path(self, request, response=None, info=None, *, item=None):
        clean_filename = re.sub(r"[/\\?%*:|\"<>\x7F\x00-\x1F]", "-", item["filename"])
        return f"canvas-files/{item['course_id']}/{item['file_id']}_{clean_filename}"
    
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
