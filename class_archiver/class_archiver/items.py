# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class ClassArchiverItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    pass


class ModuleItem(scrapy.Item):
    id = scrapy.Field()
    name = scrapy.Field()
    position = scrapy.Field()
    items_count = scrapy.Field()
    items_url = scrapy.Field()


class ModuleSubitemItem(scrapy.Item):
    id = scrapy.Field()
    title = scrapy.Field()
    position = scrapy.Field()
    indent = scrapy.Field()  # 0-based
    type = scrapy.Field()
    module_id = scrapy.Field()
    content_id = scrapy.Field()


class CanvasFileItem(scrapy.Item):
    id = scrapy.Field()
    filename = scrapy.Field()
    download_url = scrapy.Field()
    file_path = scrapy.Field()


class CanvasAssignmentItem(scrapy.Item):
    id = scrapy.Field()
    name = scrapy.Field()
    description = scrapy.Field()
    due_at = scrapy.Field()
    quiz_id = scrapy.Field()
    discussion_topic = scrapy.Field()


class PanoptoSession(scrapy.Item):
    id = scrapy.Field()
    name = scrapy.Field()
    ios_video_url = scrapy.Field()
    srt_url = scrapy.Field()
