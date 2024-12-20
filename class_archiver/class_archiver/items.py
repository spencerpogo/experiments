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
    course_id = scrapy.Field()
    id = scrapy.Field()
    name = scrapy.Field()
    position = scrapy.Field()
    items_count = scrapy.Field()
    items_url = scrapy.Field()


class ModuleSubitemItem(scrapy.Item):
    course_id = scrapy.Field()
    id = scrapy.Field()
    title = scrapy.Field()
    position = scrapy.Field()
    indent = scrapy.Field()
    type = scrapy.Field()
    module_id = scrapy.Field()
    html_url = scrapy.Field()
    content_id = scrapy.Field()
    url = scrapy.Field()


class CanvasFileItem(scrapy.Item):
    course_id = scrapy.Field()
    id = scrapy.Field()
    filename = scrapy.Field()
    download_url = scrapy.Field()
    file_path = scrapy.Field()
