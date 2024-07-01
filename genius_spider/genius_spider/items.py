# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class GeniusArtist(scrapy.Item):
    name = scrapy.Field()
    slug = scrapy.Field()
    genius_id = scrapy.Field()
    image_url = scrapy.Field()
    image_path = scrapy.Field()


class GeniusSong(scrapy.Item):
    title = scrapy.Field()
    artist_names = scrapy.Field()
    path = scrapy.Field()
    art_thumb_url = scrapy.Field()
    art_thumb_path = scrapy.Field()
    lyrics_markdown = scrapy.Field()
