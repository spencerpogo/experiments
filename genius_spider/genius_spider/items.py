# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class GeniusArtist(scrapy.Item):
    name = scrapy.Field()
    slug = scrapy.Field()
    genius_id = scrapy.Field()


class GeniusSong(scrapy.Item):
    artist_slug = scrapy.Field()
    title = scrapy.Field()
    artist_names = scrapy.Field()
    art_thumb_url = scrapy.Field()
    art_thumb_path = scrapy.Field()
    lyrics_markdown = scrapy.Field()
