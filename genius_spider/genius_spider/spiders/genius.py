import ast
import json
from pathlib import Path
from functools import partial
import logging

import scrapy
from markdownify import markdownify as md

from ..items import GeniusArtist, GeniusSong


class GeniusSpider(scrapy.Spider):
    name = "genius"
    allowed_domains = ["genius.com"]
    start_urls = []

    BASE = "https://genius.com"

    def __init__(self, *args, **kwargs):
        logging.getLogger("scrapy.core.scraper").setLevel(logging.INFO)
        super().__init__(*args, **kwargs)

    @classmethod
    def gen_artist_songs_url(cls, artist: str):
        return f"{cls.BASE}/artists/{artist}/songs"

    @classmethod
    def gen_songs_api_url(cls, artist_id: str, page: int):
        return f"{cls.BASE}/api/artists/{artist_id}/songs?page={page}&per_page=20&sort=popularity&text_format=html,markdown"
    
    def _get_slugs(self):
        slugs = getattr(self, "slug", None)
        if slugs is not None:
            yield from slugs
        slugs_file = getattr(self, "slugs_file", None)
        if not slugs_file:
            raise ValueError("Must specify either slugs array or slugs_file")
        with open(slugs_file, "r") as f:
            for l in f.readlines():
                l = l.strip()
                if l:
                    yield l

    def start_requests(self):
        for slug in self._get_slugs():
            yield scrapy.Request(
                self.gen_artist_songs_url(slug), callback=partial(self.parse_songs_html, slug)
            )

    def parse_songs_html(self, artist_slug, response):
        quote, literal_inner = response.xpath(
            '//script[contains(text(), "window.__PRELOADED_STATE__")]/text()'
        ).re(r"window.__PRELOADED_STATE__\s*=\s*JSON\.parse\(\s*(['\"])(.*)\1\s*\)")
        state_dict = json.loads(ast.literal_eval(quote + literal_inner + quote))
        # Path("state_dict.json").write_bytes(json.dumps(state_dict).encode())

        artist = next(
            a
            for a in state_dict.get("entities", {}).get("artists", {}).values()
            if a.get("slug", "").lower() == artist_slug.lower()
        )
        artist_id = artist.get("id")
        yield GeniusArtist(
            name=artist.get("name"),
            slug=artist.get("slug"),
            genius_id=artist_id,
            image_url=artist.get("imageUrl"),
        )
        yield scrapy.Request(
            self.gen_songs_api_url(artist_id, 1),
            callback=self.parse_songs_api,
        )

    def parse_songs_api(self, response):
        # p = Path("songs-resp.json"); p.exists() or p.write_bytes(response.body)
        data = json.loads(response.text)
        for song in data.get("response", {}).get("songs", []):
            song_item = GeniusSong(
                title=song.get("title_with_featured"),
                artist_names=song.get("artist_names"),
                path=song.get("path"),
                art_thumb_url=song.get("song_art_image_thumbnail_url")
                or song.get("song_art_image_url"),
            )
            yield response.follow(
                song["path"], callback=partial(self.parse_lyrics, song_item)
            )
            # break

    def parse_lyrics(self, song_item, response):
        lyrics_html = "<br>".join(
            response.xpath('//div[@data-lyrics-container="true"]').extract()
        )
        song_item["lyrics_markdown"] = md(lyrics_html).strip() + "\n"
        # p = Path("lyrics.md").write_bytes(song_item["lyrics_markdown"].encode())
        yield song_item
