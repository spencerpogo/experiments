import ast
import json

import scrapy


class GeniusSpider(scrapy.Spider):
    name = "genius"
    allowed_domains = ["genius.com"]
    start_urls = []

    BASE = "https://genius.com"

    @classmethod
    def gen_artist_songs_url(cls, artist: str):
        return f"{cls.BASE}/artists/{artist}/songs"

    @classmethod
    def gen_lyrics_url(cls, artist: str, song: str):
        return f"{cls.BASE}/{artist}-{song}-lyrics"
    
    @classmethod
    def gen_songs_api_url(cls, artist_id: str, page: int):
        return f"{cls.BASE}/api/artists/{artist_id}/songs?page={page}&per_page=20&sort=popularity&text_format=html,markdown"

    def start_requests(self):
        artist = getattr(self, "artist", None)
        song = getattr(self, "song", None)
        if not artist:
            raise ValueError("artist is required")
        if song:
            yield scrapy.Request(
                self.gen_lyrics_url(artist, song), callback=self.parse_lyrics
            )
            return
        yield scrapy.Request(self.gen_artist_songs_url(artist), callback=self.parse_artist_songs)

    def parse_artist_songs(self, response):
        state_js = response.xpath(
            '//script[contains(text(), "window.__PRELOADED_STATE__")]/text()'
        ).get()
        quote, literal_inner = response.xpath(
            '//script[contains(text(), "window.__PRELOADED_STATE__")]/text()'
        ).re(r"window.__PRELOADED_STATE__\s*=\s*JSON\.parse\(\s*(['\"])(.*)\1\s*\)")
        state_dict = json.loads(ast.literal_eval(quote + literal_inner + quote))
        self.artist_id = next(
            id_
            for id_, data in state_dict["entities"]["artists"].items()
            if data["slug"].lower() == self.artist.lower()
        )
        yield scrapy.Request(self.gen_songs_api_url(self.artist_id, 1), callback=self.parse_songs_api)
    

    def parse_songs_api(self, response):
        from pathlib import Path
        Path("songs-resp.json").write_bytes(response.body)
        self.log("scraped")


    def parse_lyrics(self, response):
        pass
