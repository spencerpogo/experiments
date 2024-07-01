# genius_spider

Usage:

1. Put a list of artist slugs in a file, for example `slugs.txt`:
   ```
   Ken-carson
   Babytron
   ```
2. Run the spider:
   ```sh
   scrapy crawl genius -a slugs_file=slugs.tx
   ```
3. Artist and song info will be stored in JSON lines format in `artists.jsonl` and `songs.jsonl`;
   Images will be stored in `files/images`
