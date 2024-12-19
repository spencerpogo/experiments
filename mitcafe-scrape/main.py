from datetime import datetime
import sys
import re

import requests
import lxml.html
import json


HOST = "https://mit.cafebonappetit.com".rstrip("/")
sess = requests.Session()


def fetch_html(date):
    with open("saved.html", "r") as f:
        return f.read()

    url = f"{HOST}/cafe/{date}/"
    print("Fetch", url, file=sys.stderr)
    r = sess.get(url)
    r.raise_for_status()
    return r.text


def scrape(html):
    """
    date: YYYY-MM-DD format date to fetch menu for
    """
    tree = lxml.html.document_fromstring(html)

    dayparts = {}
    daypart_scripts = tree.xpath(
        "//script[not(@*) and contains(text(), 'Bamco.dayparts[')]"
    )
    for daypart_script_elt in daypart_scripts:
        daypart_script = daypart_script_elt.text
        matches = re.finditer(
            r"\bBamco\.dayparts\['(.+?)'\]\s*=\s*(.+?)\s*\;?\s*$",
            daypart_script,
            re.MULTILINE,
        )
        for m in matches:
            part_id = int(m.group(1))
            part_data = json.loads(m.group(2))
            dayparts[part_id] = part_data

    menu_scripts = tree.xpath(
        "//script[not(@*) and contains(text(), 'Bamco.menu_items')]"
    )
    assert (
        len(menu_scripts) == 1
    ), f"expected one menu script but got {len(menu_scripts)}"
    menu_script = menu_scripts[0].text
    match = next(
        re.finditer(
            r"\bBamco\.menu_items\s*=\s*(.+?)\s*\;?\s*$", menu_script, re.MULTILINE
        )
    )
    menu = json.loads(match.group(1))

    return dayparts, menu


def main():
    today = datetime.now()
    html = fetch_html(today.strftime("%Y-%m-%d"))
    with open("saved.html", "w") as f:
        f.write(html)

    print(scrape(html))


if __name__ == "__main__":
    main()
