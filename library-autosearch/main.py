import re

import requests
import bs4
import sqlite3
from tqdm import tqdm


def search_physical(sess: requests.Session, tq, book: str):
    tqdm.write(f"Search: {book!r}")
    # tq.set_description(f"Search: {book!r}")
    r = sess.get(
        "https://catalog.lacountylibrary.org/client/en_US/default/search/results",
        params=[
            ("qu", book),
            ("qf", "ITYPE\tMaterial+Type\t1:BOOK\tBook"),
            ("qf", "LANGUAGE\tLanguage\tENG\tEnglish"),
            ("qf", "LIBRARY\tLibrary\t1:330\tCulver City Julian Dixon Library"),
        ],
    )
    r.raise_for_status()
    return r.text


def print_search_results(html: str):
    soup = bs4.BeautifulSoup(html, "lxml")
    wrapper = soup.find(id="results_wrapper")
    if wrapper is None:
        return
    cells = wrapper.find_all(class_="cell_wrapper")
    results: list[bs4.PageElement] = [i.find(class_="results_bio") for i in cells]
    for r in results:
        unwanted_classes = {"availableDiv"}
        elts = r.find_all(
            lambda elt: len(set(elt["class"]) & unwanted_classes) == 0, recursive=False
        )
        out = [i.get_text().replace("\xa0", "") for i in elts]
        tqdm.write(repr(out))


def main():
    db = sqlite3.connect("db.sqlite3")
    r = db.execute("SELECT Title, Author FROM goodreads WHERE Bookshelves = 'to-read'")
    results = list(r.fetchall())

    sess = requests.Session()
    with tqdm(results) as tq:
        for title, author in tq:
            title = title.split(":")[0].split("(")[0].strip()
            title = re.sub(r"[^a-zA-z ]", "", title)
            author_names = author.split(" ")
            author = (
                " ".join((author_names[0], author_names[-1]))
                if len(author_names) > 1
                else author_names[0]
            ).strip()
            search = " ".join((title, author)).replace("  ", "")
            html = search_physical(sess, tq, search)
            print_search_results(html)


if __name__ == "__main__":
    main()
