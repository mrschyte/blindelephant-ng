import requests
import logging
import random
import time
import tarfile
import hashlib
import os
import os.path
import glob
import xxhash
import pickle

from attr import define, field, Factory
from typing import Any, Set, List, Dict, FrozenSet

from urllib.parse import urljoin
from functools import reduce

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

def content_hash(path, reader):
    m = xxhash.xxh128()

    m.update(os.fsencode(path))
    m.update(b"\x00")

    while True:
        data = reader.read(16384)
        if data == b'':
            break
        m.update(data)

    return m.intdigest()

@define
class Database:
    fingerprints: Dict[int, Set[str]] = field(kw_only=True, default=Factory(dict))
    nodes: Dict[FrozenSet[str], Set[str]] = field(kw_only=True, default=Factory(dict))

    def generate(self, path: str, skip: int=0) -> 'Database':
        fingerprints: Dict[int, Set[str]] = self.fingerprints
        paths: Dict[str, Set[str]] = {}

        for vs, ps in self.nodes.items():
            for p in ps:
                if p not in paths:
                    paths[p] = set()
                paths[p].update(vs)

        for path in glob.glob(os.path.join(path, '*.tar.gz')):
            version = os.path.basename(path).replace('.tar.gz', '')
            if version not in self.versions:
                with tarfile.open(path, mode='r:gz') as tar:
                    logging.info('loading archive=%s', path)
                    for tarinfo in tar:
                        if tarinfo.isreg():
                            if skip > 0:
                                tar_path = tarinfo.path.split('/', maxsplit=skip)[-1]
                            else:
                                tar_path = tarinfo.path

                            fingerprint = content_hash(tar_path, tar.extractfile(tarinfo))
                            if fingerprint not in fingerprints:
                                fingerprints[fingerprint] = set()
                            fingerprints[fingerprint].add(version)

                            if tar_path not in paths:
                                paths[tar_path] = set()
                            paths[tar_path].add(version)

        nodes: Dict[FrozenSet[str], Set[str]] = {}
        for k, v in paths.items():
            versions = frozenset(v)
            if versions not in nodes:
                nodes[versions] = set()
            nodes[versions].add(k)
        self.nodes = nodes
        return self

    @staticmethod
    def load(path: str) -> 'Database':
        with open(path, 'rb') as fp:
            return pickle.load(fp)

    def save(self, path: str):
        with open(path, 'wb') as fp:
            return pickle.dump(self, fp)

    def indicators(self):
        versions = set(self.nodes.keys())

        while True:
            cover = minimal_cover(versions)

            if not cover:
                break

            for pathset in zip(*map(lambda c: self.nodes[c], cover)):
                yield pathset

            versions.difference_update(cover)

    @property
    def versions(self):
        if self.nodes:
            return reduce(lambda k, v: k.union(v), self.nodes.keys())
        return set()


def fetch(session, url):
    resp = session.get(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, stream=True, allow_redirects=False, verify=False)
    resp.raw.decode_content = True
    return resp.status_code, resp.raw
    
def guess(db, url, url_filter=lambda _: True):
    current = db.versions
    previous = None

    session = requests.Session()
    queried = set()

    while len(current) > 1:
        valid = filter(lambda vs: vs.intersection(current) and vs.intersection(current) != current
                        and not db.nodes[vs].issubset(queried),
                        db.nodes.keys())

        ranks = sorted(valid, key=lambda vs: (abs(0.5 - len(current.intersection(vs)) / len(current)), random.random()))

        if not ranks:
            break

        best = ranks[0]
        for path in db.nodes[best]:
            if path not in queried:
                queried.add(path)

                if not url_filter(path):
                    continue

                status, body = fetch(session, urljoin(url, path))
                logging.info('remaining=%d path=%s status=%d', len(current), path, status)
                if status == 200:
                    fingerprint = content_hash(path, body)
                    if fingerprint in db.fingerprints:
                        previous, current = current, current.intersection(db.fingerprints[fingerprint])
                        break
    
    if not current:
        return previous

    return current

def splitext(path):
    return os.path.splitext(path)[1].lower().lstrip('.')

def skip_suspicious(path):
    if splitext(path) in ('js', 'map', 'png', 'gif', 'svg', 'html', 'jpg', 'css'):
        return True
    return False

    if splitext(path) in ('php', 'sql', 'ini'):
        return False
    if path.startswith('tests/'):
        return False
    if path.startswith('admin-dev/'):
        return False
    if path.startswith('install-dev/'):
        return False
    if path.startswith('translations/'):
        return False
    if path.startswith('src/'):
        return False
    if path.startswith('mails/'):
        return False
    if path.startswith('tests-legacy/'):
        return False
    return True

def minimal_cover(sets):
    if not sets:
        return None

    remaining = set(reduce(lambda u, v: u.union(v), sets))
    cover = set()

    gain = lambda s: len(s.intersection(remaining))

    while remaining:
        best = next(iter(sorted(sets, key=gain, reverse=True)))
        remaining.difference_update(best)
        cover.add(best)
    return cover

def flatten(xs):
    for x in xs:
        if type(x) in (list, tuple, set):
            for y in flatten(x):
                yield y
        else:
            yield x

def check(db: Database, url, url_filter=lambda _: True, max_tries=10):
    session = requests.Session()
    tries = 0

    for pathset in db.indicators():
        if tries > max_tries:
            return False

        for path in pathset:
            if not url_filter(path):
                continue

            print(path)
            status, body = fetch(session, urljoin(url, path))
            logging.info('checking %d, %s', status, path)
            if status == 200:
                fingerprint = content_hash(path, body)
                if fingerprint in db.fingerprints:
                    return True
            tries += 1

def go_figure(dbs, url):
    for _id, db in dbs.items():
        if check(db, url, url_filter=skip_suspicious):
            return _id, guess(db, url, url_filter=skip_suspicious)

