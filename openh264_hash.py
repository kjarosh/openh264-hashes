#!/usr/bin/env python3
import json
import subprocess
import re
import sys
import tempfile
import urllib.request
import bz2
import hashlib
import os.path
from pathlib import Path
from urllib.error import HTTPError

OPENH264_REPO = 'cisco/openh264'

URL_REGEX = re.compile(
    r'(http://ciscobinary.openh264.org/(libopenh264-[\d.]+-[a-z\d.-]+\.(so|dylib|dll|a))\.(bz2|signed\.md5\.txt|sig.bz2))')

MD5_HASH_REGEX = re.compile(r'([0-9a-f]{32})')


def log(msg):
    print(msg, file=sys.stderr)


def gh(args, fields, repo=OPENH264_REPO):
    out = subprocess.run([
        'gh', '--repo', repo, '--json', fields, *args,
    ], check=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
    return json.loads(out)


def download(url, destination):
    urllib.request.urlretrieve(url, destination)


def unbz2(source, dest):
    with bz2.open(source, 'rb') as source, open(dest, 'wb') as dest:
        chunk_size = 1024 * 1024
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            dest.write(chunk)


def read_md5_hash(file):
    hashes = MD5_HASH_REGEX.findall(Path(file).read_text())
    if len(hashes) != 1:
        raise Exception(f'Expected one hash, found {len(hashes)} hashes')
    return hashes[0]


def hash(hash_type, file_path):
    if hash_type == 'md5':
        hash = hashlib.md5()
    elif hash_type == 'sha1':
        hash = hashlib.sha1()
    elif hash_type == 'sha256':
        hash = hashlib.sha256()
    elif hash_type == 'sha512':
        hash = hashlib.sha512()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def gather_links():
    all_links = {}
    release_list = gh(['release', 'list'], 'tagName')
    for release in release_list:
        tag = release['tagName']
        version = tag.replace('v', '')

        log(f'Gathering links for version {version}...')

        release = gh(['release', 'view', tag], 'body,publishedAt')
        matches = URL_REGEX.findall(release['body'])

        links = {}
        for match in matches:
            url = match[0]
            filename = match[1]
            ext = match[3]

            links[filename] = links.get(filename) or {}

            if ext == 'bz2':
                links[filename]['bz2'] = url
                log(f'    {filename} bz2: {url}')
            elif ext == 'signed.md5.txt':
                links[filename]['md5'] = url
                log(f'    {filename} md5: {url}')
            elif ext == 'sig.bz2':
                links[filename]['sha1.bz2'] = url
                log(f'    {filename} sha1.bz2: {url}')

        if links:
            all_links[version] = links
    return all_links


def main():
    links = gather_links()
    with open('links.json', 'w') as f:
        json.dump(links, f, indent=2)
    report = {}

    with tempfile.TemporaryDirectory() as directory:
        log(f'Downloading files to {directory}...')

        for version, version_links in links.items():
            version_report = {}
            log(f'Downloading version {version}...')

            for filename, file_links in version_links.items():
                file_report = {}
                file_report['issues'] = []

                hash_type = None

                path_binary = os.path.join(directory, filename)
                path_bz2 = os.path.join(directory, f'{filename}.bz2')

                log(f'Downloading binary {filename}...')

                try:
                    download(file_links['bz2'], path_bz2)
                except HTTPError as e:
                    file_report['issues'].append(f'http-error-{e.code}')
                    break

                try:
                    if 'md5' in file_links:
                        hash_type = 'md5'
                        path_md5 = os.path.join(directory, f'{filename}.md5')
                        log(f'Downloading MD5 {path_md5}...')
                        download(file_links['md5'], path_md5)
                    if 'sha1.bz2' in file_links:
                        hash_type = 'sha1'
                        path_sha1_bz2 = os.path.join(directory, f'{filename}.sha1.bz2')
                        path_sha1 = os.path.join(directory, f'{filename}.sha1')
                        log(f'Downloading SHA1 {path_sha1_bz2}...')
                        download(file_links['sha1.bz2'], path_sha1_bz2)
                        unbz2(path_sha1_bz2, path_sha1)
                except:
                    file_report['issues'].append(f'checksum-error')
                    hash_type = None

                log(f'Unzipping binary {filename}...')
                unbz2(path_bz2, path_binary)

                bz2_md5 = hash('md5', path_bz2)
                bz2_sha1 = hash('sha1', path_bz2)
                bz2_sha256 = hash('sha256', path_bz2)
                bz2_sha512 = hash('sha512', path_bz2)

                binary_md5 = hash('md5', path_binary)
                binary_sha1 = hash('sha1', path_binary)
                binary_sha256 = hash('sha256', path_binary)
                binary_sha512 = hash('sha512', path_binary)

                if hash_type == 'md5':
                    if binary_md5 != read_md5_hash(path_md5):
                        raise Exception(f'MD5 check failed for {filename}')
                else:
                    file_report['issues'].append(f'no-checksum')

                file_report['bz2_md5'] = bz2_md5
                file_report['bz2_sha256'] = bz2_sha256
                file_report['bz2_sha512'] = bz2_sha512
                file_report['binary_md5'] = binary_md5
                file_report['binary_sha256'] = binary_sha256
                file_report['binary_sha512'] = binary_sha512

                version_report[filename] = file_report
            report[version] = version_report

    with open('report.json', 'w') as f:
        json.dump(report, f, indent=2)


if __name__ == '__main__':
    main()
