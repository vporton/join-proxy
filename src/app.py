import copy
import hashlib
import itertools
import operator
import time
from multidict import CIMultiDict
import requests as requests
from common import OurDB, config  # before `flask`
import common
from flask import Response, request, jsonify

app = common.app


def serialize_http_request(status_code, url, body, headers) -> bytes:
    headers_joined = itertools.accumulate(headers.items().map(lambda h: h[0]+"\t"+h[1]+"\r"), operator.add)
    return (str(status_code) + "\n" + url + "\n" + headers_joined + "\n").encode('utf-8') + body


def deserialize_http_request(data: bytes):
    status_code, url, headers_data, body = data.split("\n", 3)
    headers = CIMultiDict()
    for header_data in headers_data.split("\n"):
        k, v = header_data.split("\t", 1)
        headers.add(k.decode('utf-8'), v.decode('utf-8'))
    return int(status_code), url, body, headers


# Following https://gist.github.com/questjay/3f858c2fea1731d29ea20cd5cb444e30#file-flask-server-proxy
def serve_proxied(upstream_path):
    request_headers = copy.copy(request.headers)
    request_body = request.get_data()
    url = config['upstreamPrefix'] + upstream_path if 'upstreamPrefix' in config else \
        "https://" + request_headers['host'] + '/' + upstream_path
    filter_request_headers(request_headers)
    cur_time = int(round(time.time() * 1000))
    threshold = cur_time - config['cacheTime']
    with OurDB() as our_db:
        with our_db.env.begin(our_db.content_db, write=True) as txn:  # TODO: buffers=True allowed?
            # Remove all outdated entries:
            cursor = txn.cursor()
            for key, _value in cursor:
                key_value = int.from_bytes(key, byteorder='little')
                if key_value < threshold:
                    cursor.delete()

            request_data = serialize_http_request(request_body, request_headers)
            request_data_hasher = hashlib.sha256()
            request_data_hasher.update(request_data)
            request_hash = request_data_hasher.digest()

            old_data = txn.get(request_hash)
    if old_data is not None:
        response = {
            'status': old_data[0],
            'url': old_data[1],
            'headers': old_data[2],
            'body': old_data[3],
        }
    else:
        r = make_request(url, request.method, headers=request_headers, data=request_body)
        response = {
            'status': r.status_code,
            'url': url,
            'headers': copy.copy(r.raw.headers),
            'body': r.content,
        }
    filter_response_headers(response['headers'])

    return Response(
        response=[response['body']],
        status=response['status'],
        headers=response['headers'],
        direct_passthrough=True)



def filter_request_headers(headers):
    entries_to_remove = [k for k in headers.keys() if k.lower() in ['host']]
    for k in entries_to_remove:
        del headers[k]
    for k, v in config['upstreamHeaders'].items():
        headers[k] = v


def filter_response_headers(headers):
    # http://tools.ietf.org/html/rfc2616#section-13.5.1
    hop_by_hop = ['connection', 'keep-alive', 'te', 'trailers', 'transfer-encoding', 'upgrade',
                  'content-length', 'content-encoding']  # my addition - Victor Porton
    entries_to_remove = [k for k in headers.keys() if k.lower() in hop_by_hop]
    for k in entries_to_remove:
        del headers[k]

    # FIXME
    # accept only supported encodings
    # if 'Accept-Encoding' in headers:
    #     ae = headers['Accept-Encoding']
    #     filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
    #     headers['Accept-Encoding'] = ', '.join(filtered_encodings)

    return headers


def make_request(url, method, headers={}, data=None, params=None):
    try:
        # LOG.debug("Sending %s %s with headers: %s and data %s", method, url, headers, data)
        print(f"Making request to {url}")
        return requests.request(method, url, params=params, stream=False,
                                headers=headers,
                                allow_redirects=False,
                                data=data)
    except Exception as e:
        print(e)


@app.route('<path:p>', methods=['GET', 'POST', 'HEAD'])
def proxy_handler(p):
    return serve_proxied(p)


if __name__ == '__main__':
    app.run(debug=True)
