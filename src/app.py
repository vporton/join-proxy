import struct
import werkzeug.datastructures
import functools
import hashlib
import time
from multidict import CIMultiDict
import requests as requests
from common import OurDB, config  # before `flask`
import common
from flask import Response, abort, request, jsonify

app = common.app


def serialize_http_request(status_code, method, url, headers, body) -> bytes:
    headers_list = list(headers.items())
    def h(t):
        return t[0]+"\t"+t[1]
    headers_joined = functools.reduce(lambda a, b: a+"\r"+b, map(h, headers_list[1:]), h(headers_list[0]))
    return (str(status_code) + "\n" + method + "\n" + url + "\n" + headers_joined + "\n").encode('utf-8') + body


def deserialize_http_request(data: bytes):
    status_code, method, url, headers_data, body = data.split(b"\n", 4)
    headers = CIMultiDict()
    for header_data in headers_data.split(b"\r"):
        k, v = header_data.split(b"\t", 1)
        headers.add(k.decode('utf-8'), v.decode('utf-8'))
    return int(status_code), method.decode('utf-8'), url.decode('utf-8'), headers, body


# Following https://gist.github.com/questjay/3f858c2fea1731d29ea20cd5cb444e30#file-flask-server-proxy
def serve_proxied(upstream_path):
    request_headers = CIMultiDict(request.headers)
    request_body = request.get_data()
    url = config['upstreamPrefix'] + upstream_path if 'upstreamPrefix' in config else \
        "https://" + request_headers['host'] + '/' + upstream_path
    filter_request_headers(request_headers)
    cur_time = int(round(time.time() * 1000))
    threshold = cur_time - config['cacheTime']
    with OurDB() as our_db:
        with our_db.env.begin(write=True) as txn:
            # Remove all outdated entries:
            cursor = txn.cursor(db=our_db.time_db)
            for key, value in cursor:  # TODO: slow
                key_value, = struct.unpack("Q", key)
                if key_value < threshold:
                    cursor.delete()
                    txn.delete(value, db=our_db.content_db)

            request_data = serialize_http_request(0, request.method, url, request_headers, request_body)  # FIXME: Initialize HTTP status as 0?
            request_data_hasher = hashlib.sha256()
            request_data_hasher.update(request_data)
            request_hash = request_data_hasher.digest()

            old_data_value = txn.get(request_hash, db=our_db.content_db)
    if old_data_value is not None:
        old_data = deserialize_http_request(old_data_value)
        response = {
            'status': old_data[0],
            'url': old_data[2],
            'headers': old_data[3],
            'body': old_data[4],
        }
        response['headers'].add('X-JoinProxy-Response', 'Hit')
    else:
        r = make_request(url, request.method, headers=request_headers, data=request_body)

        new_data = serialize_http_request(r.status_code, request.method, url, r.raw.headers, r.content)
        with OurDB() as our_db: # TODO: vain transaction
            with our_db.env.begin(write=True) as txn:
                txn.put(request_hash, new_data, db=our_db.content_db)
                txn.put(struct.pack("Q", cur_time), request_hash, db=our_db.time_db)

        response = {
            'status': r.status_code,
            'url': url,
            # 'headers': werkzeug.datastructures.Headers(**r.raw.headers),  # does not work
            'headers': r.raw.headers,
            'body': r.content,
        }
        response['headers'].add('X-JoinProxy-Response', 'Miss')
    filter_response_headers(response['headers'])

    response_headers = werkzeug.datastructures.Headers()
    for k, v in response['headers'].items():
        response_headers.add(k, v)

    return Response(
        response=[response['body']],
        status=response['status'],
        headers=response_headers,
        direct_passthrough=True)



def filter_request_headers(headers):
    entries_to_remove = [k for k in headers.keys() if k.lower() in ['host']]
    for k in entries_to_remove:
        del headers[k]
    if 'upstreamHeaders' in config:
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


@app.route('/<path:p>', methods=['GET', 'POST', 'PUT', 'DELETE', 'CONNECT', 'TRACE', 'PATCH'])
def proxy_handler(p):
    if 'ourSecret' in config:
        if "Bearer " + config['ourSecret'] != getattr(request.headers, 'x-joinproxy-key', None):
            abort(401)

    return serve_proxied(p)


if __name__ == '__main__':
    app.run(debug=True)
