# Request Join Proxy

## What it does

This will contain a proxy that intentionally delivers outdated data.

## Running environment

This app can be run on a server or (presumably less expensively) as
an AWS Lambda.

## Configuration

The config loads from `config.json` file in the current directory:
```json
{
  "statePath": "./tmp",
  "cacheTime": 10000,
  "ourSecret": "DohchohHahthiphooc5iefa0weiJoh6ae4ou4Ohy",
  "upstreamPrefix": "https://api.openai.com/",
  "upstreamHeaders": {
    "Authorization": "Bearer <OPENAI_API_KEY>"
  }
}
```

`statePath` is a directory that stores a database. `cacheTime` is cache time in milliseconds.
`ourSecret`, if present in the JSON file, is passed in `X-JoinProxy-Key: Bearer ...` to protect
our proxy from unauthorized use. `upstreamPrefix`, if present in the JSON file, overrides the
domain name passed in `Host:` header. `upstreamHeaders` are self-explanatory.

## Testing the app

```
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
$ python app.py
```
