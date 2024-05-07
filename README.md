# Paid Proxy

## What it does
It's a reverse proxy that limits an amount of requests accordingly to specified price of every request. The accounts can be topped up by in-app purchases or Stripe.

**Warning:** The support for in-app purchases is not yet debugged,
because Google is slow to answer bug reports and support requests.
_(I am creating my first Android app and when I follow the Google help
to sign my app for uploading to Google Play, it does not work, so
I can't yet test in-app purchases. The bug was filed.)_
Stripe support is not high priority, and it is therefore not tested, too.

## Running environment

This app can be run on a server or (presumably less expensively) as
an AWS Lambda with DB stored in an EFS.

## Testing the app

```
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
$ python app.py
```

Then follow the example session below.

### Config

`config.json`:
```json
{
  "adminSecret": "<ADMIN-PASSWORD>",
  "statePath": "./tmp",
  "upstreamKey": "<GOOGLE-MAPS-API-SECRET>",
  "upstreamHeaders": {
    "X-goog-api-key": "<GOOGLE-MAPS-API-SECRET>"
  },
  "upstreamPrefix": "https://maps.googleapis.com/maps/api/",
  "stripe": {
    "secret": "<STRIPE-SECRET (OPTIONAL)>"
  },
  "android": {
    "bundleId": "name.vporton.local_shops"
  },
  "products": {
    "creditsX1": {
      "amount": 1.0
    },
    "creditsX2": {
      "amount": 2.0
    }
  },
  "costs": {
    "place/autocomplete/": 0.00283,
    "place/details/": 0.017,
    "place/nearbysearch/": 0.017
  }
}
```

Note that above we can specify `costs` above the Google costs, to have profit.

### Demo session

```
$ curl http://127.0.0.1:5000/balance/xxx ;echo
0.0
$ curl 'http://127.0.0.1:5000/proxy/xxx/maps/api/place/nearbysearch/json?location=-33.8670,151.1957&radius=500' ;echo
Payment required
$ curl -d '' -H 'X-Admin-Secret: boi4gohth*ie?t<ah5johhu3eis1Co1m' http://127.0.0.1:5000/imitated-purchase/xxx/7.0
{
  "success": true
}
$ curl http://127.0.0.1:5000/balance/xxx ;echo
7.0
$ curl 'http://127.0.0.1:5000/proxy/xxx/maps/api/place/nearbysearch/json?location=-33.8670,151.1957&radius=500'
{
   ...
   "status" : "OK"
}
$ curl http://127.0.0.1:5000/balance/xxx ;echo
6.8639984130859375
```
