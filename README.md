# CORS Proxy

This is a simple CORS proxy used for [anychan](https://gitlab.com/catamphetamine/anychan) demo.

Based on [`cors-anywhere`](https://github.com/Rob--W/cors-anywhere) with some changes.

## Configuration

Configuration is very simple and should be specified in `config.json` file.

* `host: string` — The hostname to listen on. Example: `"0.0.0.0"` means "listen on all possible hostnames" (like `localhost`). This parameter is ignored when `HOST` environment variable is set.

* `port: number` — The port to listen on. Example: `8080`. This parameter is ignored when `PORT` environment variable is set.

* `allowedRequestOrigins?: string[]` — An explicit "whitelist" of allowed HTTP origins to accept proxy requests from. If this configuration parameter is specified then only those HTTP origins will be allowed to send HTTP requests to this proxy server. Otherwise, all incoming HTTP requests are allowed, regardless of the HTTP origin they came from.

* `cookies?: boolean` — Set to `true` to enable cookies. Cookies are disabled by default. Enabling cookies requires setting both `allowedRequestOrigins` and `shareCookiesBetweenAllowedRequestOrigins` parameters.

* `shareCookiesBetweenAllowedRequestOrigins?: boolean` — An explicit "opt-in" flag that is required to be set to `true` when enabling cookies. The only purpose of this flag is to make it explicit that cookies are shared between all `allowedRequestOrigins`.

## Cookies

In order to enable cookies, one would also have to specify an explicit "whitelist" of allowed HTTP request origins. The reason why cookies can't just be enabled for any HTTP request origin is that due to the inherent limitations of CORS proxying, all cookies are shared between all HTTP request origins because from the user's web browser's point of view, all of them are just the same CORS proxy website all the time, because what CORS proxy does is it tricks the web browser into thinking that it always communicates with the permissive CORS proxy website rather than the non-permissive target website.

To see how allowing any HTTP request origin would be a security vulnerability in this case, consider a hacker luring people into visiting their `https://hacker.com` website via the CORS proxy by providing a "phishing" link `https://proxy.com/https://hacker.com/steal-cookies` somewhere for an unsuspecting casual user to click it, resulting in stealing all their cookies for all other websites that the user has been visiting through `https://proxy.com` because their web browser would've associated all those cookies to the same `https://proxy.com` website.

For that reason, enabling `cookies: true` flag also requires setting up `allowedRequestOrigins` and also explicitly enabling the `shareCookiesBetweenAllowedRequestOrigins: true` flag.

## Run

```
npm install
npm start
```

## Use

To proxy a URL through the CORS proxy, one could send an HTTP request to:

* `/<url>`
* `/?url=<encodeURIComponent(url)>`

For example, if `host` is set to `"0.0.0.0"` and `port` is set to `8080`, then to proxy `https://google.com/page` URL through the CORS proxy, one could send an HTTP request to:

* `http://localhost:8080/https://google.com/page`
* `http://localhost:8080/?url=https%3A%2F%2Fgoogle.com%2Fpage`

## Hosting

This proxy could be hosted at Vercel for free. See an [article](https://geshan.com.np/blog/2021/01/free-nodejs-hosting/) on free Node.js hosting for more details.

## Redirects

Redirects are automatically followed. For debugging purposes, each followed redirect results
in the addition of a `X-CORS-Redirect-n` header, where `n` starts at `1`. These headers are not
accessible by the `XMLHttpRequest` API.

After 5 redirects, redirects are not followed any more. The redirect response is sent back
to the browser, which can choose to follow the redirect (handled automatically by the browser).

## Headers

The requested URL is available in the `X-Request-URL` response header.
The final URL, after following all redirects, is available in the `X-Final-URL` response header.

To prevent the use of the proxy for casual browsing, the API requires either the `Origin`
or the `X-Requested-With` header to be set.

## Changes

`lib/cors-anywhere.js` is a modified version of the original `cors-anywhere` package.

<details>
<summary>Added <code>access-control-allow-origin</code> and <code>access-control-allow-credentials</code> headers.</summary>

######

```js
var config = require('../config.json');
var allowedOrigins = config.origins;
```

```js
function withCORS(headers, request) {
  var allowedOrigin = allowedOrigins[0];
  if (allowedOrigins.indexOf(request.headers['origin']) >= 0) {
    allowedOrigin = request.headers['origin'];
  }
  headers['access-control-allow-origin'] = allowedOrigin;
  headers['access-control-allow-credentials'] = true;
  ...
}
```
</details>

<details>
<summary>Added <code>/stats</code> endpoint for getting a list of most recent HTTP requests.</summary>

######

```js
function getHandler() {
  ...

  var latestRequests = [];
  var MAX_LATEST_REQUESTS = 5000;

  return function(req, res) {
    ...
    if (req.url === '/stats') {
      res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
      res.end(randomizeIps(latestRequests).map(({ time, ip, location }) => {
        return `${formatDate(new Date(time))} · ${ip} · ${location.host}${location.pathname}`
      }).join('\n'));
      return;
    }
    ...
  }
}
```
</details>

<details>
<summary>Added support for <code>url</code> query parameter.</summary>

######

```js
function parseURL(url) {
  return new URL(url);
}
```

```js
function isRequestedOverHttps(req) {
  // https://stackoverflow.com/questions/10348906/how-to-know-if-a-request-is-http-or-https-in-node-js
  return req.connection.encrypted || /^\s*https/.test(req.headers['x-forwarded-proto']);
}

function getOrigin(req) {
  // Get the "origin" of the incoming HTTP request.
  // Example: "https://proxy.com".
  //
  // "Origin" header might not be present.
  // "Host" header is always present.
  //
  return req.headers.origin || `http${isRequestedOverHttps(req) ? 's' : ''}://${req.headers.host}`;
}
```

```js
function getHandler(options, proxy) {
  ...

  return function(req, res) {
    ...

    // "Host" HTTP header is always present.
    // "Origin" HTTP header might not be present.
    // The actual protocol is of no significance here.
    var requestLocation = parseURL(getOrigin(req) + req.url);
    var targetUrl = requestLocation.searchParams.get('url') || requestLocation.pathname.slice(1) + requestLocation.search + requestLocation.hash;

    // Get the "origin" of the incoming HTTP request.
    // Example: "https://proxy.com".
    //
    // "Origin" header might not be present.
    // "Host" header is always present.
    //
    var origin = getOrigin(req);

    ...
  }
}
```

```js
function proxyRequest(req, res, proxy) {
  var location = req.corsAnywhereRequestState.location;

  req.url = location.pathname + location.search + location.hash;

  ...
}
```
</details>

<details>
<summary>Allow cookies when the origin is whitelisted.</summary>

######

```js
function getHandler(options, proxy) {
  ...

  return function(req, res) {
    ...

    req.isWhitelistedOrigin = corsAnywhere.originWhitelist.indexOf(origin) >= 0;

    // Only allows forwarding cookies when the HTTP request
    // comes from an explicitly whitelisted HTTP origin.
    if (!req.isWhitelistedOrigin) {
      // "Cookie2" HTTP header is deprecated.
      // https://www.geeksforgeeks.org/http-headers-cookie2/
      ['cookie', 'cookie2'].forEach(function(header) {
        delete req.headers[header];
      });
    }

    ...
  }
}
```

```js
function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
  ...

  // Strip cookies when the origin is not whitelisted.
  if (!req.isWhitelistedOrigin) {
    delete proxyRes.headers['set-cookie'];
    // "Set-Cookie2" HTTP header is deprecated as of RFC6265 and should not be used.
    // https://stackoverflow.com/questions/9462180/difference-between-set-cookie2-and-set-cookie
    delete proxyRes.headers['set-cookie2'];
  }
}
```
</details>

Plus some minor fixes.