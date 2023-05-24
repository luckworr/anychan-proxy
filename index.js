// var proxy = require('cors-anywhere')
var proxy = require('./lib/cors-anywhere')

var config = require('./config.json')

// Heroku: Listen on a specific host passed as the `HOST` environment variable.
var host = process.env.HOST || config.host
// Heroku: Listen on a specific port passed as the `PORT` environment variable.
var port = process.env.PORT || config.port

proxy.createServer({
  originWhitelist: config.origins, // Allow origins.
  requireHeader: ['origin', 'x-requested-with'], // The HTTP request must come from a web browser.
}).listen(port, host, function() {
  console.log('Running CORS proxy at http(s)://' + (host === '0.0.0.0' ? '<any-host>' : host) + ':' + port)
})
