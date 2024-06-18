var express = require('express');
var i18n = require('i18n');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');

var app = express();

const addon = require('./build/Release/addon.node');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(i18n.init);
app.use(express.static(path.join(__dirname, 'public')));


app.get('/api/setup/:initialMessage', (req, res) => {
  const message = req.params.initialMessage; // Capture the route parameter
  // console.log('setupInput:', message);
  const result = addon.Setup(message); // Assuming someFunction takes a message and does something
  // console.log('setupOutput:', result);
  res.send({ result });
});

app.post('/api/hash/', (req, res) => {
  const hashInput = req.body.hashinfo; // Capture the route parameter
  console.log('hashInput:', hashInput);
  const result = addon.Hash(hashInput.A, hashInput.z, hashInput.e1, hashInput.e2, hashInput.message); // Assuming someFunction takes a message and does something
  res.send({ result });
  // console.log('hashOutput z:', result.z);
});

app.post('/api/adapt/', (req, res) => {
  const adaptInput = req.body.adaptinfo; // Capture the route parameter
  console.log('adaptInput h:', adaptInput.h);
  const result = addon.Adapt(adaptInput.A, adaptInput.trapdoor_r, adaptInput.trapdoor_e, adaptInput.z, adaptInput.e1, adaptInput.e2, adaptInput.message, adaptInput.h, adaptInput.new_message); // Assuming someFunction takes a message and does something
  console.log('adaptOutput new_h:', result.new_h);
  res.send({ result });
});

app.use('/', routes);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

i18n.configure({
  locales: ['en', 'zh-CN'],
  directory: __dirname + '/locales'
});

module.exports = app;
