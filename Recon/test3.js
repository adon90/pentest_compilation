var page = require('webpage').create();
var system = require('system');

var args = system.args;
if (args.length !== 3) {
  console.log('Usage: '+ args[0]+ ' <URL> ' + 'cookies_file>');
  phantom.exit(1);
}

var url = args[1];
var extracted = url.match(/http.*:\/\/(.*)/);
var domain = url.match(/http.*:\/\/(.*)\//);
var capture = extracted[1].replace( /\//g, '_');
var array_cookies = [];

var fs = require('fs');
var content = '';
var f = null;
var lines = null;

try {
    f = fs.open(args[2], "r");
    content = f.read().replace(/(\r\n|\n|\r)/gm,"");
} catch (e) {
    console.log(e);
}

if (f) {
    f.close();
}

if (content) {
    cookies = content.split(';');
    for (var i = 0, len = cookies.length; i < len; i++) {
	cookie_name = cookies[i].split('=')[0].replace(' ','');
	cookie_value = cookies[i].split('=')[1];
	cookie = {
	  'name': cookie_name,
	  'value': cookie_value,
	  'domain': domain[1],
	  'path': '/',
	  'httponly': true,
	  'secure': false,
	  'expires': (new Date()).getTime() + (1000 * 60 * 60)
	};
	array_cookies.push(cookie);
    }
}

phantom.cookies = array_cookies;

page.open(url, function() {
    setTimeout(function() {
        page.render(capture + '.png');
        phantom.exit();
    }, 200);
});

// Use: phantomjs --proxy=http://127.0.0.1:8080 test3.js http://www.miau.com/11 cookies.txt
