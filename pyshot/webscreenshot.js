/***
# This file is part of webscreenshot.
#
# Copyright (C) 2014, 2019 Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# webscreenshot is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webscreenshot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with webscreenshot.	 If not, see <http://www.gnu.org/licenses/>.
***/

var Page = (function(custom_headers, http_username, http_password, image_width, image_height, image_format, image_quality, ajax_timeout, max_timeout, crop_rect, custjs) {
	var opts = {
		username: http_username || '',
		password_str: http_password || '',
		width: image_width || 1200,
		height: image_height || 800,
		format: image_format || 'jpg',
		quality: image_quality || 75,
		cropRect: crop_rect || false,
		ajaxTimeout: ajax_timeout ||1400,
		maxTimeout: max_timeout || 1800,
		custJs: custjs || '',
		httpAuthErrorCode: 2
	};

	var requestCount = 0;
	var forceRenderTimeout;
	var ajaxRenderTimeout;
	var errorCode = 0;

	var page = require('webpage').create();
	var redirectURL = null;
	page.viewportSize = {
		width: opts.width,
		height: opts.height
	};

	if (opts.cropRect) {
		page.clipRect = {
			top: opts.cropRect[0],
			left: opts.cropRect[1],
			width: opts.cropRect[2],
			height: opts.cropRect[3]
		};
	}

	page.settings.userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36';
	page.settings.userName = http_username;
	page.settings.password = http_password;
	page.settings.resourceTimeout = max_timeout;
	page.customHeaders = custom_headers;
	page.onInitialized = function() {
		page.customHeaders = {};
	};

	// Silence confirmation messages and errors
	page.onConfirm = page.onPrompt = page.onError = noop;

	page.onError = function(msg){
	   console.log('[-] Javascript error: ' + msg);
	};

	page.onResourceRequested = function(request) {
		requestCount += 1;
		clearTimeout(ajaxRenderTimeout);
	};

	// page.onNavigationRequested = function(url, type, willNavigate, main) {
 //       if (main) {
 //           console.log("URL: " + url);
 //           console.log("redirect caught");
 //       }
 //    };

	page.onResourceError = function(errorData) {
	   //console.log('[-] Unable to load resource (URL:' + errorData.url + ')');
	   //console.log('[-] Error code: ' + errorData.errorCode + '. Description: ' + errorData.errorString);
	   errorCode = errorData.errorCode
	};

	page.onResourceReceived = function(response) {

		if (response.redirectURL) {
			redirectURL = response.redirectURL;
			//console.log("[*] Redirect: " + redirectURL);
		}

		// Set status code
		page.status = response.status;

		if (response.stage && response.stage == 'end' && response.status == '401') {
			page.failReason = '401';
		}

		if (!response.stage || response.stage === 'end') {
			requestCount -= 1;
			if (requestCount === 0) {
				ajaxRenderTimeout = setTimeout(renderAndExit, opts.ajaxTimeout);
			}
		}
	};

	var api = {};

	api.render = function(url, output_file_prefix) {
		opts.file = output_file_prefix + "." + opts.format;

		page.open(url, function(status) {


			// Make sure we don't change the IP address
			if (redirectURL) {

				redirect_url_obj = parseURL(redirectURL);
				orig_url_obj = parseURL(url);

				redirect_hostname = redirect_url_obj['hostname']
				orig_hostname = orig_url_obj['hostname']

				//console.log("[*] Original Hostname: " + orig_hostname);
				//console.log("[*] Redirect URL: " + redirect_hostname);

				//if ( orig_hostname !== redirect_hostname ) {
				//	console.log("[*] Redirected to different host '" + redirect_hostname + "'. Fixing up.");
				//	redirect_url_obj['hostname'] = orig_url_obj['hostname'];
				//	redirectURL = toURL(redirect_url_obj);
					//console.log("[*] Redirect now: " + redirectURL);
				//} else {
				//	console.log("[*] Redirect URL: " + redirectURL);
				//}

				var customHeaders = page.customHeaders;
				//original_host_header = page.customHeaders['Host'];
				//console.log("[*] Host header: " + original_host_header);

				//if ( original_host_header === undefined || original_host_header !== redirect_hostname ) {
				//	console.log("[*] Host header needs to be updated");
					//Update the Host header 
				customHeaders['Host'] = redirect_hostname;
				//}

				// Clear the timeout so the previous call does not stop the next one
				clearTimeout(ajaxRenderTimeout);

				var page2 = Page(customHeaders, opts.username, opts.password_str, opts.width, opts.height, opts.format, opts.quality, opts.ajaxTimeout, opts.maxTimeout, opts.cropRect, opts.custJs);
				page2.render(redirectURL, output_file_prefix);
				return;

			}

			var fs = require('fs');
			var ret_data = {'status_code' : page.status, 'file_path' : opts.file };
			fs.write(output_file_prefix + '.json', JSON.stringify(ret_data), 'w');

			if (status !== "success") {
				if (page.failReason && page.failReason == '401') {
					// Specific 401 HTTP code hint
					//console.log("[-] Exiting for 401")
					phantom.exit(opts.httpAuthErrorCode);
				} else {
					//console.log("[-] Exiting for another reason: " + page.failReason)
					// All other failures
					phantom.exit(errorCode);
				}
			} else {
				//console.log("[*] Rendering page: '" + url);
				forceRenderTimeout = setTimeout(renderAndExit, opts.maxTimeout);
			}

		});

	};

	function parseURL(url) {

		const url_arr = url.split("://");
		proto = url_arr[0];
		hostname_path = url_arr[1];
		//console.log("Proto: " + proto);

		const host_idx = hostname_path.indexOf("/");
		hostname_port = hostname_path;
		path = '';
		if( host_idx > 0 ){
			hostname_port = hostname_path.substring(0, host_idx)
			path = hostname_path.substring(host_idx+1)
		}

		//const hostname_path_arr = hostname_path.indexOf("/");
		//hostname_port = hostname_path_arr[0];
		//path = hostname_path_arr[1];

		const hostname_port_arr = hostname_port.split(":");
		hostname = hostname_port_arr[0];

		var port = undefined
		if (hostname_port_arr.length > 1 ){
		    port = hostname_port_arr[1];
		  	//console.log("Port changed on redirect: " + port);	
		}

		var url_dict = {};
		url_dict["proto"] = proto;
		url_dict["hostname"] = hostname;

		if( port !== undefined ){
			url_dict["port"] = port;
		}

		url_dict["path"] = path;

		return url_dict;

	}

	function toURL(url_obj) {

		var returnURL = "";

		returnURL = url_obj["proto"];
		returnURL += "://";
		returnURL += url_obj["hostname"];

		if( "port" in url_obj){
		 	returnURL += ":" + url_obj["port"];
		}

		if( "path" in url_obj){
		 	returnURL += "/" + url_obj["path"];
		}

		return returnURL;
	}


	function renderAndExit() {

		// Trick to avoid transparent background
		page.evaluate(function() {
			document.body.bgColor = 'white';
		});
		if (custjs)
		{
			var fs = require('fs');
			var content = fs.read(custjs);
			page.evaluateJavaScript(content);
		}

		// Sanitize
		var filepath = opts.file;
		page.render(filepath, {format: opts.format, quality: opts.quality});

		//Clear timeout threads
		clearTimeout(ajaxRenderTimeout);
		phantom.exit(0);
	}

	function noop() {}

	return api;
});

function main() {

	var system = require('system');
	var p_url = new RegExp('url_capture=(.*)');
	var p_outfile = new RegExp('output_file_prefix=(.*)');
	var p_header = new RegExp('header=(.*)');

	var p_http_username = new RegExp('http_username=(.*)');
	var http_username = '';

	var p_http_password = new RegExp('http_password=(.*)');
	var http_password = '';

	var p_width = new RegExp('width=(.*)');
	var image_width = '';

	var p_height = new RegExp('height=(.*)');
	var image_height = '';

	var p_format = new RegExp('format=(.*)');
	var image_format = '';

	var p_quality = new RegExp('quality=(.*)');
	var image_quality = '';

	var p_ajaxtimeout = new RegExp('ajaxtimeout=(.*)');
	var ajax_timeout = '';

	var p_maxtimeout = new RegExp('maxtimeout=(.*)');
	var max_timeout = '';

	var p_crop = new RegExp('crop=(.*)');
	var crop_rect = '';

	var p_custjs = new RegExp('customjs=(.*)');
	var custjs = '';

	var temp_custom_headers = {
		// Nullify Accept-Encoding header to disable compression (https://github.com/ariya/phantomjs/issues/10930)
		'Accept-Encoding': ' '
	};

	for(var i = 0; i < system.args.length; i++) {
		if (p_url.test(system.args[i]) === true)
		{
			var URL = p_url.exec(system.args[i])[1];
		}

		if (p_outfile.test(system.args[i]) === true)
		{
			var output_file_prefix = p_outfile.exec(system.args[i])[1];
		}

		if (p_http_username.test(system.args[i]) === true)
		{
			http_username = p_http_username.exec(system.args[i])[1];
		}

		if (p_http_password.test(system.args[i]) === true)
		{
			http_password = p_http_password.exec(system.args[i])[1];
		}

		if (p_header.test(system.args[i]) === true)
		{
			var header = p_header.exec(system.args[i]);
			var p_header_split = header[1].split(': ', 2);
			var header_name = p_header_split[0];
			var header_value = p_header_split[1];

			temp_custom_headers[header_name] = header_value;

		}

		if (p_width.test(system.args[i]) === true)
		{
			image_width = p_width.exec(system.args[i])[1];
		}

		if (p_height.test(system.args[i]) === true)
		{
			image_height = p_height.exec(system.args[i])[1];
		}

		if (p_format.test(system.args[i]) === true)
		{
			image_format = p_format.exec(system.args[i])[1];
		}

		if (p_quality.test(system.args[i]) === true)
		{
			image_quality = p_quality.exec(system.args[i])[1];
		}

		if (p_ajaxtimeout.test(system.args[i]) === true)
		{
			ajax_timeout = p_ajaxtimeout.exec(system.args[i])[1];
		}

		if (p_maxtimeout.test(system.args[i]) === true)
		{
			max_timeout = p_maxtimeout.exec(system.args[i])[1];
		}

		if (p_crop.test(system.args[i]) === true)
		{
			crop_rect = p_crop.exec(system.args[i])[1].split(',');
		}

		if (p_custjs.test(system.args[i]) === true)
		{
			custjs = p_custjs.exec(system.args[i])[1].split(',');
		}
	}

	if (typeof(URL) === 'undefined' || URL.length == 0 || typeof(output_file_prefix) === 'undefined' || output_file_prefix.length == 0) {
		console.log("Usage: phantomjs [options] webscreenshot.js url_capture=<URL> output_file_prefix=<output_file> [header=<custom header> http_username=<HTTP basic auth username> http_password=<HTTP basic auth password>]");
		console.log('Please specify an URL to capture and an output png filename !');

		phantom.exit(1);
	}
	else {
		var page = Page(temp_custom_headers, http_username, http_password, image_width, image_height, image_format, image_quality, ajax_timeout, max_timeout, crop_rect, custjs);
		page.render(URL, output_file_prefix);
	}
}

main();
