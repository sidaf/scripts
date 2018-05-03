"use strict";
var page = require('webpage').create(),
    system = require('system'),
    address, host_header, output, size, pageWidth, pageHeight;

if (system.args.length < 3 || system.args.length > 5) {
    console.log('Usage: webshot.js URL host_header filename [paperwidth*paperheight|paperformat] [zoom]');
    console.log('  paper (pdf output) examples: "5in*7.5in", "10cm*20cm", "A4", "Letter"');
    console.log('  image (png/jpg output) examples: "1920px" entire page, window width 1920px');
    console.log('                                   "800px*600px" window, clipped to 800x600');
    phantom.exit(1);
} else {
    address = system.args[1];
    host_header = system.args[2];
    output = system.args[3];

    page.settings.resourceTimeout = 15000; // 15 seconds
    page.onResourceTimeout = function(e) {
        //e.url
        console.log('timeout waiting for a response.');
        phantom.exit(1);
    };

    page.viewportSize = { width: 600, height: 600 };
    if (system.args.length > 4 && system.args[3].substr(-4) === ".pdf") {
        size = system.args[4].split('*');
        page.paperSize = size.length === 2 ? { width: size[0], height: size[1], margin: '0px' }
                                           : { format: system.args[4], orientation: 'portrait', margin: '1cm' };
    } else if (system.args.length > 4 && system.args[4].substr(-2) === "px") {
        size = system.args[4].split('*');
        if (size.length === 2) {
            var pageWidth = parseInt(size[0], 10),
                pageHeight = parseInt(size[1], 10);
            page.viewportSize = { width: pageWidth, height: pageHeight };
            page.clipRect = { top: 0, left: 0, width: pageWidth, height: pageHeight };
        } else {
            var pageWidth = parseInt(system.args[4], 10),
                pageHeight = parseInt(pageWidth * 3/4, 10); // it's as good an assumption as any
            page.viewportSize = { width: pageWidth, height: pageHeight };
        }
    }
    if (system.args.length > 5) {
        page.zoomFactor = system.args[5];
    }

    var parser = document.createElement('a');
    parser.href = address;

    page.onResourceRequested = function(request, network) {
        // Intercept request here. If request.url starts with URL, then insert custom host header.
        var re1 = new RegExp('^(http|https)://' + parser.host, "gi");
        if (request.url.match(re1)) {
            //console.log('Changing from ' + request.url + ' to ' + host_header);
            network.setHeader('Host', host_header);
        }
        var re2 = new RegExp('^(http|https)://' + host_header, "gi");
        var re3 = new RegExp(host_header, "gi")
        if (request.url.match(re2)) {
            //console.log('Changing from ' + request.url + ' to ' + parser.host);
            var newURL = request.url.replace(re3, parser.host);
            request.changeUrl(newURL);
            network.setHeader('Host', host_header);
        }
    };
    page.open(address, function (status) {
        if (status !== 'success') {
            console.log('unable to load website.');
            phantom.exit(1);
        } else {
            window.setTimeout(function () {
                page.render(output);
                phantom.exit();
            }, 2000);
        }
    });
}
