#
# This is a sane place to start for a Varnish 4.x VCL file
# 
# It's 4.0 format, and contains basic tuning.
#
# Version - September 2014
# Author - Ian Monroe
#
#
######################################################################
# Marker to tell the VCL compiler that this VCL has been adapted to the
# new 4.0 format.
vcl 4.0;

# Backend definition.
# You'll want to change this to your own server settings.

backend default {
    .host = "0.0.0.0";
    .port = "80";
    .connect_timeout = 30s;
    .first_byte_timeout = 45s;
}

#######################################################################
# Client side customizations


# detectdevice.vcl - regex based device detection for Varnish
# http://github.com/varnish/varnish-devicedetect/
# Author: Lasse Karstensen <lasse@varnish-software.com>
include "devicedetect.vcl";

sub vcl_recv {

	# Let's find out what kind of device we're dealing with first, and tag it
	# with an req.http.X-UA-Device identifying it as a bot, smartphone, PC, or tablet
	# which is handy to know later on.
    call devicedetect; 

	# Forbid access to obnoxious robots.
	# Your choices may vary, update to reflect your preferences.
	if (req.http.user-agent ~ "(Gigablast|AhrefsBot|heritrix|YandexBot|TurnitinBot)"){
		return(synth(403,"Forbidden"));
	}
	
	if (req.method == "PRI") {
		/* We do not support SPDY or HTTP/2.0 */
		return (synth(405));
	}

	if (req.method != "GET" &&
		req.method != "HEAD" &&
		req.method != "PUT" &&
		req.method != "POST" &&
		req.method != "TRACE" &&
		req.method != "OPTIONS" &&
		req.method != "DELETE") {
		/* Non-RFC2616 or CONNECT which is weird. */
		return (pipe);
	}

	# a little protection against POST floods.  It ain't much, but it's better than nothing.
	# change the parameters it's searching on to reflect your site structure.
	if (req.method ~ "POST"){
		if ( (req.url ~ "(/trackback/|//)") ) {
				# Don't post to strange pages, dude.
				return(synth(403, "Forbidden"));
		}
		if ( !req.http.referer ){
				# Don't POST without a referer, bot.
				return(synth(403, "Forbidden"));
		}
		if ( req.http.referer ~ "(guestadd.asp)"){
				# Don't POST from pages that don't exist in our system, pal.
				return(synth(403, "Forbidden"));
		}
		if ( !req.http.Accept-Language && !req.http.Accept-Encoding && req.http.User-Agent=="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" ){
				# Oh, you KNOW you better not post with a suspicious User Agent, and no Accept headers, DDOS botnet.
				return(synth(403, "Forbidden"));
		}
		# OK, it looks legit.
		# Don't cache anything that's a legit POSTed form	
		return (pass);
	}

	if (req.method != "GET" && req.method != "HEAD") {
		/* We only deal with GET and HEAD by default */
		return (pass);
	}

	# Remove the Google Analytics and other added parameters, useless for our backend
	if (req.url ~ "(\?|&)(utm_source|_|utm_medium|utm_campaign|gclid|cx|ie|cof|siteurl)=") {
		set req.url = regsuball(req.url, "&(job_id|utm_source|utm_medium|utm_campaign|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
		set req.url = regsuball(req.url, "\?(job_id|utm_source|utm_medium|utm_campaign|gclid|cx|ie|cof|siteurl|_)=([A-z0-9_\-\.%25]+)", "?");
		set req.url = regsub(req.url, "\?&", "?");
		set req.url = regsub(req.url, "\?$", "");
	}
	
	# Always cache stuff from static resource directories
	if (req.url ~ "(images/|themes/)") {
		unset req.http.Cookie;
	}

	# Always cache these types.
	if (req.url ~ "\.(png|txt|gif|jpeg|jpg|ico|swf|css|js)$"){
		unset req.http.Cookie;
	}

	# Always cache for bots.
	if (req.http.X-UA-Device ~ "bot"){
		unset req.http.Cookie;
	}

	# Always drop cookies unless you're in the admin pages or search, and respect
	# any cookies that are used to opt-out of mobile pages, if necessary.
	if (!(req.url ~ "(admin_tools/|control_panel/|search/)") && !(req.http.cookie ~ "(mobile_optout)") ) {
	    unset req.http.Cookie;
	}
	
	# if you need to always pass a particular URL to the backend, go ahead and put it in here.
	# use caution though; most times you don't want to PASS if you can help it.
	if (req.url ~ "(includes/interstitial)"){
		return (pass);
	}
	
	# Don't cache anything in the control panel area, search or comments
	if (req.url ~ "(admin_tools/|control_panel/)"){
    	return (pass);
	}
	
	# Tag with custom headers for convenience.
	unset req.http.X-Forwarded-For;
	set req.http.X-Forwarded-For = client.ip; 

	if (req.http.Authorization || req.http.Cookie) {
        /* Not cacheable by default */
        return (pass);
    }

    return (hash);
}

#######################################################################
# Server side customizations

sub vcl_backend_response {
	# Set a decent grace period, in case there are server problems.
  	set beresp.grace = 1h;
}

sub vcl_backend_response {	

	# Remove cookies from everywhere except where the system requires them.
	# e.g., control panel pages, login pages, etc.
	if ( !(bereq.url ~ "(admin_tools/|control_panel/|login/|logout/)") ){
		unset beresp.http.Set-Cookie;
	}	

	# Never allow the server to set cookies with static resources
	if (bereq.url ~ "\.(png|txt|gif|jpeg|jpg|ico|swf|css|js)$") {
     	unset beresp.http.Set-Cookie;
  	}
	
	# Sculpt the headers to reflect the caching policy you want the client to use.    
	unset beresp.http.pragma;
	unset beresp.http.expires;
	
	# Set the baseline TTLs
	set beresp.http.cache-control = "max-age=600";
	set beresp.ttl = 10m;

	# Override the baseline TTLs on certain directories, if necessary
	if (bereq.url ~ "/rss"){
		set beresp.ttl = 10m;
	}	
	
	if (bereq.url ~ "(images/resources|themes/)"){
        set beresp.ttl = 24h;
    }
	
	# Override the baseline TTLs on certain filetypes
	if (bereq.url ~ "\.(png|txt|gif|jpeg|jpg|ico|swf|css|js)$") {
        set beresp.ttl = 24h;
    }	
	
	# Or for particular files.
	if (bereq.url ~ "favicon.ico"){
		set beresp.ttl = 744h;
	}
	
	# Override the baseline TTL on stuff that you don't ever want to cache
	if (bereq.url ~ "(control_panel/|admin_tools/)"){
		set beresp.http.cache-control = "private, max-age=0, no-cache";
	}

    
    if (beresp.ttl <= 0s ||
      beresp.http.Set-Cookie ||
      beresp.http.Surrogate-control ~ "no-store" ||
      (!beresp.http.Surrogate-Control &&
        beresp.http.Cache-Control ~ "no-cache|no-store|private") ||
      beresp.http.Vary == "*") {
        /*
        * Mark as "Hit-For-Pass" for the next 2 minutes
        */
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
    }
    return (deliver);
}

#######################################################################
# Below are the rest of the standard VCL functions with sane defaults.
# You may override them if you wish, but you probably won't need to.


#######################################################################
# Client side defaults

sub vcl_pipe {
    # By default Connection: close is set on all piped requests, to stop
    # connection reuse from sending future requests directly to the
    # (potentially) wrong backend. If you do want this to happen, you can undo
    # it here.
    # unset bereq.http.connection;
    return (pipe);
}

sub vcl_pass {
    return (fetch);
}

sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    return (lookup);
}

sub vcl_purge {
    return (synth(200, "Purged"));
}

sub vcl_hit {
    if (obj.ttl >= 0s) {
        // A pure unadultered hit, deliver it
        return (deliver);
    }
    if (obj.ttl + obj.grace > 0s) {
        // Object is in grace, deliver it
        // Automatically triggers a background fetch
        return (deliver);
    }
    // fetch & deliver once we get the result
    return (fetch);
}

sub vcl_miss {
    return (fetch);
}

sub vcl_deliver {
	if (obj.hits > 0) {
                set resp.http.X-Cache = "HIT";
        } else {
                set resp.http.X-Cache = "MISS";
        }
	set resp.http.X-Fwd-IP = client.ip;
	
	set resp.http.X-UA-Device = req.http.X-UA-Device;
    return (deliver);
}

/*
 * We can come here "invisibly" with the following errors: 413, 417 & 503
 */
sub vcl_synth {
    set resp.http.Content-Type = "text/html; charset=utf-8";
    set resp.http.Retry-After = "5";
    synthetic( {"<!DOCTYPE html>
<html>
  <head>
    <title>"} + resp.status + " " + resp.reason + {"</title>
  </head>
  <body>
    <h1>Error "} + resp.status + " " + resp.reason + {"</h1>
    <p>"} + resp.reason + {"</p>
    <h3>Guru Meditation:</h3>
    <p>XID: "} + req.xid + {"</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
"} );
    return (deliver);
}

#######################################################################
# Backend Fetch defaults

sub vcl_backend_fetch {
    return (fetch);
}

sub vcl_backend_error {
    set beresp.http.Content-Type = "text/html; charset=utf-8";
    set beresp.http.Retry-After = "5";
    synthetic( {"<!DOCTYPE html>
<html>
  <head>
    <title>"} + beresp.status + " " + beresp.reason + {"</title>
  </head>
  <body>
    <h1>Error "} + beresp.status + " " + beresp.reason + {"</h1>
    <p>"} + beresp.reason + {"</p>
    <h3>Guru Meditation:</h3>
    <p>XID: "} + bereq.xid + {"</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
"} );
    return (deliver);
}

#######################################################################
# Housekeeping

sub vcl_init {
    return (ok);
}

sub vcl_fini {
    return (ok);
}
