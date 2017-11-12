# README

[![Build Status](https://travis-ci.org/librestack/gladd.svg?branch=master)](https://travis-ci.org/librestack/gladd)
<a href="https://scan.coverity.com/projects/2676">
  <img alt="Coverity Scan Build Status"
         src="https://scan.coverity.com/projects/2676/badge.svg"/>
</a>

See INSTALL for installation instructions.

See LICENSE for licensing information.

See CONFIGURATION for the syntax of gladd.conf

## Overview

gladd is a very simple HTTPD, intended to support scalable, RESTful,
API-driven web applications.  It's small, fast and simple.  The intention is
to provide the thinnest layer possible between a web front end and the Linux
operating system and database back ends.  Maximum flexibility the with lowest
overheads.

It isn't as friendly as many modern web frameworks.  It isn't built with MVC
in mind.  The principle of DRY is not very well supported.  gladd does not try
to hide away implementation details.  It doesn't write SQL for you, or give
you nice object mappings.

gladd assumes that you are writing a database-backed web application.  It
assumes that you know and love SQL, and that you want full control of how the
application is built and queries are executed.  It assumes that you care about
speed and scalability.

gladd makes heavy use of XML and XSLT, and familiarity with these is
recommended.

## Operation

```
gladd start	# Start gladd
gladd stop	# Stop gladd
gladd reload	# Reload configuration
```

NB: if persistent http connections are enabled, configuration will *not* be
reloaded for any live connections.  Any new connections will use the new
configuration.

## Configuration

gladd expects its configuration file to be at /etc/gladd.conf

There is presently no way to override the location of this file, but I expect
to add a --config option at some point.

## Logging

gladd logs to syslog.  Debugging can be turned on by setting "debug 1"
in gladd.conf.

## Support

If you're thinking of using gladd for your application, I'd love to hear from
you.  I'm happy to answer questions and will try to get you pointed in the
right direction.  Documentation so far is patchy, so please ask if anything is
confusing.

## BUGS

Please raise any bug reports on Github.
 https://github.com/brettsheffield/gladd/issues
Feel free to send me patches or pull requests and I'll do my best to respond. 
