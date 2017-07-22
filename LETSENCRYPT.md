# Lets Encrypt

Unless you're just testing, gladd should always run with TLS encryption.  An unencrypted API is generally considered a Bad Thing.  Generating certificates with [Let's Encrypt](letsencrypt.org) is quick and easy.

There are a couple of ways to do this.


## Using Certbot Standalone Mode (preferred)

This is the easiest method.  As this runs on port 80, it does not interfere with our live gladd on port 443 and means we don't have to leave anything listening permanently on port 80.

```
 sudo certbot certonly --standalone --preferred-challenges http -d example.com

```


## Using gladd

This method is less useful, as once we've created our certificate, we're never going to be listening on port 80 again, and certbot does not presently support renewals on port 443 with the webroot plugin.

Configure gladd (/etc/gladd.conf):
```
 port 80
 url static GET /.well-known/* /var/www/.well-known/
```

`gladd start`

and then call certbot:

`sudo certbot certonly --webroot -w /var/www/ -d example.com`


## Configuring gladd to Use Let's Encrypt Certs

Stop gladd:
`gladd stop`

Add some lines to /etc/gladd.conf:
```
port 443
ssl 5
ssl-key /etc/letsencrypt/live/example.com/privkey.pem
ssl-cert /etc/letsencrypt/live/example.com/fullchain.pem
```

Start gladd:
`gladd start`


## Automatic Renewal

Set up a cron job which runs `certbot renew` periodically.  You may want to wrap this in a script that drops the firewall on port 80 first, and puts it back up afterwards.


## See Also

* https://letsencrypt.org/gettingstarted/
* https://certbot.eff.org/
