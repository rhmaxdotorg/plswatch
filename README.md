# plswatch
Live, real-time data from [PulseChain](https://www.pulsechain.com) DEX transactions (Uniswap V2)

# intro
**plswatch** is a fork of [uniswap-v2-swaps-live.py](https://github.com/tradingstrategy-ai/web3-ethereum-defi/blob/master/scripts/uniswap-v2-swaps-live.py)

**plsnow** is a flask app that enables data from plswatch to be displayed in a web browser.

These can be used separately or together, for example you can run plswatch on the command line to get a feed of PulseChain transactions OR use plsnow to put that stream of data on the web with the help of NGINX.

# usage
This is how you can use plswatch from a command line console.

```
 $ ./plswatch.py
(see TXs for all tokens)

$ ./plswatch.py HEX

SWAP 324389.02 WPLS -> 1658.56 HEX [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
SWAP 313348.56 DAI -> 10003.82 HEX [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
SWAP 10003.82 HEX -> 1946241.79 WPLS [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
SWAP 560.72 HEX -> 7.62 INC [ 0x51c97d794340e5433d082049f69fef5df03719106a9550eb5ed645789113821e ]
...
```

# setup
And if is how you can use plswatch with plsnow for web stream of data.

**1) install web3-ethereum-defi and python misc stuff**

$ sudo apt install python-is-python3 -y

$ pip install "web3-ethereum-defi[data]" tqdm

Now plswatch can be used from command line, however if you want to use it with plsnow, flip the `WEB_MODE` to `True` in plswatch.py

```
# web configuration
WEB_MODE = True // default is False
PULSECHAIN_SCAN_TX_URL = "https://scan.pulsechain.com/tx/"
```

And also configure where your "home" directory is for the scripts and replace `/home/CHANGEME/plswatch` with the correct directory by modifying plsnow.py

```
# configuration
APP_HOME = '/home/CHANGEME/plswatch' # update for scripts location
```

**2) flask**

`$ pip install flask`

3) add low privileged user run scripts

`$ sudo useradd -m -s /bin/false -d /home/plsnow plsnow`

**3) gunicorn**

```
$ apt install gunicorn
$ pip install gevent
```

running plsnow app with gunicorn:

`$ sudo gunicorn --threads 8 -u plsnow plsnow:plsnow -b localhost:8080 -k gevent --timeout 60`

**4) DNS**

If using AWS cloud servers, you can buy and setup a domain using Route53.

Afterwards, confirm your IP on the server is directly (or maps in some way) to the domain you're using.

```
$ curl ifconfig.me
1.2.3.4

$ host www.plssite.com
www.plssite.com has address 1.2.3.4
```

**5) nginx**

`$ apt install nginx`

create a site config file and make sure this filename matches server_name EXACTLY

`$ sudo nano /etc/nginx/sites-available/plssite.com`

```
server {
    listen 80;
    server_name plssite.com;

	location / {
	    proxy_pass http://127.0.0.1:8080;
	    proxy_set_header Host $host;
	    proxy_set_header X-Real-IP $remote_addr;
	    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}
}
```

You can also add in some more security stuff like whitelisting only certain paths and making the request moot by redirecting them somewhere else if they try other paths or stuff.

```
server {
    listen 80;
    server_name plssite.com;

	location = / {
	    proxy_pass http://127.0.0.1:8080;
	    proxy_set_header Host $host;
	    proxy_set_header X-Real-IP $remote_addr;
	    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}

	location ^~ /static/ {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

	location ^~ /stream {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

	location / {
	    return 301 https://www.google.com;
	}
}
```

now restart the server to let changes take effect

```
$ sudo ln -s /etc/nginx/sites-available/plssite.com /etc/nginx/sites-enabled
$ sudo nginx -t
$ sudo systemctl restart nginx

$ sudo netstat -antp | grep nginx
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3534/nginx: master  
tcp6       0      0 :::80                   :::*                    LISTEN      3534/nginx: master  
```

Now you can recieve connections on port 80 and they will be forwarded to flask app running on port 8080.

**6) TLS certificate**
```
$ sudo apt install -y certbot python3-certbot-nginx
$ sudo certbot --nginx -d www.plssite.com
```

open the crobtab editor

`$ sudo crontab -e`

add certificate auto-renewal

`15 3 * * * /usr/bin/certbot renew --quiet`

**7) anonymize your logs and protect your user's privacy** (OPTIONAL)

You can stop logging user's IP address, referrer URL and browser user agent if you're using NGINX to serve traffic.

`$ sudo nano /etc/nginx/nginx.config`

add this to the http { } block (make sure you add near the top or at least BEFORE the includes near the end)

`log_format anonymized '[$time_local] "$request" $status $body_bytes_sent';`
                      
open the site config

`$ sudo nano /etc/nginx/sites-available/plssite.com`

add this to the server { } block

`access_log /var/log/nginx/access.log anonymized;`

check and reload the server configs
```
$ sudo nginx -t
$ sudo nginx -s reload
$ sudo systemctl reload nginx
```
