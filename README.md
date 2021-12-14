# Northwave Log4j CVE-2021-44228 checker

Friday 10 December 2021 a new Proof-of-Concept [1] addressing a Remote code Execution (RCE) vulnerability in the Java library 'log4j' [2] was published. This vulnerability has not been disclosed to the developers of the software upfront. The vulnerability is being tracked as CVE-2021-44228 [3]. More information on the vulnerability can be found in the Northwave Threat Response [4].

Northwave created a testing script that checks for vulnerable systems using injection of the payload in common HTTP headers and as a part of a HTTP GET request. Vulnerable systems are detected by listening for incoming DNS requests that contain a UUID specically created for the target. By listening for incoming DNS instead of deploying (for example) an LDAP server, we increase the likelyhood that vulnerable systems can be detected that have outbound traffic filtering in place. In practice, outbound DNS is often allowed. A high false negative rate is expected, please read the [disclamer](#DISCLAIMER).

## Coverage:

The following HTTP headers are covered:

* `X-Api-Version`
* `User-Agent`
* `Referer`
* `X-Druid-Comment`
* `Origin`
* `Location`
* `X-Forwarded-For`
* `Cookie`
* `X-Requested-With`
* `X-Forwarded-Host`
* `Accept`

For each injection, the following JNDI prefixes are checked:

* `jndi:rmi`
* `jndi:ldap`
* `jndi:dns`
* `jndi:${lower:l}${lower:d}ap`

## DISCLAIMER

Note that the script only performs two specific checks: *HTTP headers* and *HTTP GET request*. This will cause false negatives in cases where other headers, specific input fields, etcetera need to be targeted to trigger the vulnerability. This is very likely to happen.

**IMPORTANT:** In cases where the checker returns 'no vulnerability detected', proceed with filesystem checks as described in the Northwave Threat Response [4]. Only running this checker is insufficient to determine whether a system is vulnerable or not.

## Setting up a DNS server

First, we need a subdomain that we can use to receive incoming DNS requests. In this case we use the zone `log4jdnsreq.northwave.nl` and we deploy our script on `log4jchecker.northwave.nl`. Configure a DNS entry as follows:

```
log4jdnsreq 3600 IN  NS log4jchecker.northwave.nl.
```

We now set up a BIND DNS server on a Debian system using `apt install bind9` and add the following to the `/etc/bind/named.conf.options` file:

```
	recursion no;
	allow-transfer { none; };
```

This disables recusing as we do not want to run an open DNS server. Configure logging in `/etc/bind/named.conf.local` by adding the following configuration:

```
logging {
	channel querylog {
		file "/var/log/named/query.log";
		severity debug 3;
		print-time yes;
	};
	category queries { querylog;};
};
```
Don't forget to restart BIND using `systemctl restart bind9`. Check if the logging works by performing a DNS query for `xyz.log4jdnsreq.northwave.nl`. One or more queries should show up in `/var/log/named/query.log`.

## Verifying your DNS server

It's important to verify that nameserver lookups are actually logged. **This script cannot detect vulnerable sites unless your nameserver setup logs requests**

Test your server by performing a test lookup (idealy from a different machine):

```
dig test.log4jchecker.northwave.nl
```

You should not expect a response, but you should expect an entry in the log file (`cat /var/log/named/query.log`). This entry might look similar to:

```
14-Dec-2021 13:36:01.402 client @0x7f8b180a9b30 requester-ip#58755 (test.log4jchecker.northwave.nl): query: test.log4jchecker.northwave.nl IN A -E(0)DC (your-ip)
```

Don't continue unless a response is visible in the logs. The script won't detect vulnerabilities without.

## Running the script

Install any Python dependencies using `pip install -r requirements.txt`. Edit the script to change the following line to the DNS zone you configured:

```
HOSTNAME = "log4jdnsreq.northwave.nl"
```

You can now run the script by providing a single URL using the `-u` parameter or a list of urls using the `-l` parameter:

```
usage: nw_log4jcheck.py [-h] [-l LIST] [-u URL] [-w WAIT] [-t TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -l LIST, --list LIST  A text file with a list of URLs to check (one url per line)
  -u URL, --url URL     URL to check (for example: http://yoururl.com)
  -w WAIT, --wait WAIT  Number of seconds to wait before checking DNS logs (default: 15)
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP timeout in seconds to use (default: 5)
```

The last line of the output shows if the system was found to be vulnerable:

```
NO VULNERABILITY DETECTED. Proceed with on-server checking. No incoming DNS request to 3414db71-309a-4288-83d4-aa3f103db97c.log4jdns.northwave.nl was seen
```

In case no vulnerability was detected, proceed with filesystem checks as described in the Northwave Threat Response [4]. Again, only running this checker is insufficient to determine whether a system is vulnerable or not.

## License

Log4jcheck is open-sourced software licensed under the MIT license.

[1]: https://github.com/tangxiaofeng7/apache-log4j-poc
[2]: https://logging.apache.org/log4j/2.x/
[3]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228,==
[4]: https://log4shell.northwave.nl/
