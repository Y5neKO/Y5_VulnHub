### BYOB (Build Your Own Botnet) Unauthenticated RCE

This exploit works by spoofing an agent exfiltrating a file to overwrite the sqlite database and bypass authentication.  After authentication is bypassed, a command injection vulnerability is exploited in the payload builder page.

Full analysis: https://blog.chebuya.com/posts/unauthenticated-remote-command-execution-on-byob/

https://github.com/user-attachments/assets/9b6ab096-389e-4060-8eb4-2bd2dc3634c8

```
python3 exploit.py -h
usage: exploit.py [-h] -t TARGET [-u USERNAME] [-p PASSWORD] [-A USER_AGENT] -c COMMAND

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        The target URL of the BYOB admin panel
  -u USERNAME, --username USERNAME
                        The username to set for the new admin account
  -p PASSWORD, --password PASSWORD
                        The password to set for the new admin account
  -A USER_AGENT, --user-agent USER_AGENT
                        The user-agent to use for requests
  -c COMMAND, --command COMMAND
                        The command to execute on the BYOB server
```
