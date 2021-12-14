Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user 

[![asciicast](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm.svg)](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm)

### New Arguments
- `-impersonate` specifies the target user to impersonate. When omitted, will select a random domain admin.
- `-computer-name` specifies the name of the new computer which will be create. When omitted, defaults to 'SAMTHEADMIN-XX` where XX is two random numbers.
- `-computer-pass` specifies the password for the new computer (probably not necessary to do this). When omitted, defaults to a random 12 character string. 
- `-cmd` **(required)**specifies the command to run. See next section.

### Selecting Command
This version of the script will execute whatever is specified in the `-cmd` flag with the forged service ticket. There are certain arguments which are always applied before / after the command, this is shown below for your situational awareness

```
# Whatever specifed in '-cmd' will replace <cmd>
f"KRB5CCNAME='<target-user>.ccache' <cmd> -target-ip <dc_ip> -dc-ip <dc_ip> -k -no-pass @'<domain-controller-fqdn>'
```

#### Check out 
- [CVE-2021-42287/CVE-2021-42278 Weaponisation ](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [sAMAccountName spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
- [WazeHell](https://github.com/WazeHell/sam-the-admin) - Original Author