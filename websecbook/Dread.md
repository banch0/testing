# DREAD

The five variables for calculating risk in the DREAD model are:

* Damage potential: Assesses how much damage an exploited
vulnerability could cause. The more damage, the higher the risk.

* Reproducibility: Determines the degree of difficulty of
reproducing or making an exploit happen. The easier the
reproduction, the higher the risk.

* Exploitability: Evaluates the degree of expertise, time, and tools
needed to execute the exploit. The easier the process, the higher
the risk.

* Affected users: Calculates the number and importance of users
that could be affected. The larger the number and the higher the
importance, the higher the risk.

* Discoverability: Assesses the ease of identifying the threat, which
might range from one that is obvious and is shown in a web
browser address bar to one that is not documented and is very
difficult to detect. The more difficult to detect, the higher the risk.

# Sources of Web Application Security Vulnerability

Information

The severity of many vulnerabilities is well documented and publicly available. 
Several of the most useful resources for finding this information are

•	 Open Web Application Security Project (OWASP):
(www.owasp.org) Based on information sent to the organization
from security experts around the world, this site publishes lists of
the most severe web application vulnerabilities.
•	 National Vulnerability Database (NVD): (http://nvd.nist.gov/)
Sponsored by the National Institute of Standards and Technology,
this vulnerability resource focuses on servers and networks. Its
Common Vulnerability Scoring System (CVSS) provides an open
framework for communicating the characteristics and impacts of
IT vulnerabilities.
•	 US Computer Emergency Readiness Team (US CERT):
(www.us-cert.gov) This site is maintained by the National
Homeland Security’s team that leads the cybersecurity efforts in
United States .
•	 Web Application Security Consortium (WASC):
(www.webappsec.org/) This site is run by WASC, a not-for-profit
organization made up of an international group of experts,
industry practitioners, and organizational representatives who
produce open-source and widely agreed-upon best-practice
security standards for the World Wide Web.

# Web Application Vulnerabilities and the Damage They Can Cause

The obvious risks to a security breach are that unauthorized individuals: 
1) can gain access to restricted information and 2) may be able to escalate 
their privileges in order to compromise the application and the entire 
application environment. The areas that can be compromised include user 
and system administration accounts.

This chapter identifies the major classes of web application vulnerabilities,
gives some examples of actual vulnerabilities found in real-life web 
application audits, and describes their associated level of risk. The 
classes are:
•	 authentication
•	 session management
•	 access control
•	 input validation
•	 redirects and forwards
•	 injection flaws
•	 unauthorized view of data
•	 error handling
•	 cross-site scripting
•	 security misconfigurations
•	 denial of service
•	 related security issues

## Lack of Sufficient Authentication

Risk level: HIGH

Correctly checking authentication credentials and then providing access to a web
application accordingly are paramount operations for a server to perform when providing
security and privacy.
Prior to accessing a web application, a server should require end users to
authenticate themselves and confirm they are in fact who they purport to be.

## Weak Password Controls

Risk level: HIGH

Passwords are one of the most important elements to Internet security. They must
be protected and changed regularly because an attacker or malicious user can mount a
password-guessing attack (e.g., through brute force or a dictionary) that can have a high
probability of success. Once a password has been guessed, the attacker can then log on to
the application using the “guessed” account credentials and operate on the user’s behalf
(e.g., change the user’s profile, mount attacks using fields available only to authenticated
users, access sensitive information).

## Passwords Submitted Without Encryption

Risk level: HIGH

Passwords submitted over an unencrypted connection are vulnerable to capture by
an attacker that is suitably positioned on the network to monitor and capture traffic. This
includes any malicious party located on the user’s own network, within her ISP, within
the ISP used by the application, and within the application’s hosting infrastructure, as
well as networks along the communications path.

## Username Harvesting

Risk level: HIGH

Usernames need to be protected and never shared, as they can be used to try to
obtain unauthorized access to an account.

Like passwords, usernames are susceptible to being harvested with a brute-force
method or by simply finding the e-mail address associated with them by doing research
on the Internet.

## Weak Session Management

Risk level: LOW-HIGH

Session management is something that most users are unaware of, but this is an
essential security methodology for foiling hackers from attempting to break into and
take control of a session. The idea is for a server to be able to regularly verify that the user
conducting the interaction or conversation is the one the server thinks it is.
If an application doesn’t use transport-level encryption (SSL or TLS) to protect all
sensitive communications passing between a client and a server, the communications
between them is more highly susceptible to a security breach. Communications are
intended to include the login mechanism and related functions where sensitive data can
be accessed and where privileged actions are performed.

TLS is the successor of SSL. TLS is more secure than its predecessor.
However, SSL is more widely used than TLS.

[Hashing] is a form of one-way encryption. The idea is to protect critical information
such as passwords by never having to store them, something that allows them to be
compromised. By hashing them and storing the hashed value instead of storing the
actual critical information, the risk to the critical information is reduced. The recipient
must recreate the hashing process and compare hashed values to make sure the critical
information is correct. Salting is additional protection for hashing. [Salting] is adding
random extra information into the critical data before it is hashed. This process makes it
more difficult for a person of malintent to guess critical information.


## Weak SSL Ciphers Support

Risk level: HIGH

A standard method of securing communications between a user and a web application
is the use of encryption. If the method of encryption is outdated or weak, then
the security is weak. 

There are too many examples we have seen during the audit process where a remote
service supports the use of weak SSL ciphers. An attacker could break the weak cipher’s
encryption and perform a “man-in-the-middle” attack to eavesdrop on a user’s session.
As previously mentioned, SSL is a standard security technology or protocol for establishing
an encrypted link between a server and a client. SSL uses encryption technology to secure
both the communications link (referred to as a tunnel) and the data being transmitted.
The cipher for SSL is the encryption methodology that a particular version of SSL is using.
SSL can utilize a variety of ciphers, some of which are more secure than others.

## Information Submitted Using the GET Method

Risk level: MEDIUM

There are several methods that HTTP utilizes to make requests for information,
including GET and POST. Since HTTP is unencrypted, it is important for web application
programmers to consider the security weaknesses inherent in its use of the GET method,
making GET a poor choice for transmitting sensitive data such as user names and
passwords. Not to drill in too deeply, but it is the clear-text nature of the HTTP protocol
that makes it insecure. GET displays data in clear text in the URL, and the URL can in turn
be seen in server logs, in client browser histories, and in any forward or reverse proxy
servers between a user and a web application server. This makes sensitive data retrievable
for unauthorized persons.

## Self-Signed Certificates, Insecure Keys, and Passwords

Risk level: HIGH

Certificates, keys, and passwords are fundamental to Internet security. The most
reliable certificates are managed by third-party certificate authorities. Self-signed and
self-managed versions are not as trustworthy. They are good cover for an imposter posing
as a valid organization, and the SSL or TLS man-in-the-middle attack often uses self-signed
certificates to eavesdrop on SSL or TLS connections. A man-in-the-middle attack is done
by an eavesdropper of a communication session that subsequently inserts itself into

## Username Harvesting Applied to Forgotten Password Process

Risk level: HIGH

A relatively simple way for hackers to gain unauthorized access to usernames is
via a password recovery process. We have frequently seen registered users’ information
being revealed. This happens through the unnecessary display of user identification in
a password error message. An attacker or malicious user can leverage this vulnerability
to gather information on registered users. This information will assist in devising more
precise attacks (e.g., password guessing focusing on valid accounts only to reduce the
number of attempts, at a level that may not be detected by automated monitoring). 

## Session IDs Nonrandom and Too Short

Risk level: MEDIUM

Since it is a security weakness to use unique session identifiers that are easy to guess,
they should be as random and as long as possible.
A Session ID or session identifier or session token is an identification device used
to identify a user to a web application. The web application creates session tokens and
sends them to a user’s browser. The web browser in turn sends the token back to the web
application along with any requests or information in order to identify the user.

## Weak Access Control

Risk level: LOW-HIGH

Restricting or controlling access to an application, or for that matter to all important
processes and files, is the most important aspect of security. A prime goal of hackers is
to gain unauthorized access to applications and then increase the priority level of their
access privileges.
In general, strict authentication should be enforced at both the application and
server levels in order to minimize the chance of unauthorized access to confidential
information. This process is prone to administrative errors particularly if it is not kept
simple and implemented in a way that is easy to test.

## Cached HTTPS Response

Risk level: MEDIUM

Cached HTTPS responses are caused by sensitive information from application
responses being stored in the local cache memory of a user’s workstation. This
information may be viewed and retrieved by other parties who have access to the same
computer simply by looking at the cache. This situation is exacerbated if a laptop is stolen
or if a user accesses the web application from a public terminal.

## Insufficient Session Expiration

Risk level: MEDIUM

I previously discussed the importance of secure sessions. It is also important that
sessions are changed frequently to make hacking them more difficult. Insufficient session
expiration may permit an attacker to reuse old session credentials or session IDs for
authorization. One auditor was able to replay a single request to the web application after
logging out. A session is the activity carried on between a web browser and a web server
from the time of logon to the time of logout. It runs over the HTTP or HTTPS protocols.

## Session Fixation

Risk level: HIGH

Yet another issue with the security of sessions occurs when sessions are not fully
terminated when the activity related to that session is ended. Many web application
audits have revealed that there exists a serious cookie problem where the web application
authenticates a user without first invalidating the existing session. The result is that the
application continues to use the session associated with the previous user. This creates a
risk of users gaining access to data that they do not have authorization to view.

## Weak Input Validation at the Application Level

Risk level: HIGH

Unauthorized access is the golden nugget for hackers, and strong protection against
unauthorized access is strong validation of the identities of users requesting access to an
application.

While it is common practice for web applications to verify access rights before
making functionality visible in the user interface (UI), it should also be common practice
to revalidate authentication at various important access points within an application.
If revalidation of the user ID and user requests are not verified, an attacker may
be able to forge requests within an existing session in order to access unauthorized or
privileged information.

## Lack of Validated Input Allowing Automatic Script Execution

Risk level: HIGH

All user input must be filtered to restrict any data not expected and wanted by
an application. This includes any strings or groups of characters, especially control
characters, which can be used to gain unauthorized privileges and control of the
environment.
We have found quite the opposite to exist in real-world situations, where user input,
such as messages, text, and data input into e-mail fields, was not validated or filtered
before being accepted. This insecure manner of operation fails to prevent a malicious
user from inserting malicious code into the input fields. An attacker could use this
vulnerability to perform different attacks. These could include redirecting the user to
a malicious web site where he may be tricked into inputting private information or a key
logger using malicious code to steal authentication and other privileged material.

## Unauthorized Access by Parameter Manipulation

Risk level: HIGH

This vulnerability involves having a potential security weakness to what is called
a parameter manipulation attack. The problem is inherent in input fields, where too
many choices of search parameters are given to users without sufficient controls over the
parameters they may choose. This may allow a user unintended privileges in accessing
parameters, such as session tokens, values stored in cookies, HTTP headers, and so on. A
malicious user could exploit this vulnerability to access and gather data about other valid
users. This could result in breaches to confidentiality and privacy.

A parameter manipulation attack compromises weak protection of data residing in
a user’s browser, where that data should otherwise be invisible and unable to be changed
by a user. The data can be session tokens, values stored in cookies, HTTP headers, or even
prices in web carts.

## Buffer Overflows

Risk level: HIGH

Buffer overflows are a high-risk vulnerability that are widely publicized and should
be avoided.

Web applications may be vulnerable to buffer overflows, which occur when a
program attempts to store more data in a static buffer than it is designed to manage. The
additional data overwrites and corrupts memory, allowing an attacker to insert arbitrary
instructions on the web server or crash the system. For additional clarity, a buffer
overflow is an error that may occur when a program writes more data than expected to a
buffer or space allocated for an expected amount of data. The excess data overruns the
buffer’s boundary and overwrites adjacent memory. If this violation is allowed to occur, it
can permit a hacker to inject instructions and compromise an environment.

Applications may be susceptible to the insertion of too much data, which may cause
a memory overflow. This may allow dangerous instructions to be input. For example, a
hacker may enter a command line executable statement such as

<! —exec%20cmd="/bin/cat%20/etc/passwd"—>

into a legitimate web site form under the guise of an HTTP request to gain access to the
web server. If security configuration allows, the hacker will receive the /etc/passwd file
and gain access to files and, ultimately, the usernames and passwords stored on the web
server.

## Forms Submitted Using the GET Method

Risk level: HIGH

This vulnerability is almost identical to the previously discussed vulnerability of
submitting data using the GET method. In this case, an entire form is submitted using the
GET method.

## Redirects and Forwards to Insecure Sites

Risk level: LOW-MEDIUM

A session being redirected to an insecure web site is even more serious than users
surfing to the same dangerous page on their own, simply because there is an implied trust
relationship between the user and the page doing the redirecting.

## Application Susceptible to Brute-Force Attacks

Risk level: LOW

This vulnerability arises when the application code does not stop a potentially
malicious user from gaining unauthorized access after a certain number of failed
authentication attempts, simply by denying access for a period of time or forever.
If the attacker’s false login attempts are not restricted after several attempts, the
attacker can proceed to discover a successful username and password combination and
use it to impersonate the account’s legitimate user, thereby gaining unauthorized access
to the application.

## Client-Side Enforcement of Server-Side Security

Risk level: MEDIUM

When validation is performed on the client side, security is always affected to some
extent because it allows for much less control than when it is enforced on the server side.

If a server relies on validation mechanisms placed on the client side, an attacker can 
modify the client-side behavior to bypass the protection mechanisms, resulting in 
potentially unexpected interactions between the client and server. The consequences will
vary depending on what the mechanisms are trying to protect.

## Injection Flaws

Risk level: HIGH

Injection vulnerability is caused by a lack of sufficient filtering or testing of data; that
is, input from a client. All data other than expected items such as size, type, and character
type should be rejected by the web application immediately.

This is a class of attacks that relies on injecting data into a web application in order
to facilitate the execution or interpretation of malicious data in an unexpected manner.
Examples of attacks within this class include cross-site scripting (XSS), SQL injection,
header injection, and many more. They result in running malicious code to steal and
compromise data.

Malicious instructions are included with user data and sent as part of a command
or query to an interpreter, which is a program used to convert high-level language
commands into machine-readable binary language, in a line-by-line fashion, in near
real time as part of a command or query. The attacker’s hostile instructions can trick
the interpreter into executing unintended commands or accessing data without proper
authorization.

In these attacks, the victims are web applications and the databases behind them,
but can also include the users of a vulnerable web site.
Five different injection vulnerabilities follow.

### SQL Injection

Risk level: HIGH

A SQL injection is one of several types of injection vulnerabilities, which allows
malicious SQL statements and queries to be submitted to a web application without the
web application stripping them out.

Many web applications do not properly strip user input of unnecessary special
characters, such as string literal escape characters, nor do they validate information
contained in a web request before making SQL queries. SQL injection is an attack
technique that takes advantage of a security vulnerability in a web application to extract
or alter data within the database management system, which resides at the back end of
the web application. The data may come from an input field on a client’s web browser as
part of a command or request. The data is then used for doing SQL queries or executing
commands in a back-end database that are never intended to occur in normal activity.
If the vulnerability to this attack allows the database to respond to the malicious

instructions, the database is compromised. A less direct attack injects malicious code
into strings that will be kept in a table for future reference. When the stored strings are
subsequently used in an SQL command, the malicious code is executed.
Such attacks can result in access to unauthorized data, bypassing of authentication,
or the shutting down of a database regardless of whether the database resides on the web
server or a separate server.

### Blind SQL Injection

Risk level: HIGH

A blind SQL injection is another flavor of an injection vulnerability, where a web
application does not filter or restrict requests for more information from the back-end
database. These types of requests should be very closely filtered by developers.
Blind SQL injection differs from a normal SQL injection in the way the data is
retrieved from the database. When the database does not output data to the web page and
instead displays an error message about the syntax of the query, an attacker is forced to
steal data by asking the database a series of true or false questions. This makes exploiting
the SQL injection vulnerability more difficult, but still possible.
The risks are the same as for other SQL injection attacks.

### Link Injection

Risk level: HIGH

This attack occurs when a malicious user is allowed to input code that contains
carriage return (CR) and line feed (LF) characters into an HTTP RESPONSE header.
After the characters are injected, the attacker makes space in the header to write
their own malicious code. The malicious data in the HTTP header is then passed to 
the web application via the client’s browser.

This vulnerability facilitates a cross-site request forgery attack, which is covered
later in this chapter.

### HTTP Header Injection Vulnerability

Risk level: HIGH

An HTTP header injection vulnerability occurs when HTTP headers are created on
the fly based upon user input. This vulnerability occurs if strict filtering is not put in place
to restrict malicious characters. The vulnerability can allow for the HTTP response-splitting
attack to occur. An HTTP response header includes detailed information about an HTTP
sent or received message, which a typical user never sees but is quite available to view on a
browser. Viewing the header information is accomplished either by using the appropriate
command or getting the appropriate viewing tool for any web browser.

### HTTP Response-Splitting Attack

Risk level: HIGH

The HTTP response-splitting attack compromises the HTTP header and is another
member of the injection vulnerability class. It occurs when insufficient filtering allows
the carriage return (CR) character and line feed (LF) character to be entered into the 
HTTP header if the underlying environment is vulnerable to these characters. If attackers
can inject CR or LF line characters into the header, then they can also inject new HTTP
headers and write arbitrary content into the application’s response.
An attacker can exploit this vulnerability to mount an attack using multiple
attack vectors. This type of attack can lead to a full systems compromise and loss of
confidentiality, integrity, and availability.

Any attack that can be delivered via cross-site scripting can usually also be delivered
via header injection because the attacker can construct a request that causes arbitrary
JavaScript to appear within the response body. Further, it is sometimes possible to
leverage header injection vulnerabilities to poison the cache of any proxy server through
which users access the application. Here, an attacker sends a crafted request that results
in a “split” response containing arbitrary content. JavaScript is a scripting language
developed by Netscape to enable web authors to design interactive sites. It shares many
of the features and structures of the full Java language but it also can interact with HTML
source code, enabling dynamic content to be created.

If the proxy server can be manipulated to associate the injected response with
another URL used within the application, then the attacker can perform a “stored” attack
against this URL that will compromise other users who request that URL in the future.

## Unauthorized View of Data

Risk level: LOW-HIGH

This is a common vulnerability, where sensitive information about the web
application environment is disclosed. This can assist a hacker in probing for more
sensitive data in preparation for an attack. The vulnerability arises when an unauthorized
user identifies an object such as a server or file name by a specific name. An indirect
reference is done by providing an alias name to the server or file, such as a number
value or a description of what the device does. This way, users only see alias names and
the application environment translates between alias names and real object names. If
authorization for each user is not verified prior to accessing an object, a malicious party
could gain confidential information about the environment, sufficient to plan an attack.

## Internal IP Address Revealed by Web Server

Risk level: MEDIUM

This is the old story of too much information being revealed to an unintended,
unauthorized individual. In this case, an IP address is the item of concern and could be
used by a hacker to build an attack.

For example, if a web server is misconfigured and identifies its internal IP address
in an HTTP header field, that IP address could allow unauthorized parties to learn
potentially dangerous information about the corporate network.

If an attacker knows the address space of the internal network, she may be able to
craft packets to get around network protection (firewall, intrusion detection
systems/intrusion prevention systems) and get access to the insecure internal network.

## Server Path Disclosed

Risk level: MEDIUM

Another instance of otherwise-confidential information being revealed to any
unauthorized individual, in this case a literal file path is disclosed and could be 
used by a hacker to build an attack.

For example, an HTTP response containing a file’s absolute path (e.g., c:\dir\file in
Windows or /dir/file in UNIX) may be clearly visible. An unauthorized party may be able
to exploit this information to access sensitive data on the directory structure of the server
machine, which it could then use for further attacks against the site.
Information such as the location of files on the server as well as directory structure
may be extremely beneficial for an attacker. It could allow the attacker to craft and
fine-tune an attack that will have a higher probability of success while reducing the effort
and elapsed time required to execute it.

## Unencrypted VIEWSTATE

Risk level: HIGH

Here is another instance of revealing too much information, in this case unencrypted
confidential data sent by a browser to its server. As a reminder, VIEWSTATE is a
temporary storage that allows ASP.NET users to store all the temporary information about
a web page, such as which panels are open and in use, the options that are currently
chosen, the current data in each text box, and even the data for other information.
During an audit, we were able to see confidential material from the browser session
being sent back to the application in an unencrypted view state. Therefore, any user can
see information for which he does not have sufficient authorization.

## Obsolete Web Server

Risk level: MEDIUM

Obsolete servers can be more vulnerable to attacks since they do not have the most
up-to-date security protection. An attacker could exploit this vulnerability to mount an
attack focused on known vulnerabilities in outdated versions of the web site platform. Such
an attack has a higher likelihood of success on this version than on a more secure version.
There are just too many real-life examples of this occurring, not only for web servers
but for all manner of servers. 

## Query Parameter in SSL Request

Risk level: MEDIUM

This is another variation of a vulnerability that can occur when developers use the
GET command instead of using other commands such as POST, which presents fewer
security risks. The GET method allows for requests to be stored in a browser’s history.
A vulnerability arises when the browser’s history is used to reveal the URLs
containing the query parameter names and values. If these names and values are not
confidential, then the confidential information is available to unauthorized parties.
During several web application vulnerability tests, we found HTTP GET requests in
browser histories that contained parameters containing confidential information.

## Error Handling

Risk level: HIGH

This is a variation on the theme of revealing what may appear to be innocuous
information to unauthorized parties. In reality, a competent hacker may be able to
leverage the information while preparing an attack.

A malicious party may intentionally submit abnormal data in order to force error
messages. An attacker could use generic error messages such as “Username incorrect”
and “Password incorrect” or hidden files and directories to plan an attack.

## Cross-Site Scripting Attacks

Risk level: HIGH

It can arise when web applications accept input data from users and dynamically include 
it in web pages without properly validating it first. XSS vulnerabilities allow an 
attacker to execute arbitrary commands and display arbitrary content in a user’s browser.
In the victim’s browser, the malicious code appears to be a legitimate part of a web 
site and causes it to act as an unintentional accomplice to the attacker.

Cross-site scripting is the most prevalent web application security flaw. XSS flaws
occur when an application includes user-supplied data in a page sent to the browser
without properly validating or rejecting it. There are three known types of XSS flaws:
•	 stored
•	 reflected
•	 DOM based
The consequences of an XSS attack are the same regardless of the type of flaw,
with the difference between them only in how the payload arrives at the server.
The damaging results of the XSS attack include: user sessions being hijacked to
steal or to change confidential information, defacement of web sites, insertion of hostile
content, redirection of users, disclosure of the end user’s session token, and the platform
on which the user’s browser is running being attacked.

### Reflected Cross-Site Scripting Attack

Risk level: HIGH

In a reflected XSS attack, malicious data enters a client’s browser by the browser
making a request to a compromised web site. The browser becomes infected with malicious
malware code. When the client then accesses its trusted web application, the malware on
the browser secretly requests personal information from the web site. The web site sends or
reflects the data to the compromised browser, which in turn sends the personal information
to the attacker. 

The most common mechanism for delivering malicious content is to include it as
a parameter in a URL that is posted publicly or e-mailed directly to the victim. URLs
constructed in this manner constitute the core of many phishing schemes, involving an
attacker convincing a victim to visit a URL that refers her to a vulnerable site. Once the
victim is on the site, the attacker will cause malicious code to execute within the user’s
browser.

The attacker-supplied code can perform a wide variety of actions, such as stealing
the victim’s session token or login credentials, performing arbitrary actions on the victim’s
behalf, and logging her keystrokes. The attacker can induce a user to issue his crafted
request by:
•	Requesting the transfer of private information, such as cookies
    that include session data, from the victim’s computer to that of the
    attacker, who then can hijack the session
•	Sending malicious requests to a web site, which could be
    especially dangerous if the victim has administrator privileges
•	Conducting phishing attacks that emulate trusted web sites and
    trick the victim into entering a password, allowing the attacker to
    compromise the victim’s account
•	Exploiting browser vulnerabilities that enable the attacker to take
    over the victim’s computer (drive-by hacking)

### Stored Cross-Site Scripting Attack

Risk level: HIGH

In this attack, the malicious code is stored permanently on the compromised web
application, such as in the back-end database. In a compromise situation, when a 
client’s browser retrieves information from the compromised web site, it also 
retrieves malware. In this case, there are two sets of victims: the compromised 
web site and the visitors to the compromised web site. The order of the attack 
sequence is:

1. The attacker inserts malicious code into a web application.
2. The victim, who is a client of the web site, requests a page
    from the web site.
3. The compromised web site unwittingly sends the malicious
    code to its client’s browser.
4. The compromised client’s browser sends confidential
    information back to the attacker’s server.

### Cross-Site Request Forgery Attack

Risk level: HIGH

Cross-site request forgery (CSRF) is yet another vulnerability caused by insufficient
filtering of data input into a web application. This complex attack dupes a browser into
being an unwitting participant in an attack against an otherwise-trusted web site. This
type of attack sounds like the XSS attack just defined. However, it differs from XSS in that
here the attacker uses the victim’s browser as a conduit through which to send malicious
instructions to a web application currently authenticating the victim. In this case, there
are two concurrent victims:

• the client whose browser is being remotely controlled by the
    attacker, who is an unwitting participant in the attack
• the trusted web site to which the client browser is authenticated,
    which is the ultimate victim of the attack

The CSRF attack forces a logged-on victim’s browser to send a forged HTTP request,
which includes the victim’s session cookie and any other automatically included
authentication information, to a vulnerable web application. The attacker forces
the victim’s browser to generate seemingly legitimate requests and send them to the
vulnerable application. In the security world, a cookie is used as a messenger to carry
session identification data related to a specific session. The session identification is called
a session cookie or session token or session identifier.

CSRF takes advantage of the fact that most web apps allow potential attackers to
predict all the details of a particular action. Since browsers send credentials like session
cookies automatically, attackers can create malicious web pages that generate forged
requests indistinguishable from the legitimate ones.

## Security Misconfigurations and Use of Known Vulnerable Components

Risk level: MEDIUM

It is imperative for operations teams dealing with web applications to ensure their
configurations of hardware and software are free of known vulnerabilities. However,
we have commonly seen misconfigurations that expose web applications to threats.
This issue is exacerbated because there is a huge volume of documented security
vulnerabilities, primarily published in good faith for the benefit of protecting applications
and networks but also serving as guidance for hackers. Off-the-shelf and widely available
software components such as libraries, frameworks, and other software modules can
have security weaknesses that are able to be exploited by parties with malicious intent.
The problem is exacerbated if these components run with full privileges. If a vulnerable
component is exploited, such an attack can facilitate serious data loss or server takeover.
This is a common problem, as few development teams focus on ensuring that their
components/libraries are up to date.

The full range of weaknesses is therefore possible, including injection, broken
access control, cross-site scripting, and so forth. The impact could range from minimal to
complete host takeover and data compromise.

## Denial-of-Service Attack

Risk level: HIGH

Many web applications are vulnerable to denial-of-service (DoS) attacks that can
dramatically curtail access or even result in a total shutdown of the affected network.
Attackers can use various mechanisms to launch a DOS attack, such as sending many
TCP requests and using an Internet control message protocol (ICMP) to flood a device
with ping requests. ICMP is a fundamental Internet protocol; in this case, it is used by
devices on a network to send error and control messages back and forth to each other.
ICMP flooding is malicious use of the ICMP protocol to deluge a target device with so
many messages as to overwhelm its ability to respond or to therefore properly function.

Excessive numbers of TCP and ICMP ping requests, which are simply various flavors
of Internet traffic, are very high generators of unnecessary traffic. When used as designed,
these protocols work well; misused, they are tools for DoS attacks. DoS attacks may be
simple, such as repeated requests for a single URL from a single source, or more complex,
such as a coordinated effort from multiple machines or botnets to barrage the URL.

## Related Security Issues

Risk level: HIGH

There are several security issues that can be sources of the previous vulnerabilities of
which users should be aware.

### Storage of Data at Rest

Risk level: HIGH

People are very concerned about data in motion, such as data and web sites, being
compromised during transactions. However, there is also an entire class of vulnerabilities
associated with data at rest, such as the security used to store data associated with web
applications.

Many web application logs contain sensitive information, such as passwords, session
IDs, web server requests, and statistics, and by default many applications provide logs
that detail the product’s installation data. These logs and other sensitive files may be
stored on the web server or back-end database and hackers can retrieve them to perform
unauthorized functions, view their content, or compromise the resource.

### Storage of Account Lists

Risk level: HIGH

Hackers can also use account information to plan an attack. Identifying usernames
by their accounts is a strong tool to leverage if this opportunity presents itself.
Here are several real-life examples of vulnerabilities associated with account
information we obtained during the course of one audit:
•	an account list stored in a file with minimum security controls
•	an account list containing many stale accounts, including
    previous employees and contractors no longer providing services
    for the company
•	the event log for an account file indicating several failed attempts
    by existing employees at logging into stale accounts

### Password Storage

Risk level: HIGH

Gaining valid credentials for an application is bread and butter for a hacker.
The ability to gain even hints about how passwords are built and stored is valuable for
a hacker who is building an attack.

Most applications have a password recovery system that is activated by clicking
on the password reminder link. This identifies the fact that passwords are stored or
encrypted as plain text. This unsecure form of storage may allow an attacker to gain
access to passwords, which, in combination with a valid username, could provide
unauthorized access to confidential corporate information including a client’s personal
and sensitive data.

Since this type of application is also susceptible to SQL injection, the password
list is definitely at risk. A successful SQL injection attack would make the plain text or
encrypted passwords vulnerable to exposure.

### Insufficient Patch Management

Risk level: HIGH

One of the most common and high-risk activities an operations team can commit
is to not install security-related patches in a timely manner. Since descriptions of
vulnerabilities and their associated patches or corrections are widely published to assist
with security, the same information is just as available to potential hackers.
During the network-vulnerability portion of our audit, we identified out-of-date
revision levels in several third-party software platforms associated with the web
application environment.

This may be indicative of an insufficient patch-management process. Since
insufficient/insecure patches result in a very large percentage of web application
vulnerabilities, this section needs to be included as part of a web application vulnerability list.