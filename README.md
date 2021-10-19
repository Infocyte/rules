# Infocyte Rules Engine
The [Infocyte](https://www.infocyte.com) platform is a cloud-based threat detection and incident
response platform for endpoints (workstations and servers) and cloud applications like Microsoft 365.
In addition to the analysis performed natively by the Infocyte platform and it's multiple malware scanners, users are able to customize
detection criteria to fit their own needs using our dynamic rules engine. 

The service performs anaysis on the stream of incoming data as it comes into our cloud platform. 
Rule processing is in the cloud, so there is no impact to endpoints or individual instances.
Atomic rules are applied to individual events that are fed into the engine in the form of json documents while Coorelation Rules _(coming soon)_ are applied to a series of events or alerts. 
The output of the engine is to produce boolean matching of rules that can fire off an alert or describe a behavior that was observed.

The **Infocyte Query Language (IQL)** is our custom language to build rules in. 
This language is powerful yet familiar and quite simple to learn for non-programmers.

**This repository contains:**
- [Language Information](#language-information)
- [Usage Instructions](#usage)
- [API Reference](#api-reference)

## Language Information
**Infocyte Query Language (IQL)** is a custom language whose syntax is loosely based on javascript 
and related programming languages. The goal of the language is to be familiar, easy to learn and obvious. 
As with any language, there are some things to know right out of the gate:

#### Not Javascript/Some other language
While the syntax might be familiar, the features of other languages are not present.
IQL's express purpose is to provide an extremely fast and efficient way of describing equality statements by non-programmers.

#### No Need To Escape... Normally
IQL is flexible, and is designed to make interacting with it simple.
This means copy and pasting things like Windows paths is ergonomic.
There is no escape character to worry about, strings are just strings.
If you have to escape something, we recommend using the [regex()](#regex) function.

## Usage
After logging into your Infocyte instance (with an administrator role) simply navigate to
`Admin->Rules`.
Here you can create new rules or edit/remove existing ones.
Rules can also be set to active/inactive. Inactive prevents them from running during analysis.

Rules Contain two parts: a conditional statement and an action.

**Conditional statements** are formed using IQL which very closely
resembles something like javascript. They can use boolean (&&, ||) statements, grouping of
conditions, exclusions, and include some useful functions to help make them very easy to work with our data types.
More information on IQL is found [below](#api-reference).

**Actions** are what happens when a rule matches an item.
- Alert - adds an entry for the matched item to the Alert Inbox within the Infocyte application
- Flag *(coming soon)* - attaches a specific flag to the item in the Infocyte application
- Respond *(coming soon)* - initiate a response action on the endpoint using an [Infocyte Extension](https://github.com/infocyte/extensions)


## API Reference
Rules are processed against the data collected by the endpoint but is flexible enough to work on any 
arbitrary json-formatted documents that are fed into it. 
All data types contain a `type` field and any collection involving files that reside on disk will 
have properties like `path`, `md5`, `sha1`, `sha256`, etc.

### Basics

Simple rules can be written using basic equality/inequality checks:

```javascript
path == "c:\users\john\malware.exe"
```

Complex combinations can also be used:

```javascript
path == "c:\users\john\malware.exe" ||
    (path == "c:\users\*\ignore-me.exe" && parentPath != "c:\windows\system32\explorer.exe")
```

### Functions
There are some functions to help manipulate and work with the data at hand more simply:

- [lowercase()](#lowercase)
- [uppercase()](#uppercase)
- [regex()](#regex)
- [iregex()](#iregex)
- [date()](#date)
- [today()](#today)
- [trailingDays()](#trailingDays)
- [cidr()](#cidr)
- [privateIp()](#privateIp)

#### lowercase()
Transform a string or a field to its lowercase form. Given an input item:

```json
{
    "path": "c:\\windows\\system32\\notepad.exe",
    "commandLine": "c:\\windows\\system32\\notepad.exe c:\\users\\joe\\Documents\\Passwords.TXT",
}
```

All of these work:

```javascript
path == lowercase("C:\windows\System32\NotePad.EXE")
```

```javascript
lowercase(commandLine) == "c:\windows\system32\notepad.exe c:\users\joe\documents\passwords.txt",
```

```javascript
lowercase("StRIng") == lowercase("stRing")
```

#### uppercase()
Transform a string or field to its uppercase form, see [lowercase](#lowercase).

#### regex()
Provides a PCRE compliant regex matching framework. Given an input item:

```json
{
    "path": "c:\\windows\\system32\\notepad.exe",
    "commandLine": "c:\\windows\\system32\\notepad.exe c:\\users\\joe\\Documents\\Passwords.TXT",
}
```

This will work:

```javascript
path == regex(".*notepad\.exe")
```

#### iregex()
Convenience wrapper for case insensitive PCRE compliant regex matching framework. Given an input item:

```json
{
    "path": "c:\\windows\\system32\\notepad.exe",
    "commandLine": "c:\\windows\\system32\\notepad.exe c:\\users\\joe\\Documents\\Passwords.TXT",
}
```

This will work:

```javascript
commandLine == iregex("\.txt")
```

Which is equivalent to:

```javascript
commandLine == regex("(?i)\.txt")
```

#### date()
Provides date parsing and comparison operations. It will parse several formats:
- `yyyy-mm-dd`
- `yyyy-mm-dd HH:MM`
- `yyyy-mm-dd HH:MM:SS`
- `yyyy-mm-ddTHH:MM:SSZ` (ISO format)

```javascript
date('2020-01-01') < date('2021-01-01')
```

This operation works on fields as well:

```javascript
date(createdOn) > date('2021-01-01')
```

#### today()
The current date time stamp for use in [date](#date) comparisons

```javascript
date(createdOn) > today()
```

#### trailingDays()
A datetime stamp for a number of days prior to today.

The following matches any created date within the last 30 days:

```javascript
date(createdOn) > trailingDays(30)
```

#### cidr()
Generates a network CIDR for matching IP data:

```javascript
type == "connection" && remote_addr != cidr("192.168.1.0/24")
```

#### privateIp()
Compares network IPs against private or loopback ranges:

The following matches on all `destIp` instances that are not loopback or private:

```javascript
type == "connection" && remote_addr != privateIp()
```

