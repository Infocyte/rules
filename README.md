# Infocyte Rules
The [Infocyte](https://www.infocyte.com) platform is an agentless Threat Hunting and Incident
Response platform.
In addition to the analysis performed by the Infocyte platform, users are able to customize
detection criteria to fit their own needs.
Our rules language is powerful yet familiar and quite simple to learn.
Rule processing is cloud delivered, so there is no impact to endpoints or individual instances.

**This repository contains:**
- [Usage Instructions](#usage)
- [Language Information](#language-information)
- [API Reference](#api-reference)


## Usage
After logging into your Infocyte instance (with an administrator role) simply navigate to
`Admin->Rules`.
Here you can create new rules or edit/remove existing ones.
Rules can also be set to active/inactive. Inactive prevents them from running during analysis.

Rules Contain two parts: a conditional statement and an action.

**Conditional statements** are formed using the Infocyte Query Language (IQL) which very closely
resembles something like javascript. They can use boolean (&&, ||) statements, grouping of
conditions, exclusions, and include some useful functions to help make them very easy to work with.
More information on IQL is found [below](#api-reference).

**Actions** are what happens when a rule matches an item.
- Alert - adds an entry for the matched item to the Alert Inbox within the Infocyte application
- Flag *(coming soon)* - attaches a specific flag to the item in the Infocyte application
- Respond *(coming soon)* - initiate a response action on the endpoint using an [Infocyte Extension](https://github.com/infocyte/extensions)

## Language Information
IQL is a completely custom language, whose syntax is loosely based on the likes javascript or c/c++.
The goal of the language is to be familiar, easy to learn, and obvious. As with any language, there
are some things to know right out of the gate:

#### Not Javascript/Some other language
While the syntax might be familiar, the features of other languages are not present.
IQL's express purpose is to provide an extremely fast and efficient way of describing equality statements.

#### No Need To Escape... Normally
IQL is flexible, and is designed to make interacting with it simple.
This means copy and pasting things like Windows paths is ergonomic.
There is no escape character to worry about, strings are just strings.
If you have to escape something, we recommend using the [regex()](#regex) function.


## API Reference
Rules are processed against the data collected by the endpoint. The specific fields for all data
types are found [here](todo). All data types contain a `type` field and any collection involving
files that reside on disk will have properties like `path`, `md5`, `sha1`, `sha256`, etc.

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

