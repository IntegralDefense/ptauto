PassiveTotal Automation
-----------------------
ptauto is a collection of scripts for querying PassiveTotal and providing some level of automation. If you have a CRITs installation, it can automatically add queried indicators and relate them to the original indicator queried. Currently, only pt_query.py is included, which is a tool for querying PT and retrieving WHOIS results.

This is meant to run on a Linux server (we use Ubuntu)

Configuration
-------------
1. Copy logging.ini and pt.ini from etc/ into etc/local/. Edit both files in etc/local/ to use your settings.
2. If using CRITs, create a ~/.crits_api file with your CRITs API settings.
3. Also if using CRITs, copy your crits/crits/vocabulary/indicators.py file to lib/crits/vocabulary.

## Dependencies
See requirements.txt

## CRITs requirements
The CRITs project can be found here: https://github.com/crits/crits/

This is intended to work with the latest version of 4_stable.

The CRITs API must be available. The CRITs mongo database must be available.

*Important*: CRITs doesn't contain a specific indicator type for tracking WHOIS email addresses out of the box. One option is to add these email addresses as EMAIL_ADDRESS types, then find some other way to mark them as a WHOIS registrant (Add an Action; add a bucket list item). Internally, we've added a new type "WHOIS_EMAIL" to our CRITs indicators.py vocabulary file. Either way, this script needs to know which type to use when creating a WHOIS registrant email indicator. Edit your etc/local/pt.ini file in the [crits] section.

Assuming you want to use the EMAIL_ADDRESS type:
```
whois_email_type = EMAIL_ADDRESS
```

In the future, there might be additional functionality for adding an Action or bucket_list item (or even do something more complicated by including your own custom python script), but this is not present currently.

### CRITs Vocabulary
The default stable_4 vocabulary file is included. If you have modified your CRITs installation, you must copy your crits/vocabulary/indicators.py file to lib/crits/vocabulary/ (as mentioned in the configuraiton section). This file is added in the .gitignore, so you'll need to update it if something relevant changes in the main CRITs branch.

When adding your own indicators.py vocabulary file, you'll need to remove the import reference at the top.

```
from crits.vocabulary.vocab import vocab
```

and also remove the class inheritance of vocab:

```
class IndicatorTypes(vocab):
```

becomes:

```
class IndicatorTypes():
```

## Logging
By default, we have set logging to print debug messages. Edit etc/local/logging.ini to change this. To change just the console output, modify the level=DEBUG under handler_console.

Usage
-----
## pt_query.py
pt_query.py is simple to use.
```
usage: pt_query.py [-h] [--dev] [--crits] [--test] [-f] QUERY

positional arguments:
  QUERY       A value to send as a query to PT. Email, phone, name, etc.

optional arguments:
  -h, --help  show this help message and exit
  --dev       Use a development instance of CRITs (if using)
  --crits     Write the results to CRITs with appropriate relationships.
  --test      Run with test data. (Save PT queries)
  -f          Force a new API query (do not used cached results)
```

As an example, let's take an email address: (All the resulting data is faked so we don't break any licensing agreements with PT)
```
$ bin/pt_query.py --dev --test loltest@gmail.com
Domain                   Registrant Email    Registrant Name    Registrant Date    Expiration Date    Tags
-----------------------  ------------------  -----------------  -----------------  -----------------  ------
penguinpalaceimages.com  loltest@gmail.com   test name          2014-12-06         2016-12-06
coldycold.com            loltest@gmail.com   test name          2014-09-14         2015-09-14
itsfreezinghere.net      loltest@gmail.com   icecube ltd        2014-07-11         2015-07-11
```

Searching the email address returns several other domains registered by the same email address. 

### --crits flag
The --crits flag automatically uploads resulting data to CRITs and relates it properly. In the case above, loltest[@]gmail.com would be uploaded as a WHOIS indicator, and the resulting domains would be uploaded as domain indicators. Relationships would then be created between the domains and the WHOIS indicator. If the WHOIS indicator is already found in CRITs, some additional information will be added to the new domains, such as campaigns and confidence/impact.

### --dev flag
If you have two separate instances of CRITs, a dev and a prod, this will use the dev version (that you specify in the pt.ini file).

### --test flag
Some test data is provided for both email and telephone searches. This will allow you to test using the tool without using your PT API query allowance.

### Caching (-f option)
Results are cached by default from PT, and you must supply the -f option to obtain new results.
