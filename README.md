# Litchfield's Security Baseline for Oracle

This project defines a security baseline for the Oracle RDBMS and provides a tool for verifying compliance against the baseline. This baseline extends the [CIS Guidelines](https://www.cisecurity.org/).

The baseline covers such areas as parameter settings, patching, attack surface, system, role, and object privilege assignment (with an emphasis on PUBLIC defaults), audit options, critical misconfigurations and backdoors as well as user security and weak passwords.

The tool measures whether a particular setting is compliant with the baseline, details the level of risk if not compliant and generates a score based upon the exposure.

The score for each item can be totaled to define an overall score that provides a strong indication about the database system's health, or scores can be tallied across the different security domains being measured.


# What's here?

AddendumtotheOracle12cCISGuidelines.pdf: This is an Addendum to the CIS Guidelines for Oracle 12c that contains 32 additional security checks.

oracle_audit_plan.pdf: A document and list of actions to be audited and the rationale under this security baseline. This also contains an SQL script for enabling the audit items.

hardening_summary_for_oracle.pdf: A list of changes that need to be made. 

dssc.rb: A security baseline verification tool written it Ruby. This reads in a list of SELECT queries that are executed to determine if a database system is compliant.

queries.xml: The list of queries.

orcl.xml: A sample database connection configuration file.


# Running the Baseline Verification Tool

First off, have you installed the Oracle instant client and ruby-oci8?
If not, please do so :)

*** Install ruby-oci8 first ****

```
mkdir -p /opt/oracle
cd /opt/oracle 
mv ~/Downloads/i*.zip /opt/oracle/
unzip instantclient-sdk-macos.x64-12.1.0.2.0.zip
unzip instantclient-basic-macos.x64-12.1.0.2.0.zip
unzip instantclient-sqlplus-macos.x64-12.1.0.2.0.zip
OCI_DIR=/opt/oracle/instantclient_12_1; export OCI_DIR
DYLD_LIBRARY_PATH=/opt/oracle/instantclient_12_1; export DYLD_LIBRARY_PATH
ORACLE_HOME=/opt/oracle/instantclient_12_1; export ORACLE_HOME
RC_ARCHS=x86_64; export RC_ARCHS
gem install ruby-oci8
```

*** Running ***

```$ ruby dssc.rb queries.xml orcl.xml```

queries.xml contains the SQL select queries that are used to determine compliance with the baseline.
orcl.xml is the configuration file that contains the database connection information. A sample configuration file called orcl.xml exists in the repository.


-- Send results to stdout 
```
$ ruby dssc.rb queries.xml orcl.xml
```

-- Redirect results to file 
```
$ ruby dssc.rb queries.xml orcl.xml > results.xml
```


# Privileges for the scanning user

The user account used for scanning purposes requires the following privileges:
```
CREATE SESSION
SELECT ANY DICTIONARY
SELECT ON SYS.USER$
```






