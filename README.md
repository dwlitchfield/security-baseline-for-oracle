# Litchfield's Security Baseline for Oracle

This project defines a security baseline for Oracle database servers and provides a tool to measure compliance against the baseline.

# What's here?

the_baseline.pdf
A document describing the security baseline and the verification tool used to check for compliance.

AddendumtotheOracle12cCISGuidelines.pdf
This is an Addendum to the CIS Guidelines for Oracle 12c that contains 32 additional security checks.

oracle_audit_plan.pdf
A document and list of actions to be audited and the rationale under this security baseline. This also contains an SQL script for enabling the audit items.

hardening_summary_for_oracle.pdf
A list of changes that need to be made. 

dssc.rb
A security baseline verification tool written it Ruby. This reads in a list of SELECT queries that are executed to determine if a database system is compliant.

queries.xml
The list of queries.

orcl.xml
A sample database connection configuration file.


# Running the Baseline Verification Tool

$ ruby dssc.rb queries.xml orcl.xml

queries.xml contains the SQL select queries that are used to determine compliance with the baseline.
orcl.xml is the configuration file that contains the database connection information. A sample configuration file called orcl.xml exists in the repository.
