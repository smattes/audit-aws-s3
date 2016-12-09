audit S3
============================
This stack will monitor S3 and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor S3 against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;S3&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_S3_ALERT_RECIPIENT_2`:
  * description: Enter the email address(es) that will receive notifications for objects with no owner tag (Optional, only if owner tag is enabled).


## Required variables with default

### `AUDIT_AWS_S3_ALERT_LIST`:
  * description: Which alerts would you like to check for? (Default is all S3 alerts)
  * default: s3-allusers-write, s3-allusers-write-acp, s3-allusers-read, s3-authenticatedusers-write, s3-authenticatedusers-write-acp, s3-authenticatedusers-read, s3-logging-disabled, s3-world-open-policy-delete, s3-world-open-policy-get, s3-world-open-policy-list, s3-world-open-policy-put, s3-world-open-policy-all, s3-only-ip-based-policy

### `AUDIT_AWS_S3_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: true

### `AUDIT_AWS_S3_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_S3_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-west-1,us-west-2.
  * default: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1

### `AUDIT_AWS_S3_FULL_JSON_REPORT`:
  * description: Would you like to send the full JSON report? Options - notify / nothing. Default is notify.
  * default: nothing

### `AUDIT_AWS_S3_ROLLUP_REPORT`:
  * description: Would you like to send a Summary ELB report? Options - notify / nothing. Default is no / nothing.
  * default: nothing

### `AUDIT_AWS_S3_OWNERS_HTML_REPORT`:
  * description: notify or nothing
  * default: notify


## Optional variables with default

### `AUDIT_AWS_S3_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of owner of the ELB object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_S3_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. S3

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/icon.png "icon")

