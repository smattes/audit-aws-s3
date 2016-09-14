audit S3
============================
This stack will monitor S3 and alert on things CloudCoreo developers think are violations of best practices


## Description

This repo is designed to work with CloudCoreo. It will monitor S3 against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_S3_ALERT_RECIPIENT value

## Variables Requiring Your Input

### `AUDIT_AWS_S3_ALERT_RECIPIENT`:
  * description: email recipient for notification

## Variables Required but Defaulted

### `AUDIT_AWS_S3_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: s3-allusers-write,s3-allusers-write-acp,s3-allusers-read,s3-authenticatedusers-write,s3-authenticatedusers-write-acp,s3-authenticatedusers-read,s3-logging-disabled,s3-world-open-policy-delete,s3-world-open-policy-get,s3-world-open-policy-list,s3-world-open-policy-put,s3-world-open-policy-all,s3-only-ip-based-policy

### `AUDIT_AWS_S3_ALERT_RECIPIENT`:
  * description: email recipient for notification

### `AUDIT_AWS_S3_ALLOW_EMPTY`:
  * description: receive empty reports?

### `AUDIT_AWS_S3_PAYLOAD_TYPE`:
  * description: json or text
  * default: json

### `AUDIT_AWS_S3_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_S3_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1

## Variables Not Required

**None**

## Tags

1. Audit
1. Best Practices
1. Alert
1. S3

## Diagram



## Icon



