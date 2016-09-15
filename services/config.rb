
coreo_aws_advisor_alert "s3-allusers-write" do
  action :define
  service :s3
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "Critical"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "write"]
end

coreo_aws_advisor_alert "s3-allusers-write-acp" do
  action :define
  service :s3
  description "Bucket has permissions (ACP / ACL) which let all users modify the permissions."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to edit permissions."
  level "Emergency"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "write_acp"]
end

coreo_aws_advisor_alert "s3-allusers-read" do
  action :define
  service :s3
  description "Bucket has permissions (ACL) which let anyone list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to list the bucket."
  level "Alert"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "read"]
end

coreo_aws_advisor_alert "s3-authenticatedusers-write" do
  action :define
  service :s3
  description "Bucket has permissions (ACL) which let any AWS users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to write."
  level "Critical"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "write"]
end

coreo_aws_advisor_alert "s3-authenticatedusers-write-acp" do
  action :define
  service :s3
  description "Bucket has permissions ( ACP / ACL) which let any AWS user modify the permissions."
  category "dataloss"
  suggested_action "Remove the bucket permissions (ACP / ACL) that allows 'Any Authenticated AWS User' to edit permissions."
  level "danger"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "write_acp"]
end

coreo_aws_advisor_alert "s3-authenticatedusers-read" do
  action :define
  service :s3
  description "Bucket has permissions (ACL) which let any AWS user list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to list the bucket."
  level "Alert"
  objectives    ["bucket_acl", "bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.grantee.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "read"]
end

coreo_aws_advisor_alert "s3-logging-disabled" do
  action :define
  service :s3
  description "S3 bucket logging has not been enabled for the affected resource."
  category "Audit"
  suggested_action "Enable logging on your S3 buckets."
  level "Warning"
  objectives    ["bucket_logging"]
  audit_objects [""]
  operators     ["=="]
  alert_when    [nil]
end

coreo_aws_advisor_alert "s3-world-open-policy-delete" do
  action :define
  service :s3
  description "Bucket policy allows the world to delete the affected bucket"
  category "Dataloss"
  suggested_action "Remove or modify the bucket policy that enables the world to delete the contents of this bucket."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect,Principal,Action]"]
  operators     ["=~"]
  alert_when    [/"Allow",[^\]]+("AWS":"*"|"*")[^\]]+(s3:DeleteBucket)/]
end

coreo_aws_advisor_alert "s3-world-open-policy-get" do
  action :define
  service :s3
  description "Bucket policy allows the world to get the contents of the affected bucket."
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to get the contents of this bucket."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect,Principal,Action]"]
  operators     ["=~"]
  alert_when    [/"Allow",[^\]]+("AWS":"*"|"*")[^\]]+(s3:Get)/]
end

coreo_aws_advisor_alert "s3-world-open-policy-list" do
  action :define
  service :s3
  description "Bucket policy allows the world to list the contents of the affected bucket"
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to list the contents of this bucket."
  level "danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas ["jmespath.Statement[*].[Effect,Principal,Action]"]
  operators     ["=~"]
  alert_when    [/"Allow",[^\]]+("AWS":"*"|"*")[^\]]+(s3:List)/]
end

coreo_aws_advisor_alert "s3-world-open-policy-put" do
  action :define
  service :s3
  description "Bucket policy allows the world to put data into the affected bucket."
  category "Dataloss"
  suggested_action "Remove the bucket permission that enables the world to put (and overwrite) data in this bucket."
  level "danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect,Principal,Action]"]
  operators     ["=~"]
  alert_when    [/"Allow",[^\]]+("AWS":"*"|"*")[^\]]+(s3:Put)/]
end

coreo_aws_advisor_alert "s3-world-open-policy-all" do
  action :define
  service :s3
  description "Bucket policy allows the world to get, put, list, delete the affected bucket"
  category "Dataloss"
  suggested_action "Remove the bucket permission that enables the world to get, put, list, and delete the contents of this bucket."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect,Principal,Action]"]
  operators     ["=~"]
  alert_when    [/"Allow",[^\]]+("AWS":"*"|"*")[^\]]+(s3:\*)/]
end

coreo_aws_advisor_alert "s3-only-ip-based-policy" do
  action :define
  service :s3
  description "Bucket policy grants permissions to any user at an IP address or range to perform operations on objects in the specified bucket."
  category "Security"
  suggested_action "Consider using other methods to grant permission to perform operations on your S3 buckets."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect, Condition]"]
  operators     ["=~"]
  alert_when    [/"(Allow|Deny)",[^{]*({"IpAddress")[^}]*}}\]/]
end

# see PLA-889
#
coreo_aws_advisor_s3 "advise-s3" do
  action :advise
  alerts ${AUDIT_AWS_S3_ALERT_LIST}
#  regions ${AUDIT_AWS_S3_REGIONS}  
  global_objective "buckets"
  bucket_name /.*/
  global_modifier({:bucket_name => "buckets.name"})
end

coreo_uni_util_notify "advise-s3" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_S3_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_s3.advise-s3.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_s3.advise-s3.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_s3.advise-s3.number_ignored_violations",
  "violations": STACK::coreo_aws_advisor_s3.advise-s3.report }'
  payload_type "${AUDIT_AWS_S3_PAYLOAD_TYPE}"
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end

