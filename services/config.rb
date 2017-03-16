
coreo_aws_rule "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "Critical"
  objectives    ["bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AllUsers/i, /\bwrite\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-allusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write-acp.html"
  display_name "All users can write the bucket ACP / ACL"
  description "Bucket has permissions (ACP / ACL) which let all users modify the permissions."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to edit permissions."
  level "Emergency"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AllUsers/i, /\bwrite_acp\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-allusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-read.html"
  display_name "All users can list the affected bucket"
  description "Bucket has permissions (ACL) which let anyone list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to list the bucket."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AllUsers/i, /\bread\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-authenticatedusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write.html"
  display_name "All authenticated AWS users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to write."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AuthenticatedUsers/i, /\bwrite\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-authenticatedusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write-acp.html"
  display_name "All authenticated AWS users can change bucket permissions"
  description "Bucket has permissions ( ACP / ACL) which let any AWS user modify the permissions."
  category "Dataloss"
  suggested_action "Remove the bucket permissions (ACP / ACL) that allows 'Any Authenticated AWS User' to edit permissions."
  level "Emergency"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AuthenticatedUsers/i, /\bwrite_acp\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-authenticatedusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-read.html"
  display_name "All authenticated AWS users can read the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS user list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to list the bucket."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AuthenticatedUsers/i, /\bread\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-logging-disabled" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-logging-disabled.html"
  display_name "S3 bucket logging not enabled"
  description "S3 bucket logging has not been enabled for the affected resource."
  category "Audit"
  suggested_action "Enable logging on your S3 buckets."
  level "Warning"
  objectives    ["bucket_logging"]
  audit_objects [""]
  operators     ["=="]
  raise_when    [nil]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-delete" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-delete.html"
  display_name "Bucket policy gives world delete permission"
  description "Bucket policy allows the world to delete the affected bucket and/or its contents"
  category "Dataloss"
  suggested_action "Remove or modify the bucket policy that enables the world to delete the contents of this bucket or even the bucket itself."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  raise_when    [/s3:Delete*/]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-get" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-get.html"
  display_name "Bucket policy gives world Get permission"
  description "Bucket policy allows the world to get the contents of the affected bucket."
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to get the contents of this bucket."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  raise_when    [/s3:Get*/]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-list" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-list.html"
  display_name "Bucket policy gives world List permission"
  description "Bucket policy allows the world to list the contents of the affected bucket"
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to list the contents of this bucket."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  raise_when    [/s3:List*/]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-put" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-put.html"
  display_name "Bucket policy gives world Put permission"
  description "Bucket policy allows the world to put data into the affected bucket."
  category "Dataloss"
  suggested_action "Remove the bucket permission that enables the world to put (and overwrite) data in this bucket."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  raise_when    [/s3:Put*/]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-all" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-all.html"
  display_name "Bucket policy gives the world permission to do anything in the bucket"
  description "Bucket policy gives the world permission to do anything in the bucket"
  category "Dataloss"
  suggested_action "Modify the principle to remove the * notation which signifies any person or remove the * from allowed actions which signifies allowing any possible action on the bucket or its contents."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Action == 's3:*' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  raise_when    [/[^\[\]\{\}]/]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-only-ip-based-policy" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-only-ip-based-policy.html"
  display_name "Bucket policy uses IP addresses to grant permission"
  description "Bucket policy grants permissions to any user at an IP address or range to perform operations on objects in the specified bucket."
  category "Security"
  suggested_action "Consider using other methods to grant permission to perform operations on your S3 buckets."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect, Condition]"]
  operators     ["=~"]
  raise_when    [/"(Allow|Deny)",[^{]*({"IpAddress")[^}]*}}\]/]
  id_map "modifiers.bucket"
end



coreo_uni_util_variables "s3-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.number_violations' => 'unset'}
            ])
end

coreo_aws_rule_runner "advise-s3" do
  service :s3
  action :run
  rules ${AUDIT_AWS_S3_ALERT_LIST}
#  regions ${AUDIT_AWS_S3_REGIONS}  
  global_objective "buckets"
  global_modifier({:bucket => "buckets.name"})
end

coreo_uni_util_variables "s3-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.report' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.number_violations'},

            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-s3" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "${JSRUNNER_COMMONS_VERSION}"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-s3.report}'
  function <<-EOH
 

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: ", e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "${AUDIT_AWS_S3_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}

setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_S3_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_S3_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_S3_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_S3_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
   ALLOW_EMPTY, SEND_ON, 
  SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditS3 = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);
const notifiers = AuditS3.getLetters();

const JSONReportAfterGeneratingSuppression = AuditS3.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(JSONReportAfterGeneratingSuppression));
coreoExport('report', JSON.stringify(JSONReportAfterGeneratingSuppression['violations']));

callback(notifiers);
  EOH
end



coreo_uni_util_variables "s3-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-s3.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.report'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.table'}
            ])
end



coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-s3-to-tag-values" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
end


coreo_uni_util_notify "advise-s3-rollup" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_S3_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_S3_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
cloud account name: PLAN::cloud_account_name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-s3.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 rule results on PLAN::stack_name :: PLAN::name'
  })
end
