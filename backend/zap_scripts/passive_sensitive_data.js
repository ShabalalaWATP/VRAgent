// ZAP Passive Scanner - Sensitive Data Detection
// Type: passive
// Engine: ECMAScript (Graal.js)
// Description: Detects sensitive data exposure in HTTP responses

function scan(ps, msg, src) {
    var responseBody = msg.getResponseBody().toString();
    var url = msg.getRequestHeader().getURI().toString();
    
    // Patterns for sensitive data
    var patterns = [
        {
            name: "Credit Card Number",
            regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b/g,
            risk: 3,
            description: "Potential credit card number exposed in response"
        },
        {
            name: "Social Security Number",
            regex: /\b\d{3}-\d{2}-\d{4}\b/g,
            risk: 3,
            description: "Potential SSN exposed in response"
        },
        {
            name: "Email Address",
            regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            risk: 1,
            description: "Email address found in response"
        },
        {
            name: "API Key Pattern",
            regex: /(?:api[_-]?key|apikey|api_secret)['":\s]*['"]*([a-zA-Z0-9_-]{20,})['""]*/gi,
            risk: 3,
            description: "Potential API key exposed in response"
        },
        {
            name: "AWS Access Key",
            regex: /AKIA[0-9A-Z]{16}/g,
            risk: 3,
            description: "AWS Access Key ID found in response"
        },
        {
            name: "Private Key",
            regex: /-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----/g,
            risk: 3,
            description: "Private key exposed in response"
        },
        {
            name: "Password in URL/Response",
            regex: /(?:password|passwd|pwd)['"=:\s]+['"]?([^'"&\s]{4,})/gi,
            risk: 2,
            description: "Password potentially exposed"
        },
        {
            name: "JWT Token",
            regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
            risk: 2,
            description: "JWT token found in response"
        }
    ];
    
    for (var i = 0; i < patterns.length; i++) {
        var pattern = patterns[i];
        var matches = responseBody.match(pattern.regex);
        
        if (matches && matches.length > 0) {
            ps.newAlert()
                .setRisk(pattern.risk)
                .setConfidence(2)
                .setName("Sensitive Data Exposure: " + pattern.name)
                .setDescription(pattern.description)
                .setEvidence(matches[0].substring(0, 100))
                .setMessage(msg)
                .raise();
        }
    }
}
