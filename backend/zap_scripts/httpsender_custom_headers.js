// ZAP HTTP Sender Script - Custom Header Injection
// Type: httpsender
// Engine: ECMAScript (Graal.js)
// Description: Adds custom headers to all outgoing requests

var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');

function sendingRequest(msg, initiator, helper) {
    // Add custom security testing headers
    var header = msg.getRequestHeader();
    
    // Add X-Forwarded-For for testing IP-based restrictions
    if (!header.getHeader("X-Forwarded-For")) {
        header.setHeader("X-Forwarded-For", "127.0.0.1");
    }
    
    // Add custom user agent for identification
    header.setHeader("X-Security-Scanner", "VRAgent-ZAP");
    
    // Add cache bypass headers
    header.setHeader("Cache-Control", "no-cache, no-store");
    header.setHeader("Pragma", "no-cache");
}

function responseReceived(msg, initiator, helper) {
    // Log interesting responses
    var status = msg.getResponseHeader().getStatusCode();
    
    if (status >= 500) {
        print("[HTTP Sender] Server error detected: " + status + " - " + msg.getRequestHeader().getURI());
    }
    
    // Check for security headers
    var responseHeader = msg.getResponseHeader();
    var missingHeaders = [];
    
    if (!responseHeader.getHeader("X-Content-Type-Options")) {
        missingHeaders.push("X-Content-Type-Options");
    }
    if (!responseHeader.getHeader("X-Frame-Options")) {
        missingHeaders.push("X-Frame-Options");
    }
    if (!responseHeader.getHeader("Content-Security-Policy")) {
        missingHeaders.push("Content-Security-Policy");
    }
    
    if (missingHeaders.length > 0) {
        print("[HTTP Sender] Missing security headers: " + missingHeaders.join(", "));
    }
}
