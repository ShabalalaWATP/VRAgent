// ZAP Authentication Script - Session Validation
// Type: authentication
// Engine: ECMAScript (Graal.js)
// Description: Validates authentication session and detects logged-out states

function authenticate(helper, paramsValues, credentials) {
    var loginUrl = paramsValues.get("loginUrl");
    var username = credentials.getParam("username");
    var password = credentials.getParam("password");
    
    // Build login request
    var requestUri = new URI(loginUrl, false);
    var requestMethod = HttpRequestHeader.POST;
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
    
    var requestBody = "username=" + encodeURIComponent(username) + 
                      "&password=" + encodeURIComponent(password);
    
    var msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
    
    helper.sendAndReceive(msg);
    
    return msg;
}

function getRequiredParamsNames() {
    return ["loginUrl"];
}

function getOptionalParamsNames() {
    return [];
}

function getCredentialsParamsNames() {
    return ["username", "password"];
}
