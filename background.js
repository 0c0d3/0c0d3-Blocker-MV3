// background.js

// Block images and fonts from all URLs
browser.declarativeNetRequest.updateDynamicRules({
  addRules: [
    {
      id: 1, // Numeric ID for the first rule
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "*", // Match all URLs
        resourceTypes: ["image", "font", "imageset", "object", "ping", "sub_frame", "xslt", "xml_dtd", "beacon", "other"], // Block images and fonts
      }
    }
  ],
  removeRuleIds: [1] // Clear the previous rule with ID 1 if it exists
});

// Log the action to the console

// Block fingerprinting headers such as User-Agent, geolocation, and more
browser.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        console.log("Blocking fingerprinting and image headers for:", details.url);

        const headersToBlock = [
            "user-agent",            // Block User-Agent header
            "accept-language",       // Block Accept-Language header
            "referer",               // Block Referer header
            "accept-encoding",       // Block Accept-Encoding header
            "geolocation",           // Block geolocation headers
            "sec-ch-ua",             // Block Client Hints header (browser)
            "sec-ch-ua-mobile",      // Block mobile Client Hints
            "sec-ch-ua-platform",    // Block platform Client Hints (OS)
            "sec-fetch-site",        // Block the fetch site's origin policy
            "sec-fetch-mode",        // Block fetch mode information
            "sec-fetch-dest",        // Block fetch destination
            "dnt",                   // Block Do Not Track header
            "x-forwarded-for",       // Block IP forwarding header
            "x-real-ip",             // Block real IP header
            "device-memory",         // Block Device Memory header
            "downlink",              // Block Network Downlink header
            "rtt",                   // Block Round-Trip Time header
            "ect",                   // Block Effective Connection Type
            "save-data",             // Block Save-Data header
            "accept",                // Block Accept header (image-related)
            "if-modified-since",     // Block If-Modified-Since (image caching)
            "range"                  // Block Range header (used for loading partial content like images)
        ];

        // Add logic to disable HTTP/2 and HTTP/3 by removing ALPN-related headers
        const httpVersionsToBlock = [
            "upgrade-insecure-requests", // Upgrade-Insecure-Requests header triggers HTTP/2
            "alt-svc",                   // Alt-Svc allows switching to HTTP/2/3
            "early-data"                 // Early-Data used in HTTP/2 and HTTP/3
        ];

        // Filter out the headers to block
        details.requestHeaders = details.requestHeaders.filter(header => 
            !headersToBlock.includes(header.name.toLowerCase()) &&
            !httpVersionsToBlock.includes(header.name.toLowerCase())
        );

        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "requestHeaders"]
);

// Block ETag from incoming headers (response)
browser.webRequest.onHeadersReceived.addListener(
    function(details) {
        console.log("Blocking ETag headers for:", details.url);

        // Remove ETag from the response headers
        details.responseHeaders = details.responseHeaders.filter(header => 
            header.name.toLowerCase() !== "etag"
        );
        
        return { responseHeaders: details.responseHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "responseHeaders"]
);

// Block ETag from outgoing requests (just in case)
browser.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        console.log("Blocking outgoing ETag headers for:", details.url);

        // Remove ETag from the request headers
        details.requestHeaders = details.requestHeaders.filter(header => 
            header.name.toLowerCase() !== "if-none-match"
        );

        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "requestHeaders"]
);


// Block ETag from incoming headers (response)
browser.webRequest.onHeadersReceived.addListener(
    function(details) {
        console.log("Blocking ETag headers for:", details.url);

        // Remove ETag from the response headers
        details.responseHeaders = details.responseHeaders.filter(header => 
            header.name.toLowerCase() !== "etag"
        );
        
        return { responseHeaders: details.responseHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "responseHeaders"]
);

// Block ETag from outgoing requests (just in case)
browser.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        console.log("Blocking outgoing ETag headers for:", details.url);

        // Remove ETag from the request headers
        details.requestHeaders = details.requestHeaders.filter(header => 
            header.name.toLowerCase() !== "if-none-match"
        );

        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "requestHeaders"]
);


// Block access to specific fingerprinting APIs
browser.webRequest.onBeforeRequest.addListener(
    function(details) {
        const fingerprintingAPIs = [
            "navigator.permissions",
            "navigator.geolocation.getCurrentPosition",
            "window.crypto.getRandomValues",
            "navigator.userAgent",
            "navigator.plugins",
            "navigator.languages",
            "window.localStorage",
            "window.sessionStorage"
        ];

        // Check if the request URL contains any of the fingerprinting APIs
        if (fingerprintingAPIs.some(api => details.url.includes(api))) {
            console.log("Blocked fingerprinting API access:", details.url);
            return { cancel: true }; // Block the request
        }

        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);


// Block access to specific headers that can reveal browser and OS information
browser.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        const browserOSHeadersToBlock = [
            "user-agent",          // Block User-Agent
            "sec-ch-ua",          // Block Client Hints
            "sec-ch-ua-mobile",   // Block mobile Client Hints
            "sec-ch-ua-platform"  // Block platform Client Hints
        ];

        console.log("Blocking headers that reveal browser and OS information for:", details.url);
        details.requestHeaders = details.requestHeaders.filter(header => 
            !browserOSHeadersToBlock.includes(header.name.toLowerCase())
        );

        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"]
);

