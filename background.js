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
console.log("Blocking all images and fonts from all sources.");

