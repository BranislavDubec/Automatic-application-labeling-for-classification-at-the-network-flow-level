var port = browser.runtime.connectNative("receiver");

function onResponse(response) {
  console.log(`Received ${response}`);
}

function onError(error) {
  console.log(`Error: ${error}`);
}

function logRequest(details) {
  if (!details.fromCache){
      let sendObject = {
        url: details.url,
        ip: details.ip
      }
      port.postMessage(details);
    
  }
}
browser.webRequest.onResponseStarted.addListener(
  logRequest,
  {urls: ["<all_urls>"]}
);


