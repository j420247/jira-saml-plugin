var client;
setTimeout(function() {
        client = new ZeroClipboard( document.getElementById("copy-button") );

        client.on( "copy", function (event) {
          var clipboard = event.clipboardData;
      var samlField = document.getElementById("samlEndpoint");
          clipboard.setData( "text/plain", samlField.value );
          var endpointCopied = document.getElementById("endpoint-copied");
          endpointCopied.style.visibility = "visible";
      setTimeout(function() {
            endpointCopied.style.visibility = "hidden";
          }, 2000);
      return false;
        });
}, 500);
