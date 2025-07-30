"use strict";

function applyConfiguration(title, button_color) {
  const state = {
    view: "trying",
    dots: "",
    completeTimer: null,
    targetElem: document.querySelector(".content"),
    configurationStatus: "not_configured",
    completed: false,
    ssid: document.getElementById("ssid").getAttribute("value"),
    title: title,
  };

  function runGetStatus() {
    setTimeout(getStatus, 1000);
  }

  function getStatus() {
    // Add timeout to prevent hanging requests
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    fetch("/api/v1/configuration/status", {
      signal: controller.signal
    })
      .then((resp) => {
        clearTimeout(timeoutId);
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.json();
      })
      .then(handleStatusResponse)
      .catch((error) => {
        clearTimeout(timeoutId);
        
        // Handle network change errors during polling
        if (error.message.includes("NetworkError") || 
            error.message.includes("ERR_NETWORK_CHANGED") ||
            error.message.includes("Failed to fetch") ||
            error.message.includes("aborted")) {
          
          console.log("Network error during polling - continuing to retry");
          handleNetworkErrorResponse(error);
        } else {
          console.error("Status polling error:", error);
          handleNetworkErrorResponse(error);
        }
      });
  }

  function handleStatusResponse(status) {
    console.log("Status received:", status);
    
    switch (status) {
      case "not_configured":
        state.dots = state.dots + ".";
        if (state.dots.length > 10) {
          state.dots = ""; // Reset dots to prevent infinite growth
        }
        render(state);
        runGetStatus(); // Continue polling
        break;
      case "good":
        state.view = "configurationGood";
        state.configurationStatus = status;
        state.completeTimer = setTimeout(complete, 60000);
        render(state);
        break;
      case "bad":
        state.view = "configurationBad";
        state.configurationStatus = status;
        render(state);
        break;
      default:
        console.log("Unknown status:", status);
        runGetStatus(); // Continue polling for unknown status
        break;
    }
  }

  function handleNetworkErrorResponse(e) {
    console.log("Network error:", e);
    state.dots = state.dots + ".";
    if (state.dots.length > 15) {
      state.dots = ""; // Reset dots to prevent infinite growth
    }
    render(state);
    runGetStatus(); // Continue polling even on network errors
  }

  function createCompleteLink({ targetElem, view }) {
    const button = document.createElement("button");
    var btnClass = "btn-primary";
    var btnText = "Complete";

    if (view === "configurationBad") {
      btnClass = "btn-danger";
      btnText = "Complete Without Verification";
    }

    if (view != "configurationBad") {
      button.style.backgroundColor = button_color;
    }

    button.classList.add("btn");
    button.classList.add(btnClass);
    button.addEventListener("click", handleCompleteClick);
    button.innerHTML = btnText;

    targetElem.appendChild(button);
  }

  function handleCompleteClick(e) {
    if (state.completeTimer) {
      clearTimeout(state.completeTimer);
      state.completeTimer = null;
    }
    complete();
  }

  function view({ view, title, dots, ssid }) {
    switch (view) {
      case "trying":
        return [
          `
        <p>Please wait while the ${title} verifies your configuration.</p>
        
        <p>${dots}</p>
        
        <p><strong>What's happening:</strong></p>
        <ul class="text-left">
          <li>Device is connecting to your WiFi network</li>
          <li>Verifying network credentials</li>
          <li>Testing internet connectivity</li>
        </ul>

        <p class="text-muted">If this page doesn't update in 15-30 seconds, check that you're connected to
        the access point named "<b>${ssid}</b>". Network changes during configuration are normal.</p>
        `,
          runGetStatus,
        ];
      case "configurationGood":
        return [
          `
        <p>Success!</p>

        <p>Press "Complete" to exit the wizard and connect back to your previous network.</p>
        <p>Exiting automatically after 60 seconds.</p>
        `,
          createCompleteLink,
        ];
      case "configurationBad":
        return [
          `
        <p>Failed to connect.</p>

        <p>Try checking the following:</p>
        <ul>
          <li>All WiFi passwords are correct</li>
          <li>At least one network is in range</li>
          <li>Whether your network administrator requires additional steps for granting access to the WiFi network</li>
        </ul>

        <p>Please check your setup and try again or skip verification.</p>
        <a class="btn btn-primary" href="/">Configure</a>
        `,
          createCompleteLink,
        ];
      case "complete":
        return [
          `
          <div class="text-center">
            <h3 class="text-success">✓ Configuration Complete!</h3>
            <p>Your device has been successfully configured and will now connect to your network.</p>
            <p class="text-muted">You can close this page or wait for automatic redirection...</p>
          </div>
          `, 
          null
        ];
    }
  }

  function complete() {
    // First, show the success message immediately
    state.view = "complete";
    render(state);
    
    // Then, after showing success, make the API call to actually complete
    setTimeout(() => {
      console.log("Calling complete endpoint...");
      
      fetch("/api/v1/complete", {
        method: "GET"
      })
      .then((resp) => {
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return resp.json();
      })
      .then((data) => {
        console.log("Configuration completed successfully:", data);
        
        // Update the UI to show final completion message
        state.targetElem.innerHTML = `
          <div class="text-center">
            <h3 class="text-success">✓ Setup Complete!</h3>
            <p>${data.message || 'Your device has been successfully configured.'}</p>
            <p class="text-muted">The wizard is shutting down. You can close this page.</p>
            <p class="text-muted">Your device will reconnect to the configured network shortly.</p>
          </div>
        `;
      })
      .catch((error) => {
        console.error("Error completing configuration:", error);
        
        // Show error but still indicate the process might have worked
        state.targetElem.innerHTML = `
          <div class="text-center">
            <h3 class="text-warning">⚠ Completion Error</h3>
            <p>There was an issue finalizing the setup, but your configuration may still be active.</p>
            <p class="text-muted">Error: ${error.message}</p>
            <p class="text-muted">You can try closing this page and checking if your device connected to the network.</p>
          </div>
        `;
      });
    }, 2000); // Show success message for 2 seconds before actually completing
  }

  function render(state) {
    const [innerHTML, action] = view(state);
    state.targetElem.innerHTML = innerHTML;

    if (action) {
      action(state);
    }
  }

  // Show initial message that configuration is starting
  state.targetElem.innerHTML = `
    <p>Starting configuration process...</p>
    <p>Preparing to apply network settings...</p>
    <p class="text-muted">Please wait a moment...</p>
  `;

  // Add delay before making the apply request to ensure stability
  setTimeout(() => {
    console.log("Starting apply request after delay");
    
    // Add timeout to the apply fetch to handle network issues
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      console.log("Apply request timeout - aborting");
      controller.abort();
    }, 15000); // 15 second timeout for apply

    fetch("/api/v1/apply", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      signal: controller.signal
    })
  .then((resp) => {
    clearTimeout(timeoutId);
    console.log("Apply response status:", resp.status, "OK:", resp.ok);
    
    if (!resp.ok) {
      if (resp.status === 404) {
        // No configurations to apply
        console.log("No configurations found to apply");
        state.view = "configurationBad";
        state.targetElem.innerHTML = `
          <p>No network configurations found to apply.</p>
          <p>Please go back and configure at least one network.</p>
          <a class="btn btn-primary" href="/">Configure Networks</a>
        `;
        return null; // Return null instead of undefined to handle properly
      }
      // Log the specific HTTP error
      console.error("HTTP Error:", resp.status, resp.statusText);
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return resp;
  })
  .then((resp) => {
    // Check if resp is not null (could be null from 404 handling above)
    if (resp) {
      console.log("Apply successful, starting status polling");
      runGetStatus();
    }
  })
  .catch((error) => {
    clearTimeout(timeoutId);
    console.error("Apply error details:", error);
    console.error("Error type:", error.constructor.name);
    console.error("Error message:", error.message);
    
    // Check for network change/abort errors specifically
    if (error.message.includes("NetworkError") || 
        error.message.includes("ERR_NETWORK_CHANGED") ||
        error.message.includes("ERR_ABORTED") ||
        error.message.includes("Failed to fetch") ||
        error.message.includes("Load failed") ||  // Add Safari specific error
        error.name === "AbortError") {
      
      console.log("Network change/abort detected - this is normal during WiFi configuration");
      
      // Show a message indicating this is expected and start polling
      state.targetElem.innerHTML = `
        <p>Configuration in progress...</p>
        <p>The device is switching networks. Please wait while we verify the connection.</p>
        <p class="text-muted">This may take 15-30 seconds.</p>
      `;
      
      // Start polling immediately since the apply probably worked
      setTimeout(() => {
        runGetStatus();
      }, 3000); // Wait 3 seconds then start polling
      
      return; // Don't show error message
    }
    
    let errorDetails = error.message;
    let troubleshooting = "";
    
    // Provide specific troubleshooting based on error type
    if (error.message.includes("HTTP 500")) {
      troubleshooting = "<p><strong>Possible causes:</strong> Internal server error, check device logs.</p>";
    } else if (error.message.includes("HTTP 404")) {
      troubleshooting = "<p><strong>Possible causes:</strong> No network configurations found.</p>";
    } else if (error.message.includes("timeout") || error.message.includes("aborted")) {
      troubleshooting = "<p><strong>Possible causes:</strong> Request timeout, device is busy.</p>";
    }
    
    state.view = "configurationBad";
    state.targetElem.innerHTML = `
      <p>Failed to start configuration process.</p>
      <p><strong>Error:</strong> ${errorDetails}</p>
      ${troubleshooting}
      <p>Check the browser console for more details.</p>
      <a class="btn btn-primary" href="/">Try Again</a>
    `;
  });
  }, 2000); // 2 second delay before starting the apply process
}
