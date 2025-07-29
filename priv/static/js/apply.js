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
      .catch(handleNetworkErrorResponse);
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

        <p>If this page doesn't update in 15-30 seconds, check that you're connected to
        the access point named "<b>${ssid}</b>"</p>
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
      fetch("/api/v1/complete").then((resp) => {
        console.log("Configuration completed successfully");
        // Optionally redirect or show additional message
      }).catch((error) => {
        console.error("Error completing configuration:", error);
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

  fetch("/api/v1/apply", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  })
  .then((resp) => {
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
        return;
      }
      // Log the specific HTTP error
      console.error("HTTP Error:", resp.status, resp.statusText);
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return resp;
  })
  .then((resp) => {
    if (resp) {
      console.log("Apply successful, starting status polling");
      runGetStatus();
    }
  })
  .catch((error) => {
    console.error("Apply error details:", error);
    console.error("Error type:", error.constructor.name);
    console.error("Error message:", error.message);
    
    let errorDetails = error.message;
    let troubleshooting = "";
    
    // Provide specific troubleshooting based on error type
    if (error.message.includes("HTTP 500")) {
      troubleshooting = "<p><strong>Possible causes:</strong> Internal server error, check device logs.</p>";
    } else if (error.message.includes("HTTP 404")) {
      troubleshooting = "<p><strong>Possible causes:</strong> No network configurations found.</p>";
    } else if (error.message.includes("Failed to fetch") || error.message.includes("NetworkError")) {
      troubleshooting = "<p><strong>Possible causes:</strong> Network connection lost, device not responding.</p>";
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
}
