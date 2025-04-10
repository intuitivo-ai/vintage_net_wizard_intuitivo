"use strict";

(() => {
  const doorState = document.querySelector("#door-state");
  const LockState = document.querySelector("#lock-state");
  const LockType = document.querySelector("#lock-type");
  const LockBtn = document.querySelector("#lock-btn");
  const divClear = document.querySelector("#clear_imbera");
  const ClearBtn = document.querySelector("#clear-btn");
  const LockNama = document.querySelector("#switch-nama");
  const divNama = document.querySelector("#nama-activate");
  const imbera = document.querySelector("#imbera");
  const stateImbera = document.querySelector("#comm-imbera");
  const namaImbera = document.querySelector("#nama-imbera");
  const profileImbera = document.querySelector("#profile-imbera");
  const tempImbera = document.querySelector("#temp-imbera");
  const versionImbera = document.querySelector("#version-imbera");
  const NTP = document.querySelector("#ntps");
  const APN = document.querySelector("#apn");

  var methodSelect = document.getElementById("method");
  var addressGroup = document.getElementById("address-group");
  var netmaskGroup = document.getElementById("netmask-group");
  var gatewayGroup = document.getElementById("gateway-group");
  var nameServersGroup = document.getElementById("name-servers-group");

  // Agregar el event listener para el cambio de valor
  methodSelect.addEventListener("change", toggleFields);

  // Llamar a la función para asegurarse de que los campos correctos se muestren al cargar la página
  toggleFields();

  getDoorState();
  setInterval(getDoorState, 1000);

  getLockState();
  setInterval(getLockState, 1000);

  getLockType();

  getNtpApn();
  getInternetSharingConfig();

  initStream();

  //setTimeout(() => initStream(), 100);

  //setTimeout(() => changeVideo("0", 1), 5000);

  //setTimeout(() => changeVideo("1", 1), 5000);

  //setTimeout(() => changeVideo("2", 1), 5000);

  // Call the function on page load to ensure the correct fields are displayed
  window.onload = toggleFields;

  async function fetchBinaryData(url, data) {
    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(data),
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error("Error al obtener el binary.");
    }

    return response.arrayBuffer();
  }

  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function setcam(cam, binaryData) {
    const base64Data = arrayBufferToBase64(binaryData);
    cam.src = "data:image/jpeg;base64," + base64Data;
  }

  function initStream() {
    fetch("/api/v1/init_cams")
      .then((resp) => resp.json())
      .then((state) => {});
  }

  function stopStream() {
    fetch("/api/v1/stop_cams")
      .then((resp) => resp.json())
      .then((state) => {});
  }

  function toggleFields() {
    var method = document.getElementById("method").value;

    if (method === "dhcp") {
      addressGroup.style.display = "none";
      netmaskGroup.style.display = "none";
      gatewayGroup.style.display = "none";
      nameServersGroup.style.display = "none";
    } else {
      addressGroup.style.display = "block";
      netmaskGroup.style.display = "block";
      gatewayGroup.style.display = "block";
      nameServersGroup.style.display = "block";
    }
  }

  window.addEventListener("beforeunload", function (e) {
    stopStream();
    return; //Webkit, Safari, Chrome
  });

  window.addEventListener("onunload", function (e) {
    stopStream();
    return; //Webkit, Safari, Chrome
  });

  async function changeVideo(cam_index, index) {
    const cam = document.querySelector(`#cam${cam_index}`);

    const format_index = index.toString().padStart(4, "0");

    fetchBinaryData("/api/v1/cam", { cam_index: cam_index, format_index: format_index })
      .then((binaryData) => {
        setcam(cam, binaryData);
      })
      .catch((error) => {
        console.error("Error: ", error);
      });

    await sleep(1000);

    changeVideo(cam_index, index + 1);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function getDoorState() {
    fetch("/api/v1/door")
      .then((resp) => resp.json())
      .then((state) => {
        doorState.textContent = state.status;
      });
  }

  function getLockType() {
    fetch("/api/v1/lock_type")
      .then((resp) => resp.json())
      .then((state) => {
        LockType.textContent = state.type;

        if (state.type === "imbera") {
          imbera.style.display = "block"; // Mostrar el div
          divNama.style.display = "block"; // Mostrar el div
          divClear.style.display = "block"; // Mostrar el div
          getImbera();
          setInterval(getImbera, 1000);
        } else {
          imbera.style.display = "none"; // Ocultar el div
          divNama.style.display = "none"; // Ocultar el div
          divClear.style.display = "none"; // Ocultar el div
        }
      });
  }

  function getLockState() {
    fetch("/api/v1/status_lock")
      .then((resp) => resp.json())
      .then((state) => {
        LockState.textContent = state.status;
        stateImbera.textContent = state.isWorking;
      });
  }

  function getNtpApn() {
    fetch("/api/v1/get_ntp_apn")
      .then((resp) => resp.json())
      .then((state) => {
        const mobileNetwork = state.mobileNetwork;
        NTP.value = state.ntp;
        APN.value = mobileNetwork.apn;
      });
  }

  // Obtener la configuración actual de compartir internet
  function getInternetSharingConfig() {
    fetch("/api/v1/get_internet_sharing")
      .then((resp) => resp.json())
      .then((state) => {
        const internetSelect = document.getElementById("internet_select");
        if (internetSelect) {
          const sharingMode = state.mode;
          // Si el modo es vacío o "disabled", seleccionar la opción "disabled"
          if (!sharingMode || sharingMode === "" || sharingMode === "disabled") {
            internetSelect.value = "disabled";
          } else {
            // De lo contrario, seleccionar la opción correspondiente
            internetSelect.value = sharingMode;
          }
          
          // Disparar el evento change para activar el código que muestra/oculta las credenciales WiFi
          const event = new Event("change");
          internetSelect.dispatchEvent(event);
        }
      })
      .catch((error) => {
        console.error("Error getting internet sharing config:", error);
        // En caso de error, seleccionar "disabled" por defecto
        const internetSelect = document.getElementById("internet_select");
        if (internetSelect) {
          internetSelect.value = "disabled";
        }
      });
  }

  function getImbera() {
    fetch("/api/v1/get_imbera_all")
      .then((resp) => resp.json())
      .then((state) => {


        const nama = state.nama;

        namaImbera.textContent = nama.enabled;
        profileImbera.textContent = nama.profile;
        tempImbera.textContent = nama.temperature + " °C";
        versionImbera.textContent = nama.version;

        if (nama.profile == 1) {
          LockNama.checked = false;
        } else if (nama.profile == 2) {
          LockNama.checked = true;
        }

      });
  }

  LockBtn.addEventListener("click", ({ target }) => {
    disableBtn(LockBtn, true);
    fetch("/api/v1/lock", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: "",
    });
    setTimeout(() => disableBtn(LockBtn, false), 1000);
  });

  ClearBtn.addEventListener("click", ({ target }) => {
    disableBtn(ClearBtn, true);
    fetch("/api/v1/clear", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: "",
    });
    setTimeout(() => disableBtn(ClearBtn, false), 12000);
  });

  function disableBtn(btn, disabled) {
    btn.disabled = disabled;
  }

  LockNama.addEventListener("click", ({ target }) => {
    //console.log(`debug: ${target.checked}`)
    fetch("/api/v1/nama_change", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ value: target.checked }),
    });
  });

  // WiFi Credentials and Reboot Functionality
  document.addEventListener("DOMContentLoaded", function() {
    // Selector de internet para mostrar/ocultar credenciales WiFi
    const internetSelect = document.getElementById("internet_select");
    const wifiCredentialsDiv = document.getElementById("wifi_credentials");
    const wifiSsidSpan = document.getElementById("wifi_ssid");
    const wifiPasswordSpan = document.getElementById("wifi_password");
    const rebootButton = document.getElementById("reboot_button");
    
    if (internetSelect) {
      // Mostrar u ocultar div según selección
      internetSelect.addEventListener("change", function() {
        const selectedValue = internetSelect.value;
        if (selectedValue === "wwan0_to_wlan0" || selectedValue === "eth0_to_wlan0") {
          fetch("/api/v1/wifi_credentials")
            .then(response => response.json())
            .then(data => {
              wifiSsidSpan.textContent = data.ssid || "Not available";
              wifiPasswordSpan.textContent = data.password || "Not available";
              wifiCredentialsDiv.style.display = "block";
            })
            .catch(error => {
              console.error("Error fetching WiFi credentials:", error);
              wifiCredentialsDiv.style.display = "none";
            });
        } else {
          wifiCredentialsDiv.style.display = "none";
        }
      });
      
      // Comprobar el valor inicial al cargar la página
      if (internetSelect.value === "wwan0_to_wlan0" || internetSelect.value === "eth0_to_wlan0") {
        fetch("/api/v1/wifi_credentials")
          .then(response => response.json())
          .then(data => {
            wifiSsidSpan.textContent = data.ssid || "Not available";
            wifiPasswordSpan.textContent = data.password || "Not available";
            wifiCredentialsDiv.style.display = "block";
          })
          .catch(error => {
            console.error("Error fetching WiFi credentials:", error);
          });
      }
    }
    
    // Configurar el botón de reinicio
    if (rebootButton) {
      rebootButton.addEventListener("click", function() {
        if (confirm("Are you sure you want to reboot the device?")) {
          fetch("/api/v1/reboot", {
            method: "POST"
          })
          .then(response => {
            if (response.ok) {
              alert("Device is rebooting...");
            } else {
              alert("Failed to reboot the device.");
            }
          })
          .catch(error => {
            console.error("Error rebooting device:", error);
            alert("Error: Could not reboot the device.");
          });
        }
      });
    }
  });
})();
