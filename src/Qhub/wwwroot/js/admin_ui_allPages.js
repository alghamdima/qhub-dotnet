// This file contains shared JS code for all admin views
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...


// Copies the data-clipboard-text of any .copyurl button, including buttons added after the page loaded
document.addEventListener("click", event => {
    const button = event.target.closest(".copyurl[data-clipboard-text]");
    if (!button) {
        return;
    }
    // Browsers only allow clipboard access over HTTPS or on localhost
    const copied = navigator.clipboard ? navigator.clipboard.writeText(button.dataset.clipboardText) : Promise.reject();
    copied.catch(() => showToast(4000, "Could not copy: the browser only allows this over HTTPS"));
});

var toastId;

function showToast(timeout, text) {
    let notification = document.getElementById("toastnotification");
    if (typeof text !== 'undefined')
        notification.innerText = text;
    else
        notification.innerText = notification.dataset.default;
    notification.classList.add("show");

    clearTimeout(toastId);
    toastId = setTimeout(() => {
        hideToast();
    }, timeout);
}

function hideToast() {
    document.getElementById("toastnotification").classList.remove("show");
}

// Puts an untouched copy of the modal back when it closes, which clears previous values and form validation
function resetModalOnHide(id) {
    const modal = document.getElementById(id);
    const original = modal.cloneNode(true);
    modal.addEventListener("hide.bs.modal", () => {
        modal.remove();
        document.body.appendChild(original);
    }, { once: true });
}


// Converts a unix timestamp to the local "YYYY-MM-DDTHH:MM" value a datetime-local input expects
function unixToLocalInput(timestamp) {
    const date = new Date(timestamp * 1000);
    date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
    return date.toISOString().slice(0, 16);
}

// Converts the value of a datetime-local input, which is in local time, to a unix timestamp
function localInputToUnix(value) {
    return Math.floor(new Date(value).getTime() / 1000);
}

function createCalendar(element, timestamp) {
    const input = document.getElementById(element);
    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    input.min = unixToLocalInput(startOfToday.getTime() / 1000);
    input.value = unixToLocalInput(timestamp);
}


function handleEditCheckboxChange(checkbox) {
    var targetElement = document.getElementById(checkbox.getAttribute("data-toggle-target"));

    if (checkbox.checked) {
        targetElement.classList.remove("disabled");
        targetElement.removeAttribute("disabled");
    } else {
        targetElement.classList.add("disabled");
        targetElement.setAttribute("disabled", true);
    }
}

function downloadFileWithPresign(id) {
    apiFilesListDownloadSingle(id)
        .then(data => {
            if (!data.hasOwnProperty("downloadUrl")) {
                throw new Error("Unable to get presigned key");
            }
            const a = document.createElement('a');
            a.href = data.downloadUrl;
            a.style.display = 'none';

            document.body.appendChild(a);
            a.click();
            a.remove();
        })
        .catch(error => {
            alert("Unable to download. Details are in the browser console.");
            console.error('Error:', error);
        });
}

function downloadFilesZipWithPresign(ids, filename) {
    apiFilesListDownloadZip(ids, filename)
        .then(data => {
            if (!data.hasOwnProperty("downloadUrl")) {
                throw new Error("Unable to get presigned key");
            }
            const a = document.createElement('a');
            a.href = data.downloadUrl;
            a.style.display = 'none';

            document.body.appendChild(a);
            a.click();
            a.remove();
        })
        .catch(error => {
            alert("Unable to download. Details are in the browser console.");
            console.error('Error:', error);
        });
}

/**
 * doLogout
 *
 * Called by the Logout link's onclick. Notifies the SharedWorker (if active)
 * to drop this port – and close the SSE connection if no other tabs remain –
 * then navigates to ./logout. Using an explicit message here is more precise
 * than beforeunload, which would fire on every navigation (refresh, back, etc.)
 * and could prematurely tear down the worker while other tabs are still open.
 */
function doLogout(event) {
    if (typeof sseWorkerPort !== "undefined" && sseWorkerPort !== null) {
        // "shutdown" tells the worker to close the SSE connection and notify
        // all other tabs, not just this one, since the session is now invalid
        // for everyone. Each tab's onmessage handler will redirect to ./login.
        sseWorkerPort.postMessage({ type: "shutdown" });
    }
    window.location.href = "./logout";
}
