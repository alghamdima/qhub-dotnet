// This file contains JS code to connect to the API
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...


const storedTokens = new Map();

async function getToken(permission, forceRenewal) {
    const apiUrl = './auth/token';

    if (!forceRenewal) {
        if (!storedTokens.has(permission)) {
            return getToken(permission, true);
        }
        let token = storedTokens.get(permission);
        if (token.expiry - (Date.now() / 1000) < 60) {
            return getToken(permission, true);
        }
        return token.key;
    }
    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'permission': permission

        },
    };
    // Errors go to the caller, which logs them
    const response = await fetch(apiUrl, requestOptions);
    if (!response.ok) {
        throw new Error(`Request failed with status: ${response.status}`);
    }
    const data = await response.json();
    if (!data.hasOwnProperty("key")) {
        throw new Error(`Invalid response when trying to get token`);
    }
    storedTokens.set(permission, {
        key: data.key,
        expiry: data.expiry
    });
    return data.key;
}

// /auth

async function apiAuthModify(apiKey, permission, modifier) {
    const apiUrl = './api/auth/modify';
    const reqPerm = 'PERM_API_MOD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'targetKey': apiKey,
            'permission': permission,
            'permissionModifier': modifier

        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiAuthModify:", error);
        throw error;
    }
}


async function apiAuthFriendlyName(apiKey, newName) {
    const apiUrl = './api/auth/friendlyname';
    const reqPerm = 'PERM_API_MOD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'targetKey': apiKey,
            'friendlyName': newName

        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiAuthModify:", error);
        throw error;
    }
}


async function apiAuthDelete(apiKey) {
    const apiUrl = './api/auth/delete';
    const reqPerm = 'PERM_API_MOD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'targetKey': apiKey,
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiAuthDelete:", error);
        throw error;
    }
}


async function apiAuthCreate() {
    const apiUrl = './api/auth/create';
    const reqPerm = 'PERM_API_MOD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'basicPermissions': 'true'
        },
    };


    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiAuthCreate:", error);
        throw error;
    }
}



// /chunk


async function apiChunkComplete(uuid, filename, filesize, contenttype, allowedDownloads, expiryDays, expiryMinutes, password, nonblocking) {
    const apiUrl = './api/chunk/complete';
    const reqPerm = 'PERM_UPLOAD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'uuid': uuid,
            'filename': 'base64:' + Base64.encode(filename),
            'filesize': filesize,
            'contenttype': contenttype,
            'allowedDownloads': allowedDownloads,
            'expiryDays': expiryDays,
            'password': password,
            'nonblocking': nonblocking
        },
    };
    // An empty header is rejected, so it is only sent when set
    if (expiryMinutes !== "") {
        requestOptions.headers['expiryMinutes'] = expiryMinutes;
    }

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            let errorMessage;

            // Attempt to parse JSON, fallback to text if parsing fails
            try {
                const errorResponse = await response.json();
                errorMessage = errorResponse.ErrorMessage || `Request failed with status: ${response.status}`;
            } catch {
                // Handle non-JSON error
                const errorText = await response.text();
                errorMessage = errorText || `Request failed with status: ${response.status}`;
            }
            throw new Error(errorMessage);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiChunkComplete:", error);
        throw error;
    }
}


// /files


async function apiFilesReplace(id, newId) {
    const apiUrl = './api/files/replace';
    const reqPerm = 'PERM_REPLACE';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'id': id,
            'Authorization': 'Bearer ' + token,
            'idNewContent': newId,
            'deleteNewFile': false
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesReplace:", error);
        throw error;
    }
}

async function apiFilesListById(fileId) {
    const apiUrl = './api/files/list/' + fileId;
    const reqPerm = 'PERM_VIEW';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesListById:", error);
        throw error;
    }
}


async function apiFilesListDownloadSingle(fileId) {
    const apiUrl = './api/files/download/' + fileId;
    const reqPerm = 'PERM_DOWNLOAD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'presignUrl': true
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesListDownloadSingle:", error);
        throw error;
    }
}


async function apiFilesQr(fileId) {
    const apiUrl = './api/files/qr/' + fileId;
    const reqPerm = 'PERM_UPLOAD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token
            },
        });
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        return await response.blob();
    } catch (error) {
        console.error("Error in apiFilesQr:", error);
        throw error;
    }
}


async function apiFilesListDownloadZip(fileIds, filename) {
    const apiUrl = './api/files/downloadzip';
    const reqPerm = 'PERM_DOWNLOAD';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'ids': fileIds,
            'filename': 'base64:' + Base64.encode(filename),
            'presignUrl': true
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesListDownloadZip:", error);
        throw error;
    }
}


async function apiFilesModify(id, allowedDownloads, expiry, password, originalPw) {
    const apiUrl = './api/files/modify';
    const reqPerm = 'PERM_EDIT';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'id': id,
            'Authorization': 'Bearer ' + token,
            'allowedDownloads': allowedDownloads,
            'expiryTimestamp': expiry
        },
    };
    // The password changes only when the header is sent; an empty one removes it
    if (!originalPw) {
        requestOptions.headers['password'] = password;
    }
    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesModify:", error);
        throw error;
    }
}



async function apiFilesDelete(id, delay) {
    const apiUrl = './api/files/delete';
    const reqPerm = 'PERM_DELETE';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'id': id,
            'delay': delay
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiFilesDelete:", error);
        throw error;
    }
}


async function apiFilesRestore(id) {
    const apiUrl = './api/files/restore';
    const reqPerm = 'PERM_DELETE';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'id': id
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiFilesRestore:", error);
        throw error;
    }
}



// users


async function apiUserCreate(userName) {
    const apiUrl = './api/user/create';
    const reqPerm = 'PERM_MANAGE_USERS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'username': userName

        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            if (response.status == 409) {
                throw new Error("duplicate");
            }
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiUserModify:", error);
        throw error;
    }
}


async function apiUserModify(userId, permission, modifier) {
    const apiUrl = './api/user/modify';
    const reqPerm = 'PERM_MANAGE_USERS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'userid': userId,
            'userpermission': permission,
            'permissionModifier': modifier

        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiUserModify:", error);
        throw error;
    }
}


async function apiUserChangeRank(userId, newRank) {
    const apiUrl = './api/user/changeRank';
    const reqPerm = 'PERM_MANAGE_USERS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'userid': userId,
            'newRank': newRank

        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiUserModify:", error);
        throw error;
    }
}

async function apiUserDelete(id, deleteFiles) {
    const apiUrl = './api/user/delete';
    const reqPerm = 'PERM_MANAGE_USERS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'userid': id,
            'deleteFiles': deleteFiles
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiUserDelete:", error);
        throw error;
    }
}



async function apiUserResetPassword(id, generatePw) {
    const apiUrl = './api/user/resetPassword';
    const reqPerm = 'PERM_MANAGE_USERS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'userid': id,
            'generateNewPassword': generatePw
        },
    };

    // Errors go to resetPw(), which logs them
    const response = await fetch(apiUrl, requestOptions);
    if (!response.ok) {
        throw new Error(`Request failed with status: ${response.status}`);
    }
    return response.json();
}


// Logs


async function apiLogSystemStatus() {
    const apiUrl = './api/logs/systemStatus';
    const reqPerm = 'PERM_MANAGE_LOGS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiLogSystemStatus:", error);
        throw error;
    }
}

async function apiLogResetTraffic() {
    const apiUrl = './api/logs/resetTraffic';
    const reqPerm = 'PERM_MANAGE_LOGS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiLogResetTraffic:", error);
        throw error;
    }
}

async function apiLogGet(timestamp) {
    const apiUrl = './api/logs/get';
    const reqPerm = 'PERM_MANAGE_LOGS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'timestamp': timestamp
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error in apiLogGet:", error);
        throw error;
    }
}


async function apiLogsDelete(timestamp) {
    const apiUrl = './api/logs/delete';
    const reqPerm = 'PERM_MANAGE_LOGS';

    let token;

    try {
        token = await getToken(reqPerm, false);
    } catch (error) {
        console.error("Unable to gain permission token:", error);
        throw error;
    }

    const requestOptions = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
            'timestamp': timestamp
        },
    };

    try {
        const response = await fetch(apiUrl, requestOptions);
        if (!response.ok) {
            throw new Error(`Request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error in apiLogsDelete:", error);
        throw error;
    }
}

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

// This file contains JS code for the API view
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...


function changeApiPermission(userId, permission, buttonId) {

    var indicator = document.getElementById(buttonId);
    if (indicator.classList.contains("perm-processing") || indicator.classList.contains("perm-nochange")) {
        return;
    }
    var wasGranted = indicator.classList.contains("perm-granted");
    indicator.classList.add("perm-processing");
    indicator.classList.remove("perm-granted");
    indicator.classList.remove("perm-notgranted");

    var modifier = "GRANT";
    if (wasGranted) {
        modifier = "REVOKE";
    }


    apiAuthModify(userId, permission, modifier)
        .then(data => {
            if (wasGranted) {
                indicator.classList.add("perm-notgranted");
                indicator.classList.add("perm-nownotgranted");
            } else {
                indicator.classList.add("perm-granted");
                indicator.classList.add("perm-nowgranted");
            }
            indicator.classList.remove("perm-processing");
            setTimeout(() => {
                 indicator.classList.remove("perm-nowgranted");
                 indicator.classList.remove("perm-nownotgranted");
            }, 1000);
        })
        .catch(error => {
            if (wasGranted) {
                indicator.classList.add("perm-granted");
            } else {
                indicator.classList.add("perm-notgranted");
            }
            indicator.classList.remove("perm-processing");
            alert("Unable to set permission. Details are in the browser console.");
            console.error('Error:', error);
        });
}

function deleteApiKey(apiKey) {

    document.getElementById("delete-" + apiKey).disabled = true;

    apiAuthDelete(apiKey)
        .then(data => {
            document.getElementById("row-" + apiKey).classList.add("rowDeleting");
            setTimeout(() => {
                document.getElementById("row-" + apiKey).remove();
            }, 290);
        })
        .catch(error => {
            alert("Unable to delete API key. Details are in the browser console.");
            console.error('Error:', error);
        });
}



function newApiKey() {
    document.getElementById("button-newapi").disabled = true;
    apiAuthCreate()
        .then(data => {
            addRowApi(data.Id, data.PublicId);
            document.getElementById("button-newapi").disabled = false;
        })
        .catch(error => {
            alert("Unable to create API key. Details are in the browser console.");
            console.error('Error:', error);
        });
}




function addFriendlyNameChange(apiKey) {
    let cell = document.getElementById("friendlyname-" + apiKey);
    if (cell.classList.contains("isBeingEdited"))
        return;
    cell.classList.add("isBeingEdited");
    let currentName = cell.innerText;
    let input = document.createElement("input");
    input.size = 5;
    input.value = currentName;
    let allowEdit = true;

    let submitEntry = function() {
        if (!allowEdit)
            return;
        allowEdit = false;
        let newName = input.value;
        if (newName == "") {
            newName = "Unnamed key";
        }
        cell.innerText = newName;

        cell.classList.remove("isBeingEdited");

        apiAuthFriendlyName(apiKey, newName)
            .catch(error => {
                alert("Unable to save name. Details are in the browser console.");
                console.error('Error:', error);
            });
    };

    input.onblur = submitEntry;
    input.addEventListener("keyup", function(event) {
        // Enter
        if (event.keyCode === 13) {
            event.preventDefault();
            submitEntry();
        }
    });
    cell.innerText = "";
    cell.appendChild(input);
    input.focus();
}




function addRowApi(apiKey, publicId) {

    let table = document.getElementById("apitable");
    let row = table.insertRow(0);

    row.id = "row-" + publicId;
    let cellCount = 0;
    let cellFriendlyName = row.insertCell(cellCount++);
    let cellId = row.insertCell(cellCount++);
    let cellLastUsed = row.insertCell(cellCount++);
    let cellPermissions = row.insertCell(cellCount++);
    let cellUserName;
    if (canViewOtherApiKeys) {
        cellUserName = row.insertCell(cellCount++);
    }
    let cellButtons = row.insertCell(cellCount++);

    if (canViewOtherApiKeys) {
        cellUserName.classList.add("newApiKey");
        cellUserName.innerText = userName;
    }

    cellFriendlyName.classList.add("newApiKey");
    cellId.classList.add("newApiKey");
    cellLastUsed.classList.add("newApiKey");
    cellPermissions.classList.add("newApiKey");
    cellPermissions.classList.add("prevent-select");
    cellButtons.classList.add("newApiKey");


    cellFriendlyName.innerText = "Unnamed key";
    cellFriendlyName.id = "friendlyname-" + publicId;
    cellFriendlyName.onclick = function() {
        addFriendlyNameChange(publicId);
    };
    cellId.innerText = apiKey;
    cellId.classList.add("font-monospace");
    cellLastUsed.innerText = "Never";


    const btnGroup = document.createElement("div");
    btnGroup.className = "btn-group";
    btnGroup.setAttribute("role", "group");


    // === Buttons Cell ===
    const copyButton = document.createElement('button');
    copyButton.type = 'button';
    copyButton.dataset.clipboardText = apiKey;
    copyButton.title = 'Copy API Key';
    copyButton.className = 'copyurl btn btn-outline-light btn-sm';
    copyButton.setAttribute('onclick', 'showToast(1000)');

    const copyIcon = document.createElement('i');
    copyIcon.className = 'bi bi-copy';
    copyButton.appendChild(copyIcon);

    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.id = `delete-${publicId}`;
    deleteButton.title = 'Delete';
    deleteButton.className = 'btn btn-outline-danger btn-sm';
    deleteButton.setAttribute('onclick', `deleteApiKey('${publicId}')`);

    const deleteIcon = document.createElement('i');
    deleteIcon.className = 'bi bi-trash3';
    deleteButton.appendChild(deleteIcon);

    btnGroup.appendChild(copyButton);
    btnGroup.appendChild(deleteButton);
    cellButtons.appendChild(btnGroup);

    // === Permissions Cell ===
    const perms = [{
            perm: 'PERM_VIEW',
            icon: 'bi-eye',
            granted: true,
            title: 'List Uploads'
        },
        {
            perm: 'PERM_UPLOAD',
            icon: 'bi-file-earmark-plus',
            granted: true,
            title: 'Upload'
        },
        {
            perm: 'PERM_EDIT',
            icon: 'bi-pencil',
            granted: true,
            title: 'Edit Uploads'
        },
        {
            perm: 'PERM_DELETE',
            icon: 'bi-trash3',
            granted: true,
            title: 'Delete Uploads'
        },
        {
            perm: 'PERM_REPLACE',
            icon: 'bi-recycle',
            granted: false,
            title: 'Replace Uploads'
        },
        {
            perm: 'PERM_DOWNLOAD',
            icon: 'bi-box-arrow-in-down',
            granted: false,
            title: 'Download Files'
        },
        {
            perm: 'PERM_MANAGE_USERS',
            icon: 'bi-people',
            granted: false,
            title: 'Manage Users'
        },
        {
            perm: 'PERM_MANAGE_LOGS',
            icon: 'bi-card-list',
            granted: false,
            title: 'Manage System Logs'
        },
        {
            perm: 'PERM_API_MOD',
            icon: 'bi-sliders2',
            granted: false,
            title: 'Manage API Keys'
        }
    ];

    perms.forEach(({
        perm,
        icon,
        granted,
        title
    }) => {
        const i = document.createElement('i');
        const id = `${perm.toLowerCase()}_${publicId}`;
        i.id = id;
        i.className = `bi ${icon} ${granted ? 'perm-granted' : 'perm-notgranted'}`;
        i.title = title;
        i.setAttribute('onclick', `changeApiPermission("${publicId}","${perm}", "${id}");`);
        cellPermissions.appendChild(i);
        cellPermissions.appendChild(document.createTextNode(' '));
    });


    if (!canReplaceFiles) {
        let cell = document.getElementById("perm_replace_" + publicId);
        cell.classList.add("perm-unavailable");
        cell.classList.add("perm-nochange");
    }
    if (!canManageUsers) {
        let cell = document.getElementById("perm_manage_users_" + publicId);
        cell.classList.add("perm-unavailable");
        cell.classList.add("perm-nochange");
    }
    if (!canViewSystemLog) {
        let cell = document.getElementById("perm_manage_logs_" + publicId);
        cell.classList.add("perm-unavailable");
        cell.classList.add("perm-nochange");
    }

    setTimeout(() => {
        cellFriendlyName.classList.remove("newApiKey");
        cellId.classList.remove("newApiKey");
        cellLastUsed.classList.remove("newApiKey");
        cellPermissions.classList.remove("newApiKey");
        cellButtons.classList.remove("newApiKey");
    }, 700);

}

// This file contains JS code for the Logs view
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...

function filterLogs(tag) {
    const textarea = document.getElementById('logviewer');
    if (tag == "all") {
        textarea.value = logContent;
    } else {
        textarea.value = logContent.split("\n").filter(line => line.includes("[" + tag + "]")).join("\n");
    }
    textarea.scrollTop = textarea.scrollHeight;
}

function setTrafficInfo(totalTraffic, recordingSince) {
    insertReadableSizeTwoOutputs(totalTraffic, 'totalTraffic', 'totalTrafficUnit');
    document.getElementById('cardTraffic').title= "Traffic since "+formatUnixTimestamp(recordingSince);
}

function setMemoryUsage(used, total) {
    insertReadableSizeTwoOutputs(total, 'totalMemory', 'memoryUnit');
    let unit = document.getElementById('memoryUnit').innerText;
    insertReadableSizeForcedUnit(used, 'usedMemory', unit);
}

function setDiskUsage(used, total) {
    insertReadableSizeTwoOutputs(total, 'totalDisk', 'diskUnit');
    let unit = document.getElementById('diskUnit').innerText;
    insertReadableSizeForcedUnit(used, 'usedDisk', unit);
}


function formatDuration(seconds) {
    const units = [{
            label: "y",
            value: 31536000
        },
        {
            label: "d",
            value: 86400
        },
        {
            label: "h",
            value: 3600
        },
        {
            label: "m",
            value: 60
        },
        {
            label: "s",
            value: 1
        },
    ];

    let startIndex = units.findIndex(unit => seconds >= unit.value);

    // If everything is below 1 minute, force start at minutes
    if (startIndex === -1 || units[startIndex].label === "s") {
        startIndex = units.findIndex(u => u.label === "m");
    }

    const first = units[startIndex];
    const second = units[startIndex + 1];

    const firstAmount = Math.floor(seconds / first.value);
    const remainder = seconds % first.value;
    const secondAmount = Math.floor(remainder / second.value);

    return `${firstAmount}${first.label} ${secondAmount}${second.label}`;
}

function addUptime() {
    if (currentUptime > 3600) {
        return;
    }
    setTimeout(() => {
        currentUptime = currentUptime + 1;
        document.getElementById('uptime').innerText = formatDuration(currentUptime);
        addUptime();
    }, 1000);
}

function setPercentageBar(id, num1, num2) {
    let percentage = num1;
    if (num2 !== undefined) {
        percentage = ((num1 / num2) * 100);
    }

    const bar = document.getElementById(id);

    bar.classList.remove("bg-success");
    bar.classList.remove("bg-warning");
    bar.classList.remove("bg-danger");

    if (percentage < 70) {
        bar.classList.add("bg-success");
    }
    if (percentage >= 70 && percentage < 90) {
        bar.classList.add("bg-warning");
    }
    if (percentage >= 90) {
        bar.classList.add("bg-danger");
    }
    bar.style.width = percentage + '%';
}


async function loadLogs(timestamp) {
    const textarea = document.getElementById('logviewer');

    try {
        const data = await apiLogGet(timestamp);
        lastLogUpdate = data.timestamp;
        let doScroll = true;
        if (timestamp != 0) {
            if (data.logEntries == "") {
                return;
            }
            doScroll = allowScroll();
            logContent = logContent + data.logEntries;
        } else {
            logContent = data.logEntries;
        }
        filterLogs(document.getElementById('logFilter').value);
        if (doScroll) {
            textarea.scrollTop = textarea.scrollHeight;
        }
    } catch (error) {
        lastLogUpdate = 0;
        console.error("Failed to load logs:", error);
        textarea.value = "Error loading logs. See console for details.";
    }
}


async function loadStatus() {
    try {
        const data = await apiLogSystemStatus();

        currentUptime = data.uptime;
        document.getElementById('labelCpu').innerText = data.cpuLoad + '%';
        document.getElementById('labelActiveFiles').innerText = data.activeFiles;
        setPercentageBar("barCpu", data.cpuLoad);
        setPercentageBar("barDisk", data.diskUsagePercentage);
        setPercentageBar("barMemory", data.memoryUsagePercentage);
        setMemoryUsage(data.memoryUsed, data.memoryTotal);
        setDiskUsage(data.diskUsed, data.diskTotal);
        setTrafficInfo(data.dataServed, data.trafficRecordingSince)
    } catch (error) {
        console.error("Failed to server status:", error);
    }
}

async function pollInfo() {
    firstStart = true;
    while (true) {
        await loadLogs(lastLogUpdate);
        if (firstStart) {
            firstStart = false;
        } else {
            await loadStatus();
        }
        await new Promise(r => setTimeout(r, POLL_INTERVAL_S * 1000));
    }
}

function allowScroll() {
    const textarea = document.getElementById('logviewer');
    return textarea.scrollTop + textarea.clientHeight >= textarea.scrollHeight - 5;
}


function deleteLogs() {
    const delSelector = document.getElementById("deleteLogsSel");
    if (!delSelector) {
        return;
    }
    const cutoff = delSelector.value;
    if (cutoff == "none" || cutoff == "") {
        return;
    }
    if (!confirm("Do you want to delete the selected logs?")) {
        document.getElementById('deleteLogsSel').selectedIndex = 0;
        return;
    }
    let timestamp = Math.floor(Date.now() / 1000)
    switch (cutoff) {
        case "all":
            timestamp = 0;
            break;
        case "2":
            timestamp = timestamp - 2 * 24 * 60 * 60;
            break;
        case "7":
            timestamp = timestamp - 7 * 24 * 60 * 60;
            break;
        case "14":
            timestamp = timestamp - 14 * 24 * 60 * 60;
            break;
        case "30":
            timestamp = timestamp - 30 * 24 * 60 * 60;
            break;
        default:
            return;
    }
    apiLogsDelete(timestamp)
        .then(data => {
            location.reload();
        })
        .catch(error => {
            alert("Unable to delete logs. Details are in the browser console.");
            console.error('Error:', error);
        });
}


function resetTrafficStat() {
    if (!confirm("Do you want to reset the traffic statistics?")) {
        return;
    }

    apiLogResetTraffic()
        .then(data => {
            location.reload();
        })
        .catch(error => {
            alert("Unable to reset stats. Details are in the browser console.");
            console.error('Error:', error);
        });
}

// This file contains JS code for the API view
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...


var dropzoneObject;

var isUploading = false;

var rowCount = -1;


function initDropzone() {

    Dropzone.options.uploaddropzone = {
        paramName: "file",
        dictDefaultMessage: "",
        createImageThumbnails: false,
        // The customer code is required (brief Q6): the last 4 digits of the customer's ID.
        accept: function(file, done) {
            if (!/^[0-9]{4}$/.test(document.getElementById("password").value)) {
                done("Enter the customer's code (the last 4 digits of the ID) before uploading.");
                return;
            }
            done();
        },
        chunksUploaded: function(file, done) {
            sendChunkComplete(file, done);
        },
        init: function() {
            dropzoneObject = this;
            this.on("addedfile", file => {
                file.upload.uuid = getUuid();
                saveUploadDefaults();
                addFileProgress(file);
            });
            this.on("queuecomplete", function() {
                isUploading = false;
            });
            this.on("sending", function(file, xhr, formData) {
                isUploading = true;
            });

            // Error handling for chunk upload, especially returning 413 error code (invalid nginx configuration)
            this.on("error", function(file, errorMessage, xhr) {
                console.log(errorMessage);
                if (xhr) {
                    if (xhr.status === 413) {
                        showError(file, "File too large to upload. If you are using a reverse proxy, make sure that the allowed body size is at least 70MB.");
                        return;
                    }
                    try {
                        console.log(xhr);
                        errInfo = JSON.parse(xhr.responseText);
                        showError(file, "Error: " + errInfo.ErrorMessage);
                    } catch (ignored) {
                        showError(file, "Error: " + xhr.responseText);
                    }
                } else {
                    showError(file, "Error: " + errorMessage);
                }
            });
            this.on("uploadprogress", function(file, progress, bytesSent) {
                updateProgressbar(file, progress, bytesSent);
            });
        },
    };


    document.onpaste = function(event) {
        if (dropzoneObject.disabled) {
            return;
        }
        const activeElement = document.activeElement;
        // disable upload on paste if edit field with data-allow-regular-paste is selected or the calendar view (with placeholder attribute)
        if (activeElement && (activeElement.hasAttribute('data-allow-regular-paste') || activeElement.hasAttribute('placeholder'))) {
            return;
        }

        var items = (event.clipboardData || event.originalEvent.clipboardData).items;
        for (let index in items) {
            var item = items[index];
            if (item.kind === 'file') {
                dropzoneObject.addFile(item.getAsFile());
            }
            if (item.kind === 'string') {
                item.getAsString(function(s) {
                    // If a picture was copied from a website, the origin information might be submitted, which is filtered with this regex out
                    const pattern = /<img *.+>/gi;
                    if (pattern.test(s) === false) {
                        let blob = new Blob([s], {
                            type: 'text/plain'
                        });
                        let file = new File([blob], "Pasted Text.txt", {
                            type: "text/plain",
                            lastModified: new Date(0)
                        });
                        dropzoneObject.addFile(file);
                    }
                });
            }
        }
    };

    window.addEventListener('beforeunload', (event) => {
        if (isUploading) {
            event.returnValue = 'Upload is still in progress. Do you want to close this page?';
        }
    });
}


function updateProgressbar(file, progress, bytesSent) {
    let chunkId = file.upload.uuid;
    let container = document.getElementById(`us-container-${chunkId}`);
    if (container == null || container.getAttribute('data-complete') === "true") {
        return;
    }
    let rounded = Math.round(progress);
    if (rounded < 0) {
        rounded = 0;
    }
    if (rounded > 100) {
        rounded = 100;
    }
    let millisSinceUpload = Date.now() - container.getAttribute('data-starttime');
    let megabytePerSecond = bytesSent / (millisSinceUpload / 1000) / 1024 / 1024;
    document.getElementById(`us-progressbar-${chunkId}`).style.width = rounded + "%";

    let uploadSpeed = Math.round(megabytePerSecond * 10) / 10;
    if (!Number.isNaN(uploadSpeed))
        document.getElementById(`us-progress-info-${chunkId}`).innerText = rounded + "% - " + uploadSpeed + "MB/s";
}

function addFileProgress(file) {
    addFileStatus(file.upload.uuid, file.upload.filename);
}


function setUploadDefaults() {
    let defaultDownloads = getLocalStorageWithDefault("defaultDownloads", 1);
    let defaultExpiry = getLocalStorageWithDefault("defaultExpiry", 14);
    localStorage.removeItem("defaultPassword"); // the code is never kept in the browser (brief Q6)
    let defaultUnlimitedDownloads = getLocalStorageWithDefault("defaultUnlimitedDownloads", false) === "true";
    let defaultUnlimitedTime = getLocalStorageWithDefault("defaultUnlimitedTime", false) === "true";

    document.getElementById("allowedDownloads").value = defaultDownloads;
    document.getElementById("expiryDays").value = defaultExpiry;
    document.getElementById("expiryUnit").value = getLocalStorageWithDefault("defaultExpiryUnit", "1440");
    document.getElementById("password").value = "";
    document.getElementById("enableDownloadLimit").checked = !defaultUnlimitedDownloads;
    document.getElementById("enableTimeLimit").checked = !defaultUnlimitedTime;

    document.getElementById("enablePassword").checked = true;
    document.getElementById("enablePassword").disabled = true;
    document.getElementById("password").disabled = false;
    document.getElementById("password").required = true;

    if (defaultUnlimitedDownloads) {
        document.getElementById("allowedDownloads").disabled = true;
    }
    if (defaultUnlimitedTime) {
        document.getElementById("expiryDays").disabled = true;
        document.getElementById("expiryUnit").disabled = true;
    }

}

function saveUploadDefaults() {
    localStorage.setItem("defaultDownloads", document.getElementById("allowedDownloads").value);
    localStorage.setItem("defaultExpiry", document.getElementById("expiryDays").value);
    localStorage.setItem("defaultExpiryUnit", document.getElementById("expiryUnit").value);
    localStorage.setItem("defaultUnlimitedDownloads", !document.getElementById("enableDownloadLimit").checked);
    localStorage.setItem("defaultUnlimitedTime", !document.getElementById("enableTimeLimit").checked);
}

function getLocalStorageWithDefault(key, default_value) {
    var value = localStorage.getItem(key);
    if (value === null) {
        return default_value;
    }
    return value;
}

function sendChunkComplete(file, done) {
    let uuid = file.upload.uuid;
    let filename = file.name;
    let filesize = file.size;
    let contenttype = file.type;
    let allowedDownloads = document.getElementById("allowedDownloads").value;
    let expiryDays = document.getElementById("expiryDays").value;
    let expiryUnit = document.getElementById("expiryUnit").value;
    let expiryMinutes = "";
    let password = document.getElementById("password").value;
    let nonblocking = true;

    if (!document.getElementById("enableDownloadLimit").checked) {
        allowedDownloads = 0;
    }
    if (!document.getElementById("enableTimeLimit").checked) {
        expiryDays = 0;
    } else if (expiryUnit !== "1440") {
        expiryMinutes = expiryDays * expiryUnit;
    }

    apiChunkComplete(uuid, filename, filesize, contenttype, allowedDownloads, expiryDays, expiryMinutes, password, nonblocking)
        .then(data => {
            done();
            let progressText = document.getElementById(`us-progress-info-${file.upload.uuid}`);
            if (progressText != null)
                progressText.innerText = "In Queue...";
        })
        .catch(error => {
            console.error('Error:', error);
            dropzoneUploadError(file, "Upload failed. Details are in the browser console.");
        });
}

function dropzoneUploadError(file, errormessage) {
    file.accepted = false;
    dropzoneObject._errorProcessing([file], errormessage);
    showError(file, errormessage);
}

function dropzoneGetFile(uid) {
    for (let i = 0; i < dropzoneObject.files.length; i++) {
        const currentFile = dropzoneObject.files[i];
        if (currentFile.upload.uuid === uid) {
            return currentFile;
        }
    }
    return null;
}

function requestFileInfo(fileId, uid) {
    apiFilesListById(fileId)
        .then(data => {
            addRow(data);
            notifyWorker({ type: "fileAdded", item: data });
            removeFileStatus(uid);
        })
        .catch(error => {
            let file = dropzoneGetFile(uid);
            if (file != null) {
                dropzoneUploadError(file, "Upload failed. Details are in the browser console.");
            }
            console.error('Error:', error);
        });
}


function parseProgressStatus(eventData) {
    let container = document.getElementById(`us-container-${eventData.chunk_id}`);
    if (container == null) {
        return;
    }
    container.setAttribute('data-complete', 'true');
    let text;
    switch (eventData.upload_status) {
        case 0:
            text = "Processing file...";
            break;
        case 1:
            text = "Saving file...";
            break;
        case 2:
            text = "Finalising...";
            requestFileInfo(eventData.file_id, eventData.chunk_id);
            break;
        case 3:
            text = "Error";
            let file = dropzoneGetFile(eventData.chunk_id);
            if (eventData.error_message == "")
                eventData.error_message = "Server Error";
            if (file != null) {
                dropzoneUploadError(file, eventData.error_message);
            }
            return;
        default:
            text = "Unknown status";
            break;
    }
    document.getElementById(`us-progress-info-${eventData.chunk_id}`).innerText = text;
}

function showError(file, message) {
    let chunkId = file.upload.uuid;
    document.getElementById(`us-progressbar-${chunkId}`).style.width = "100%";
    document.getElementById(`us-progressbar-${chunkId}`).style.backgroundColor = "red";
    document.getElementById(`us-progress-info-${chunkId}`).innerText = message;
    document.getElementById(`us-progress-info-${chunkId}`).classList.add('uploaderror');
}


function editFile() {
    const button = document.getElementById('mb_save');
    button.disabled = true;
    let id = button.getAttribute('data-fileid');

    let allowedDownloads = document.getElementById('mi_edit_down').value;
    let expiryTimestamp = localInputToUnix(document.getElementById('mi_edit_expiry').value);
    const pwInput = document.getElementById('mi_edit_pw');
    const requirePassword = document.getElementById('mc_password').checked;
    // An empty field keeps the existing password (its placeholder reads "(unchanged)"), unticking removes it
    const originalPassword = requirePassword && pwInput.value === '' && pwInput.dataset.hasPassword === 'true';
    const newPassword = requirePassword ? pwInput.value : '';

    if (!document.getElementById('mc_download').checked) {
        allowedDownloads = 0;
    }
    if (!document.getElementById('mc_expiry').checked) {
        expiryTimestamp = 0;
    }

    let replaceFile = false;
    let replaceId = "";
    if (document.getElementById('mc_replace').checked) {
        replaceId = document.getElementById('mi_edit_replace').value;
        replaceFile = (replaceId != "");
    }

    apiFilesModify(id, allowedDownloads, expiryTimestamp, newPassword, originalPassword)
        .then(data => {
            if (!replaceFile) {
                location.reload();
                return;
            }
            apiFilesReplace(id, replaceId)
                .then(data => {
                    location.reload();
                })
                .catch(error => {
                    alert("Unable to edit file. Details are in the browser console.");
                    console.error('Error:', error);
                    button.disabled = false;
                });
        })
        .catch(error => {
            alert("Unable to edit file. Details are in the browser console.");
            console.error('Error:', error);
            button.disabled = false;
        });
}

function showEditModal(filename, id, downloads, expiry, password, unlimitedown, unlimitedtime, canReplace) {
    resetModalOnHide('modaledit');

    document.getElementById("m_filenamelabel").innerText = filename;
    document.getElementById("mb_save").setAttribute('data-fileid', id);
    createCalendar("mi_edit_expiry", expiry);

    if (unlimitedown) {
        document.getElementById("mi_edit_down").value = "1";
        document.getElementById("mi_edit_down").disabled = true;
        document.getElementById("mc_download").checked = false;
    } else {
        document.getElementById("mi_edit_down").value = downloads;
        document.getElementById("mi_edit_down").disabled = false;
        document.getElementById("mc_download").checked = true;
    }

    if (unlimitedtime) {
        document.getElementById("mi_edit_expiry").value = unixToLocalInput(add14DaysIfBeforeCurrentTime(expiry));
        document.getElementById("mi_edit_expiry").disabled = true;
        document.getElementById("mc_expiry").checked = false;
    } else {
        document.getElementById("mi_edit_expiry").value = unixToLocalInput(expiry);
        document.getElementById("mi_edit_expiry").disabled = false;
        document.getElementById("mc_expiry").checked = true;
    }

    const pwInput = document.getElementById("mi_edit_pw");
    pwInput.value = "";
    pwInput.placeholder = password ? "(unchanged)" : "";
    pwInput.dataset.hasPassword = password ? "true" : "false";
    pwInput.disabled = !password;
    document.getElementById("mc_password").checked = !!password;

    let selectReplace = document.getElementById("mi_edit_replace");
    if (canReplace) {
        document.getElementById("replaceGroup").style.display = 'flex';
        let files = getAllAvailableFiles();
        for (let i = 0; i < files[0].length; i++) {
            if (files[0][i] == id)
                continue;
            selectReplace.add(new Option(files[1][i] + " (" + files[0][i] + ")", files[0][i]));
        }
    } else {
        document.getElementById("replaceGroup").style.display = 'none';
    }



    new bootstrap.Modal('#modaledit', {}).show();
}


function add14DaysIfBeforeCurrentTime(unixTimestamp) {
    let currentTime = Date.now();
    let timestampInMilliseconds = unixTimestamp * 1000;
    if (timestampInMilliseconds < currentTime) {
        let newTimestamp = currentTime + (14 * 24 * 60 * 60 * 1000);
        return Math.floor(newTimestamp / 1000);
    } else {
        return unixTimestamp;
    }
}

function getAllAvailableFiles() {
    let ids = [];
    let filenames = [];

    let elements = document.querySelectorAll('[id^="cell-name-"]');
    for (let element of elements) {
        ids.push(element.id.replace("cell-name-", ""));
        filenames.push(element.innerHTML);
    }
    return [ids, filenames];
}


function deleteFile(id) {
    document.getElementById("button-delete-" + id).disabled = true;
    apiFilesDelete(id, 10)
        .then(data => {
            changeRowCount(false, document.getElementById("row-" + id));
            showToastFileDeletion(id);
            notifyWorker({ type: "fileDeleted", id: id });
        })
        .catch(error => {
            alert("Unable to delete file. Details are in the browser console.");
            console.error('Error:', error);
        });
}


function checkBoxChanged(checkBox, correspondingInput) {
    let disable = !checkBox.checked;

    if (disable) {
        document.getElementById(correspondingInput).setAttribute("disabled", "");
    } else {
        document.getElementById(correspondingInput).removeAttribute("disabled");
    }
    if (correspondingInput === "password" && disable) {
        document.getElementById("password").value = "";
    }
}

function parseSseData(data) {
    let eventData;
    try {
        eventData = JSON.parse(data);
    } catch (e) {
        console.error("Failed to parse event data:", e);
        return;
    }
    switch (eventData.event) {
        case "download":
            setNewDownloadCount(eventData.file_id, eventData.download_count, eventData.downloads_remaining);
            return;
        case "uploadStatus":
            parseProgressStatus(eventData);
            return;
        default:
            console.error("Unknown event", eventData);
    }
}

function setNewDownloadCount(id, downloadCount, downloadsRemaining) {
    let downloadCell = document.getElementById("cell-downloads-" + id);
    if (downloadCell != null) {
        downloadCell.innerText = downloadCount;
        downloadCell.classList.add("updatedDownloadCount");
        setTimeout(() => downloadCell.classList.remove("updatedDownloadCount"), 500);
    }
    if (downloadsRemaining != -1) {
        let downloadsRemainingCell = document.getElementById("cell-downloadsRemaining-" + id);
        if (downloadsRemainingCell != null) {
            downloadsRemainingCell.innerText = downloadsRemaining;
            downloadsRemainingCell.classList.add("updatedDownloadCount");
            setTimeout(() => downloadsRemainingCell.classList.remove("updatedDownloadCount"), 500);
        }
    }
}


/**
 * sseWorkerPort holds the active SharedWorker MessagePort so that sseLogout()
 * in admin_ui_allPages.js can send a "close" message before navigating away.
 * Null when running in direct-EventSource fallback mode.
 */
var sseWorkerPort = null;

/**
 * notifyWorker posts a message to the SharedWorker if one is active.
 * The worker will relay it to all other connected tabs.
 * Safe to call in fallback (direct SSE) mode — it's a no-op when the port is null.
 * @param {Object} msg
 */
function notifyWorker(msg) {
    if (sseWorkerPort !== null) {
        sseWorkerPort.postMessage(msg);
    }
}

/**
 * registerChangeHandler
 *
 * Uses a SharedWorker to hold a single SSE connection that is shared across
 * all open tabs. This prevents hitting the browser's per-origin HTTP/1.1
 * connection limit (typically 6), which would otherwise block new tabs from
 * receiving updates when many admin pages are open simultaneously.
 *
 * Falls back to a direct EventSource when SharedWorker is unavailable
 * (e.g. Firefox private-browsing mode, or very old browsers).
 */
function registerChangeHandler() {
    if (typeof SharedWorker !== "undefined") {
        try {
            const worker = new SharedWorker("./js/sse-worker.js");

            worker.port.onmessage = (event) => {
                if (event.data.type === "message") {
                    parseSseData(event.data.data);
                } else if (event.data.type === "error") {
                    console.error("SSE worker connection error:", event.data.detail);
                } else if (event.data.type === "shutdown") {
                    // Another tab logged out — the session is gone for everyone.
                    setTimeout(function() {  
                   	 window.location.href = "./login";
		     }, 1000);
                } else if (event.data.type === "fileAdded") {
                    // Another tab finished an upload or restored a file — add the
                    // row if it isn't already present (guard against duplicate IDs).
                    if (document.getElementById("row-" + sanitizeId(event.data.item.Id)) == null) {
                        addRow(event.data.item);
                    }
                } else if (event.data.type === "fileDeleted") {
                    // Another tab deleted a file — remove the row silently (no toast,
                    // since this tab didn't initiate the deletion).
                    let row = document.getElementById("row-" + sanitizeId(event.data.id));
                    if (row != null) {
                        changeRowCount(false, row);
                    }
                } else if (event.data.type === "log") {
                    const { level, message, detail } = event.data;
                    if (detail) {
                        console[level](message, detail);
                    } else {
                        console[level](message);
                    }
                }
            };

            worker.onerror = (err) => {
                // Worker itself failed to load – fall back to a direct connection.
                console.warn("SharedWorker failed, falling back to direct SSE:", err);
                sseWorkerPort = null;
                _registerDirectSSE();
            };

            worker.port.start();
            sseWorkerPort = worker.port;
            return;
        } catch (e) {
            console.warn("SharedWorker unavailable, falling back to direct SSE:", e);
        }
    }
    _registerDirectSSE();
}

/**
 * _registerDirectSSE
 *
 * Fallback: open an EventSource directly in this tab. Used when SharedWorker
 * is not supported or fails to load. Each tab will hold its own connection,
 * which may hit browser connection limits if many tabs are open.
 */
function _registerDirectSSE() {
    const source = new EventSource("./uploadStatus");
    source.onmessage = (event) => {
        parseSseData(event.data);
    };
    source.onerror = (error) => {
        // Check for net::ERR_HTTP2_PROTOCOL_ERROR 200 (OK) and ignore it
        if (error.target.readyState !== EventSource.CLOSED) {
            source.close();
        }
        console.log("Reconnecting to SSE (direct)...");
        setTimeout(_registerDirectSSE, 5000);
    };
}

var statusItemCount = 0;


function addFileStatus(chunkId, filename) {
    const container = document.createElement('div');
    container.setAttribute('id', `us-container-${chunkId}`);
    container.classList.add('us-container');

    // create filename div
    const filenameDiv = document.createElement('div');
    filenameDiv.classList.add('filename');
    filenameDiv.textContent = filename;
    container.appendChild(filenameDiv);

    // create progress bar container div
    const progressContainerDiv = document.createElement('div');
    progressContainerDiv.classList.add('upload-progress-container');
    progressContainerDiv.setAttribute('id', `us-progress-container-${chunkId}`);

    // create progress bar div
    const progressBarDiv = document.createElement('div');
    progressBarDiv.classList.add('upload-progress-bar');

    // create progress bar progress div
    const progressBarProgressDiv = document.createElement('div');
    progressBarProgressDiv.setAttribute('id', `us-progressbar-${chunkId}`);
    progressBarProgressDiv.classList.add('upload-progress-bar-progress');
    progressBarProgressDiv.style.width = '0%';
    progressBarDiv.appendChild(progressBarProgressDiv);

    // create progress info div
    const progressInfoDiv = document.createElement('div');
    progressInfoDiv.setAttribute('id', `us-progress-info-${chunkId}`);
    progressInfoDiv.classList.add('upload-progress-info');
    progressInfoDiv.textContent = '0%';

    // append progress bar and progress info to progress bar container
    progressContainerDiv.appendChild(progressBarDiv);
    progressContainerDiv.appendChild(progressInfoDiv);

    // append progress bar container to container
    container.appendChild(progressContainerDiv);

    container.setAttribute('data-starttime', Date.now());
    container.setAttribute('data-complete', "false");

    const uploadstatusContainer = document.getElementById("uploadstatus");
    uploadstatusContainer.appendChild(container);
    uploadstatusContainer.style.visibility = "visible";
    statusItemCount++;
}

function removeFileStatus(chunkId) {
    const container = document.getElementById(`us-container-${chunkId}`);
    if (container == null) {
        return;
    }
    container.remove();
    statusItemCount--;
    if (statusItemCount < 1) {
        document.getElementById("uploadstatus").style.visibility = "hidden";
    }
}


function addRow(item) {
    let table = document.getElementById("downloadtable");
    let row = table.insertRow(0);
    item.Id = sanitizeId(item.Id);
    row.id = "row-" + item.Id;
    let cellFilename = row.insertCell(0);
    let cellFileSize = row.insertCell(1);
    let cellRemainingDownloads = row.insertCell(2);
    let cellStoredUntil = row.insertCell(3);
    let cellDownloadCount = row.insertCell(4);
    let cellUrl = row.insertCell(5);
    let cellButtons = row.insertCell(6);

    cellFilename.innerText = item.Name;
    cellFilename.id = "cell-name-" + item.Id;
    cellDownloadCount.id = "cell-downloads-" + item.Id;
    cellFileSize.innerText = item.Size;
    if (item.UnlimitedDownloads) {
        cellRemainingDownloads.innerText = "Unlimited";
    } else {
        cellRemainingDownloads.innerText = item.DownloadsRemaining;
        cellRemainingDownloads.id = "cell-downloadsRemaining-" + item.Id;
    }
    if (item.UnlimitedTime) {
        cellStoredUntil.innerText = "Unlimited";
    } else {
        cellStoredUntil.innerText = formatUnixTimestamp(item.ExpireAt);
    }
    cellDownloadCount.innerText = item.DownloadCount;

    const link = document.createElement('a');
    link.href = item.UrlDownload;
    link.target = '_blank';
    link.style.color = 'inherit';
    link.id = 'url-href-' + item.Id;
    link.textContent = item.Id;

    cellUrl.appendChild(link);

    if (item.IsPasswordProtected === true) {
        const icon = document.createElement('i');
        icon.className = 'bi bi-key';
        icon.title = 'Password protected';
        cellUrl.appendChild(document.createTextNode(' '));
        cellUrl.appendChild(icon);
    }

    cellButtons.appendChild(createButtonGroup(item));


    cellFilename.classList.add('newItem');
    cellFileSize.classList.add('newItem');
    cellRemainingDownloads.classList.add('newItem');
    cellStoredUntil.classList.add('newItem');
    cellDownloadCount.classList.add('newItem');
    cellUrl.classList.add('newItem');
    cellButtons.classList.add('newItem');
    cellFileSize.setAttribute('data-order', item.SizeBytes);

    changeRowCount(true, row);
    return item.Id;
}

function createButtonGroup(item) {
    const groupContainer = document.createElement("div");
    groupContainer.className = "btn-toolbar justify-content-end";
    groupContainer.setAttribute("role", "toolbar");

    const group1 = document.createElement("div");
    group1.className = "btn-group me-2";
    group1.setAttribute("role", "group");

    // === Button: Copy URL ===
    const copyUrlBtn = document.createElement('button');
    copyUrlBtn.type = 'button';
    copyUrlBtn.className = 'copyurl btn btn-outline-light btn-sm';
    copyUrlBtn.dataset.clipboardText = item.UrlDownload;
    copyUrlBtn.id = 'url-button-' + item.Id;
    copyUrlBtn.title = 'Copy URL';

    const copyIcon = document.createElement('i');
    copyIcon.className = 'bi bi-copy';
    copyUrlBtn.appendChild(copyIcon);
    copyUrlBtn.appendChild(document.createTextNode(' URL'));

    copyUrlBtn.addEventListener('click', () => {
        showToast(1000);
    });

    group1.appendChild(copyUrlBtn);

    // Share button
    const btnShare = document.createElement("button");
    btnShare.type = "button";
    btnShare.className = "btn btn-outline-light btn-sm";
    btnShare.title = "Share";
    btnShare.onclick = () => shareUrl(event, item.Id);
    // For some reason bi-share does not always show up, using the svg fixes it 
    btnShare.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi" viewBox="0 0 16 16">
 				 <path d="M13.5 1a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M11 2.5a2.5 2.5 0 1 1 .603 1.628l-6.718 3.12a2.5 2.5 0 0 1 0 1.504l6.718 3.12a2.5 2.5 0 1 1-.488.876l-6.718-3.12a2.5 2.5 0 1 1 0-3.256l6.718-3.12A2.5 2.5 0 0 1 11 2.5m-8.5 4a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3m11 5.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3"/>
			</svg>`;
    group1.appendChild(btnShare);


    // Dropdown toggle 
    const btnDropdown2 = document.createElement("button");
    btnDropdown2.type = "button";
    btnDropdown2.className = "btn btn-outline-light btn-sm dropdown-toggle dropdown-toggle-split";
    btnDropdown2.setAttribute("data-bs-toggle", "dropdown");
    btnDropdown2.setAttribute("aria-expanded", "false");
    btnDropdown2.id = `shareDropdown-${item.Id}`;
    
    group1.appendChild(btnDropdown2);

    const dropdown2 = document.createElement("ul");
    dropdown2.className = "dropdown-menu dropdown-menu-end";
    dropdown2.setAttribute("data-bs-theme", "dark");

    const qrLi = document.createElement("li");
    const qrA = document.createElement("a");
    qrA.className = "dropdown-item";
    qrA.id = `qrcode-${item.Id}`;
    qrA.style.cursor = "pointer";
    qrA.title = "Open QR Code";
    qrA.onclick = () => showQrCode(item.Id);
    qrA.innerHTML = `<i class="bi bi-qr-code"></i> QR Code`;
    qrLi.appendChild(qrA);
    dropdown2.appendChild(qrLi);

    const emailLi = document.createElement("li");
    const emailA = document.createElement("a");
    emailA.className = "dropdown-item";
    emailA.title = "Share via email";
    emailA.id = `email-${item.Id}`;
    emailA.target = "_blank";
    emailA.href = `mailto:?body=${encodeURIComponent(item.UrlDownload)}`;
    emailA.innerHTML = `<i class="bi bi-envelope"></i> Email`;
    emailLi.appendChild(emailA);
    dropdown2.appendChild(emailLi);
    group1.appendChild(dropdown2);

    // Button group for Download/Edit/Delete
    const group2 = document.createElement("div");
    group2.className = "btn-group";
    group2.setAttribute("role", "group");
    
    
    // === Button: Download ===
    const btnDownload = document.createElement('button');
    btnDownload.type = 'button';
    btnDownload.className = 'btn btn-outline-light btn-sm';
    btnDownload.title = 'Download';

    const downloadIcon = document.createElement('i');
    downloadIcon.className = 'bi bi-download';
    btnDownload.appendChild(downloadIcon);

    btnDownload.addEventListener('click', () => {
        downloadFileWithPresign(item.Id);
    });

    group2.appendChild(btnDownload);

    // === Button: Edit ===
    const btnEdit = document.createElement('button');
    btnEdit.type = 'button';
    btnEdit.className = 'btn btn-outline-light btn-sm';
    btnEdit.title = 'Edit';

    const editIcon = document.createElement('i');
    editIcon.className = 'bi bi-pencil';
    btnEdit.appendChild(editIcon);

    btnEdit.addEventListener('click', () => {
        showEditModal(
            item.Name,
            item.Id,
            item.DownloadsRemaining,
            item.ExpireAt,
            item.IsPasswordProtected,
            item.UnlimitedDownloads,
            item.UnlimitedTime,
            canReplaceOwnFiles
        );
    });

    group2.appendChild(btnEdit);

    // === Button: Delete ===
    const btnDelete = document.createElement('button');
    btnDelete.type = 'button';
    btnDelete.className = 'btn btn-outline-danger btn-sm';
    btnDelete.title = 'Delete';
    btnDelete.id = 'button-delete-' + item.Id;

    const deleteIcon = document.createElement('i');
    deleteIcon.className = 'bi bi-trash3';
    btnDelete.appendChild(deleteIcon);

    btnDelete.addEventListener('click', () => {
        deleteFile(item.Id);
    });
    group2.appendChild(btnDelete);

    groupContainer.appendChild(group1);
    groupContainer.appendChild(group2);

    return groupContainer;
}

function sanitizeId(str) {
    return str.replace(/[^a-zA-Z0-9]/g, '');
}

function changeRowCount(add, row) {
    let datatable = new DataTable.Api('#maintable');
    if (rowCount == -1) {
        rowCount = datatable.rows().count();
    }
    if (add) {
        rowCount = rowCount + 1;
        datatable.row.add(row);
    } else {
        rowCount = rowCount - 1;
        row.classList.add("rowDeleting");
        setTimeout(() => {
            datatable.row(row).remove();
            row.remove();
        }, 290);
    }

    let infoEmpty = document.getElementsByClassName("dt-empty")[0];
    if (typeof infoEmpty !== "undefined") {
        infoEmpty.innerText = "Files stored: " + rowCount;
    } else {
        document.getElementsByClassName("dt-info")[0].innerText = "Files stored: " + rowCount;
    }
}


function hideQrCode() {
    document.getElementById("qroverlay").style.display = "none";
    document.getElementById("qrcode").innerHTML = "";
}

// Shows the QR code the server generates for the file's download link
function showQrCode(fileId) {
    const overlay = document.getElementById("qroverlay");
    apiFilesQr(fileId)
        .then(blob => {
            const image = document.createElement("img");
            image.src = URL.createObjectURL(blob);
            image.onload = () => URL.revokeObjectURL(image.src);
            image.width = 200;
            image.height = 200;
            image.alt = "QR code";
            document.getElementById("qrcode").replaceChildren(image);
            overlay.style.display = "block";
        })
        .catch(error => {
            alert("Unable to show QR code. Details are in the browser console.");
            console.error('Error:', error);
        });
    overlay.addEventListener("click", hideQrCode);
}


function showToastFileDeletion(id) {
    let notification = document.getElementById("toastnotificationUndo");
    let filename = document.getElementById("cell-name-" + id).innerText;
    let filenameToast = document.getElementById("toastFilename");
    let button = document.getElementById("toastUndoButton");

    filenameToast.innerText = filename;

    button.dataset.fileid = id;
    hideToast();
    notification.classList.add("show");

    clearTimeout(toastId);
    toastId = setTimeout(() => {
        hideFileToast();
    }, 5000);
}

function hideFileToast() {
    document.getElementById("toastnotificationUndo").classList.remove("show");
}

function handleUndo(button) {
    hideFileToast();
    apiFilesRestore(button.dataset.fileid)
        .then(data => {
            addRow(data.FileInfo);
            notifyWorker({ type: "fileAdded", item: data.FileInfo });
        })
        .catch(error => {
            alert("Unable to restore file. Details are in the browser console.");
            console.error('Error:', error);
        });
}


function shareUrl(event, id) {
    if (!navigator.share) {
         event.stopPropagation();
    	 bootstrap.Dropdown.getOrCreateInstance(document.getElementById(`shareDropdown-${id}`)).toggle();
        return;
    }
    let filename = document.getElementById("cell-name-" + id).innerText;
    let url = document.getElementById("url-href-" + id).getAttribute("href");
    navigator.share({
        title: filename,
        url: url,
    })
}


// This file contains JS code for the User view
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...


function changeUserPermission(userId, permission, buttonId) {

    let indicator = document.getElementById(buttonId);
    if (indicator.classList.contains("perm-processing") || indicator.classList.contains("perm-nochange")) {
        return;
    }
    let wasGranted = indicator.classList.contains("perm-granted");
    indicator.classList.add("perm-processing");
    indicator.classList.remove("perm-granted");
    indicator.classList.remove("perm-notgranted");

    let modifier = "GRANT";
    if (wasGranted) {
        modifier = "REVOKE";
    }

    if (permission == "PERM_REPLACE_OTHER" && !wasGranted) {
        hasNotPermissionReplace = document.getElementById("perm_replace_" + userId).classList.contains("perm-notgranted");
        if (hasNotPermissionReplace) {
            showToast(2000, "Also granting permission to replace own files");
            changeUserPermission(userId, "PERM_REPLACE", "perm_replace_" + userId);
        }
    }
    if (permission == "PERM_REPLACE" && wasGranted) {
        hasPermissionReplaceOthers = document.getElementById("perm_replace_other_" + userId).classList.contains("perm-granted");
        if (hasPermissionReplaceOthers) {
            showToast(2000, "Also revoking permission to replace files of other users");
            changeUserPermission(userId, "PERM_REPLACE_OTHER", "perm_replace_other_" + userId);
        }
    }


    apiUserModify(userId, permission, modifier)
        .then(data => {
            if (wasGranted) {
                indicator.classList.add("perm-notgranted");
            } else {
                indicator.classList.add("perm-granted");
            }
            indicator.classList.remove("perm-processing");
        })
        .catch(error => {
            if (wasGranted) {
                indicator.classList.add("perm-granted");
            } else {
                indicator.classList.add("perm-notgranted");
            }
            indicator.classList.remove("perm-processing");
            alert("Unable to set permission. Details are in the browser console.");
            console.error('Error:', error);
        });
}



function changeRank(userId, newRank, buttonId) {

    let indicator = document.getElementById(buttonId);
    if (indicator.disabled) {
        return;
    }
    indicator.disabled = true;

    apiUserChangeRank(userId, newRank)
        .then(data => {
            location.reload();
        })
        .catch(error => {
            indicator.disabled = false;
            alert("Unable to change rank. Details are in the browser console.");
            console.error('Error:', error);
        });
}



function showDeleteUserModal(userId, userEmail) {
    let checkboxDelete = document.getElementById("checkboxDelete");
    checkboxDelete.checked = false;
    document.getElementById("deleteModalBody").innerText = userEmail;
    bootstrap.Modal.getOrCreateInstance('#deleteModal').show();

    document.getElementById("buttonDelete").onclick = function() {
        apiUserDelete(userId, checkboxDelete.checked)
            .then(data => {
                bootstrap.Modal.getOrCreateInstance('#deleteModal').hide();
                document.getElementById("row-" + userId).classList.add("rowDeleting");
                setTimeout(() => {
                    document.getElementById("row-" + userId).remove();
                }, 290);
            })
            .catch(error => {
                alert("Unable to delete user. Details are in the browser console.");
                console.error('Error:', error);
            });
    };
}


function showAddUserModal() {
    resetModalOnHide('newUserModal');
    bootstrap.Modal.getOrCreateInstance('#newUserModal').show();
}


function showResetPwModal(userid, name) {
    resetModalOnHide('resetPasswordModal');

    document.getElementById("l_userpwreset").innerText = name;
    let button = document.getElementById("resetPasswordButton");
    button.onclick = function() {
        resetPw(userid, document.getElementById("generateRandomPassword").checked);
    };
    bootstrap.Modal.getOrCreateInstance('#resetPasswordModal').show();
}

function resetPw(userid, newPw) {
    let button = document.getElementById("resetPasswordButton");
    document.getElementById("resetPasswordButton").disabled = true;
    apiUserResetPassword(userid, newPw)
        .then(data => {
            if (!newPw) {
                bootstrap.Modal.getOrCreateInstance('#resetPasswordModal').hide();
                showToast(1000, 'Password change requirement set successfully')
                return;
            }
            button.style.display = 'none';
            document.getElementById("cancelPasswordButton").style.display = 'none';
            document.getElementById("formentryReset").style.display = 'none';
            document.getElementById("randomPasswordContainer").style.display = 'block';
            document.getElementById("closeModalResetPw").style.display = 'block';
            document.getElementById("l_returnedPw").innerText = data.password;
            document.getElementById("copypwclip").onclick = function() {
                navigator.clipboard.writeText(data.password);
                showToast(1000, "Password copied to clipboard");
            }
        })
        .catch(error => {
            alert("Unable to reset user password. Details are in the browser console.");
            console.error('Error:', error);
            button.disabled = false;
        });
}


function addNewUser() {
    let button = document.getElementById("mb_addUser");
    button.disabled = true;
    let form = document.getElementById('newUserForm');
    if (!form.checkValidity()) {
        form.classList.add('was-validated');
        button.disabled = false;
    } else {
        let editName = document.getElementById("e_userName");
        apiUserCreate(editName.value.trim())
            .then(data => {
                bootstrap.Modal.getOrCreateInstance('#newUserModal').hide();
                addRowUser(data.id, data.name, data.permissions);
                console.log(data);
            })
            .catch(error => {
                if (error.message == "duplicate") {
                    alert("A user already exists with that name");
                    button.disabled = false;
                } else {
                    alert("Unable to create user. Details are in the browser console.");
                    console.error('Error:', error);
                    button.disabled = false;
                }
            });
    }
}



const PermissionDefinitions = [
    {
        key: "UserPermReplaceUploads",
        bit: 1 << 0,
        icon: "bi bi-recycle",
        title: "Replace own uploads",
        htmlId: userid => `perm_replace_${userid}`,
        apiName: "PERM_REPLACE"
    },
    {
        key: "UserPermListOtherUploads",
        bit: 1 << 1,
        icon: "bi bi-eye",
        title: "List other uploads",
        htmlId: userid => `perm_list_${userid}`,
        apiName: "PERM_LIST"
    },
    {
        key: "UserPermEditOtherUploads",
        bit: 1 << 2,
        icon: "bi bi-pencil",
        title: "Edit other uploads",
        htmlId: userid => `perm_edit_${userid}`,
        apiName: "PERM_EDIT"
    },
    {
        key: "UserPermDeleteOtherUploads",
        bit: 1 << 4,
        icon: "bi bi-trash3",
        title: "Delete other uploads",
        htmlId: userid => `perm_delete_${userid}`,
        apiName: "PERM_DELETE"
    },
    {
        key: "UserPermReplaceOtherUploads",
        bit: 1 << 3,
        icon: "bi bi-arrow-left-right",
        title: "Replace other uploads",
        htmlId: userid => `perm_replace_other_${userid}`,
        apiName: "PERM_REPLACE_OTHER"
    },
    {
        key: "UserPermManageLogs",
        bit: 1 << 5,
        icon: "bi bi-card-list",
        title: "Manage system logs",
        htmlId: userid => `perm_logs_${userid}`,
        apiName: "PERM_LOGS"
    },
    {
        key: "UserPermManageUsers",
        bit: 1 << 7,
        icon: "bi bi-people",
        title: "Manage users",
        htmlId: userid => `perm_users_${userid}`,
        apiName: "PERM_USERS"
    },
    {
        key: "UserPermManageApiKeys",
        bit: 1 << 6,
        icon: "bi bi-sliders2",
        title: "Manage all API keys",
        htmlId: userid => `perm_api_${userid}`,
        apiName: "PERM_API"
    }
];

function hasPermission(userPerm, permissionBit) {
    return (userPerm & permissionBit) !== 0;
}


function addRowUser(userid, name, permissions) {

    userid = sanitizeUserId(userid);

    let table = document.getElementById("usertable");
    let row = table.insertRow(1);
    row.id = "row-" + userid;
    let cellName = row.insertCell(0);
    let cellGroup = row.insertCell(1);
    let cellLastOnline = row.insertCell(2);
    let cellUploads = row.insertCell(3);
    let cellPermissions = row.insertCell(4);
    let cellActions = row.insertCell(5);

    cellName.classList.add("newUser");
    cellGroup.classList.add("newUser");
    cellLastOnline.classList.add("newUser");
    cellUploads.classList.add("newUser");
    cellPermissions.classList.add("newUser");
    cellActions.classList.add("newUser");


    cellName.innerText = name;
    cellGroup.innerText = "User";
    cellLastOnline.innerText = "Never";
    cellUploads.innerText = "0";

    // Create one button group
    const btnGroup = document.createElement("div");
    btnGroup.className = "btn-group";
    btnGroup.setAttribute("role", "group");

    // Password reset button (optional)
    if (isInternalAuth) {
        const btnResetPw = document.createElement("button");
        btnResetPw.id = `pwchange-${userid}`;
        btnResetPw.type = "button";
        btnResetPw.className = "btn btn-outline-light btn-sm";
        btnResetPw.title = "Reset Password";
        btnResetPw.onclick = () => showResetPwModal(userid, name);
        btnResetPw.innerHTML = `<i class="bi bi-key-fill"></i>`;
        btnGroup.appendChild(btnResetPw);
    }

    // Promote button
    const btnPromote = document.createElement("button");
    btnPromote.id = `changeRank_${userid}`;
    btnPromote.type = "button";
    btnPromote.className = "btn btn-outline-light btn-sm";
    btnPromote.title = "Promote User";
    if (isAdmin) {
        btnPromote.onclick = () => changeRank(userid, 'ADMIN', `changeRank_${userid}`);
    } else {
        btnPromote.disabled = true;
    }
    btnPromote.innerHTML = `<i class="bi bi-chevron-double-up"></i>`;
    btnGroup.appendChild(btnPromote);

    // Delete button
    const btnDelete = document.createElement("button");
    btnDelete.id = `delete-${userid}`;
    btnDelete.type = "button";
    btnDelete.className = "btn btn-outline-danger btn-sm";
    btnDelete.title = "Delete";
    btnDelete.onclick = () => showDeleteUserModal(userid, name);
    btnDelete.innerHTML = `<i class="bi bi-trash3"></i>`;
    btnGroup.appendChild(btnDelete);

    // Insert button group into cellActions
    cellActions.innerHTML = '';
    cellActions.appendChild(btnGroup);

    // Permissions
     cellPermissions.innerHTML = PermissionDefinitions.map(perm => {
        let granted = "perm-notgranted";
        if (hasPermission(permissions, perm.bit)) {
            granted = "perm-granted";
        }
        const id = perm.htmlId(userid);
        let nochangeClass = "";
        if (!hasPermission(userPermissions, perm.bit)) {
            nochangeClass = "perm-nochange";
        }
        
        

        return `
        <i id="${id}"
           class="${perm.icon} ${granted} ${nochangeClass}"
           title="${perm.title}"
           onclick='changeUserPermission(${userid}, "${perm.apiName}", "${id}")'>
        </i>`;
    }).join("");

    setTimeout(() => {

        cellName.classList.remove("newUser");
        cellGroup.classList.remove("newUser");
        cellLastOnline.classList.remove("newUser");
        cellUploads.classList.remove("newUser");
        cellPermissions.classList.remove("newUser");
        cellActions.classList.remove("newUser");
    }, 700);
}

function sanitizeUserId(id) {
    const numericId = id.toString().trim();
    if (!/^\d+$/.test(numericId)) {
        throw new Error("Invalid ID: must contain only digits.");
    }
    return numericId;
}
