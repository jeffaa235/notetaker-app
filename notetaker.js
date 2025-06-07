document.addEventListener('DOMContentLoaded', function() {

    function customPrompt(message, defaultvalue = "", dropdownOptions = []) {
        return new Promise((resolve) => {
            // Create the modal dynamically
            const modalHtml = `
        <div class="modal fade" id="customPromptModal" tabindex="-1" aria-hidden="true">
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title">${message}</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
              </div>
              <div class="modal-body">
		<input type="text" autofocus class="form-control mb-3" id="textInput" placeholder="Type something..." value="${defaultvalue}">
                <select class="form-select" id="dropdownMenu">
                ${dropdownOptions.map(option => `<option value="${option}">${option}</option>`).join('')}
                </select>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="cancelBtn">Cancel</button>
                <button type="button" class="btn btn-primary" id="confirmBtn">OK</button>
              </div>
            </div>
          </div>
        </div>
      `;

            // Append the modal to the body
            document.body.insertAdjacentHTML('beforeend', modalHtml);

            // Initialize the modal
            const modalElement = document.getElementById('customPromptModal');
            const modal = new bootstrap.Modal(modalElement);

            // Get references to elements
            const textInput = modalElement.querySelector('#textInput');
            const dropdownMenu = modalElement.querySelector('#dropdownMenu');
            const confirmBtn = modalElement.querySelector('#confirmBtn');
            const cancelBtn = modalElement.querySelector('#cancelBtn');


            if (dropdownOptions.length === 0) {

                dropdownMenu.style.display = 'none';
            }

            // Handle "OK" button click
            confirmBtn.addEventListener('click', () => {
                const userInput = textInput.value.trim();
                const dropdownValue = dropdownMenu.value;
                if (userInput && dropdownValue) {
                    resolve({
                        text: userInput,
                        option: dropdownValue
                    });
                } else if (userInput) {
                    resolve(userInput);
                } else {
                    alert('Please enter some text.');
                }
                modal.hide();
            });

            // Handle "Cancel" button click
            cancelBtn.addEventListener('click', () => {
                resolve(null); // Resolve with null if canceled
                modal.hide();
            });

            // Clean up the modal after it is hidden
            modalElement.addEventListener('hidden.bs.modal', () => {
                modalElement.remove();
            });

            textInput.addEventListener('keypress', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault(); // Prevent any default behavior (e.g., form submission)
                    confirmBtn.click(); // Trigger the "OK" button click
                }
            });

            // Show the modal
            modal.show();
			textInput.focus();
			// Listen for when the modal is fully shown
			modalElement.addEventListener('shown.bs.modal', function () {
				textInput.focus();
			});        
		});
    }

    /**
     * Custom alert function using Bootstrap modal
     * @param {string} message - The message to display in the alert
     * @returns {Promise<void>} - Resolves when the modal is closed
     */
    function customAlert(message) {
        return new Promise((resolve) => {
            // Check if the modal already exists
            let modal = document.getElementById('customAlertModal');
            if (!modal) {
                // Create the modal container
                modal = document.createElement('div');
                modal.id = 'customAlertModal';
                modal.className = 'modal fade';
                modal.setAttribute('tabindex', '-1');
                modal.setAttribute('aria-hidden', 'true');

                // Add modal structure
                modal.innerHTML = `
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Alert</h5>
                        </div>
                        <div class="modal-body">
                            <p id="customAlertMessage">Default message</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" data-bs-dismiss="modal">OK</button>
                        </div>
                    </div>
                </div>
            `;

                // Append the modal to the body
                document.body.appendChild(modal);
            }

            // Set the message in the modal body
            const modalMessage = modal.querySelector('#customAlertMessage');
            modalMessage.textContent = message;

            // Show the modal
            const bsModal = new bootstrap.Modal(modal, {
                backdrop: 'static', // Prevent closing by clicking outside
                keyboard: true // Allow closing by pressing the Escape key
            });

            // Resolve the promise when the modal is hidden
            modal.addEventListener('hidden.bs.modal', () => resolve());

            // Show the modal
            bsModal.show();
        });
    }

    function customMultiPrompt(title, fields) {
        return new Promise((resolve) => {
            // Create the modal dynamically
            const modalHtml = `
        <div class="modal fade" id="customMultiPromptModal" tabindex="-1" aria-hidden="true">
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title">${title}</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
              </div>
              <div class="modal-body" id="multiPromptBody">
                <!-- Fields will be dynamically inserted here -->
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="cancelBtn">Cancel</button>
                <button type="button" class="btn btn-primary" id="confirmBtn">OK</button>
              </div>
            </div>
          </div>
        </div>
      `;

            // Append the modal to the body
            document.body.insertAdjacentHTML('beforeend', modalHtml);

            // Initialize the modal
            const modalElement = document.getElementById('customMultiPromptModal');
            const modal = new bootstrap.Modal(modalElement);

            // Get references to elements
            const modalBody = modalElement.querySelector('#multiPromptBody');
            const confirmBtn = modalElement.querySelector('#confirmBtn');
            const cancelBtn = modalElement.querySelector('#cancelBtn');

            // Dynamically create input fields based on the 'fields' array
            fields.forEach(field => {
                const {
                    name,
                    prompt,
                    type = "text",
                    options = []
                } = field;

                // Create a container for the field
                const fieldContainer = document.createElement('div');
                fieldContainer.classList.add('mb-3');

                // Add a label for the field
                const label = document.createElement('label');
                label.classList.add('form-label');
                label.textContent = prompt;
                fieldContainer.appendChild(label);

                if (type === "select") {
                    // If the field is a dropdown
                    const select = document.createElement('select');
                    select.classList.add('form-select');
                    select.setAttribute('data-name', name);

                    // Add options to the dropdown
                    options.forEach(option => {
                        const optionElement = document.createElement('option');
                        optionElement.value = option;
                        optionElement.textContent = option;
                        select.appendChild(optionElement);
                    });

                    fieldContainer.appendChild(select);
                } else {
                    // If the field is an input (text, number, password, etc.)
                    const input = document.createElement('input');
                    input.type = type; // Supports "text", "number", "password", etc.
                    input.classList.add('form-control');
                    input.placeholder = `Enter ${name}`;
                    input.setAttribute('data-name', name);
                    fieldContainer.appendChild(input);
                }

                // Append the field container to the modal body
                modalBody.appendChild(fieldContainer);
            });

            // Handle "OK" button click
            confirmBtn.addEventListener('click', () => {
                const response = {};

                // Collect user input for each field
                fields.forEach(({
                    name
                }) => {
                    const fieldElement = modalBody.querySelector(`[data-name="${name}"]`);
                    if (fieldElement.tagName === "SELECT") {
                        response[name] = fieldElement.value; // Dropdown value
                    } else {
                        response[name] = fieldElement.value.trim(); // Text/password/number input value
                    }
                });

                // Validate that all fields have been filled
                const allFieldsFilled = Object.values(response).every(value => value !== "");
                if (!allFieldsFilled) {
                    alert("Please fill in all fields.");
                    return;
                }

                resolve(response); // Resolve with the collected responses
                modal.hide();
            });

            // Handle "Cancel" button click
            cancelBtn.addEventListener('click', () => {
                resolve(null); // Resolve with null if canceled
                modal.hide();
            });

            // Clean up the modal after it is hidden
            modalElement.addEventListener('hidden.bs.modal', () => {
                modalElement.remove();
            });

            // Show the modal
            modal.show();
        });
    }

    function customConfirm(message) {
        // Create a unique ID for the modal to avoid conflicts
        const modalId = `customConfirmModal-${Date.now()}`;

        // Create the modal HTML structure dynamically
        const modalHTML = `
    <div id="${modalId}" class="modal fade" tabindex="-1" role="dialog">
      <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Confirmation</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <p>${message}</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary confirm-btn">OK</button>
          </div>
        </div>
      </div>
    </div>
  `;

        // Append the modal to the body
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Initialize the Bootstrap modal
        const modalElement = document.getElementById(modalId);
        const modal = new bootstrap.Modal(modalElement, {
            backdrop: 'static', // Prevent closing by clicking outside
            keyboard: false, // Prevent closing by pressing ESC
        });

        // Show the modal
        modal.show();

        // Return a Promise that resolves based on user action
        return new Promise((resolve) => {
            // Add event listeners for the buttons
            const confirmButton = modalElement.querySelector('.confirm-btn');
            const cancelButton = modalElement.querySelector('.btn-secondary');

            const handleConfirm = () => {
                resolve(true); // Resolve with true when "OK" is clicked
                cleanup();
            };

            const handleCancel = () => {
                resolve(false); // Resolve with false when "Cancel" is clicked
                cleanup();
            };

            confirmButton.addEventListener('click', handleConfirm);
            cancelButton.addEventListener('click', handleCancel);

            // Cleanup function to remove the modal and event listeners
            function cleanup() {
                modal.hide(); // Hide the modal
                modalElement.addEventListener('hidden.bs.modal', () => {
                    modalElement.remove(); // Remove the modal from the DOM
                }, {
                    once: true
                });

                // Remove event listeners to prevent memory leaks
                confirmButton.removeEventListener('click', handleConfirm);
                cancelButton.removeEventListener('click', handleCancel);
            }
        });
    }

    function getCurrentNoteUid() {
        return sessionStorage.getItem("currentNoteUid");
    }

    class FilesManager {
        constructor() {
            this.storageKey = 'filesList';
        }

        // Retrieve all files from localStorage
        getAllFiles() {
            return JSON.parse(localStorage.getItem(this.storageKey)) || [];
        }

        // Save the updated files list to localStorage
        saveFilesList(files) {
            localStorage.setItem(this.storageKey, JSON.stringify(files));
        }

        // Add a new file to the list
        createNewFile() {
            const newFile = {
                filename: "New File ",
                uuid: self.crypto.randomUUID(),
                created: new Date().toISOString(),
                encrypted: false,
                hash: "",
                verifypasswordhash: "",
                saved: new Date().toISOString(),
                savetype: "browser"
            };

            const files = this.getAllFiles();
            files.push(newFile);
            this.saveFilesList(files);
            this.refreshPage(); // Optional: refresh the page after creating a new file
        }

        // TODO please no async
        // TODO please do not async

        async loadFile(file) {
            // const newFile = {
            // filename: "New File",
            // uuid: self.crypto.randomUUID(),
            // created: new Date().toISOString(),
            // encrypted: false,
            // hash: "",
            // verifypasswordhash: "",
            // saved: new Date().toISOString(),
            // savetype: "browser"
            // };

            function loadF(file) {
                return new Promise((resolve, reject) => {
                    // Check if a valid file is provided

                    if (!file || !(file instanceof File)) {
                        console.error("Invalid file provided.");
                        reject(new Error("Invalid file."));
                        return;
                    }

                    // Create a FileReader to read the file content
                    const reader = new FileReader();
                    // Create an object to store file metadata
                    // const fileInfo = {
                    // filename: file.name, // Original file name
                    // uuid: uuid,          // Unique identifier for the file
                    // };

                    const newFile = {
                        filename: file.name,
                        uuid: self.crypto.randomUUID(),
                        created: new Date().toISOString(),
                        encrypted: false,
                        hash: "",
                        verifypasswordhash: "",
                        saved: new Date().toISOString(),
                        savetype: "browser"
                    };

                    // When the file is successfully read
                    reader.onload = (event) => {
                        const fileContent = event.target.result; // Get the file content
                        try {
                            // Save the file content in localStorage using the UUID as the key
                            localStorage.setItem(newFile.uuid, fileContent);

                            // Resolve the promise with the file info object
                            resolve(newFile);
                        } catch (error) {
                            console.error("Error saving file to localStorage:", error);
                            reject(error);
                        }
                    };

                    // Handle errors during file reading
                    reader.onerror = (error) => {
                        console.error("Error reading file:", error);
                        reject(error);
                    };

                    // Read the file content as text
                    reader.readAsText(file);
                });
            }

            const fileInfo = await loadF(file);
            const files = this.getAllFiles();
            if (fileInfo) {
                // files.push(newFile);
                // this.saveFilesList(files);
                this.pushFile(fileInfo);
                this.refreshPage(); // Optional: refresh the page after creating a new file

            }
        }

        // Delete a file by UUID
        deleteFile(uuid) {
            let files = this.getAllFiles();
            files = files.filter(file => file.uuid !== uuid);
            this.saveFilesList(files);
        }

        // Update a file by UUID
        updateFile(uuid, updatedData) {
            const files = this.getAllFiles();
            const index = files.findIndex(file => file.uuid === uuid);
            if (index !== -1) {
                files[index] = {
                    ...files[index],
                    ...updatedData
                };
                this.saveFilesList(files);
            }
        }


        // Add a new file to the filesList
        pushFile(newFile) {
            const files = this.getAllFiles(); // Get existing files
            files.push(newFile); // Add the new file
            this.saveFilesList(files); // Save updated filesList back to localStorage
        }

        getFile(uuid) {
            const files = this.getAllFiles(); // Retrieve all files
            return files.find(file => file.uuid === uuid) || null; // Find the file with the matching uuid, or return null if not found
        }

        // Refresh the page (or any UI-related logic)
        refreshPage() {
            function fireReloadViewEvent() {
                // Create a new custom event named "ReloadView"
                const reloadViewEvent = new CustomEvent("ReloadView", {
                    detail: {
                        message: "ReloadView event triggered!"
                    } // Optional: Add custom data
                });

                // Dispatch the event on the eventTarget
                document.dispatchEvent(reloadViewEvent);
            }
            fireReloadViewEvent();

            // Example: trigger a custom event or refresh UI elements
            //document.dispatchEvent(new Event('DOMContentLoaded'));
        }
    }

    let filesManager = new FilesManager();

    class CryptoManager {
        constructor() {
            //this.filesList = (() => filesManager.getAllFiles())();
            this.predefinedSalt = "0000"; // Set your predefined salt value here
        }

        get filesList() {
            return filesManager.getAllFiles();
        }

        // Function to generate a SHA-512 hash
        async generateHash(password, salt = "") {
            const encoder = new TextEncoder();
            const data = encoder.encode(salt + password);
            const hash = await crypto.subtle.digest('SHA-512', data);
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Function to derive a key from the password
        async deriveKey(password, salt) {
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                encoder.encode(password), {
                    name: "PBKDF2"
                },
                false,
                ["deriveKey"]
            );

            return crypto.subtle.deriveKey({
                    name: "PBKDF2",
                    salt: encoder.encode(salt),
                    iterations: 100000,
                    hash: "SHA-512"
                },
                keyMaterial, {
                    name: "AES-CBC",
                    length: 128
                },
                false,
                ["encrypt", "decrypt"]
            );
        }

        // Function to encrypt the note content
        async encryptNoteContent(content, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
            const key = await this.deriveKey(password, saltHex);
            const encoder = new TextEncoder();
            const encryptedContent = await crypto.subtle.encrypt({
                    name: "AES-CBC",
                    iv: salt
                },
                key,
                encoder.encode(content)
            );

            return {
                encryptedContent: Array.from(new Uint8Array(encryptedContent)).map(b => b.toString(16).padStart(2, '0')).join(''),
                saltHex
            };
        }

        // Function to decrypt the note content
        async decryptNoteContent(encryptedContent, password, saltHex) {
            const key = await this.deriveKey(password, saltHex);
            const decoder = new TextDecoder();
            const encryptedArray = Uint8Array.from(encryptedContent.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            const decryptedContent = await crypto.subtle.decrypt({
                    name: "AES-CBC",
                    iv: Uint8Array.from(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
                },
                key,
                encryptedArray
            );

            return decoder.decode(decryptedContent);
        }

        // Function to save the updated filesList
        saveFilesList(fileslist) {
            //localStorage.setItem("filesList", JSON.stringify(this.filesList));
            this.saveFilesList(fileslist);
        }

        // Function to check if a note is encrypted
        isNoteEncrypted(uuid) {
            const file = this.filesList.find(file => file.uuid === uuid);
            return file ? file.encrypted : false;
        }

        // Function to set note as encrypted
        markNoteEncrypted(uuid) {
            //const file = this.filesList.find(file => file.uuid === uuid);
            filesManager.updateFile(uuid, {
                "encrypted": true
            });
            //this.saveFilesList();
            return true;
        }

        // Function to verify the password using the predefined salt
        async verifyPassword(uuid, password) {
            //updateFilesList();
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file) {
                const verifypasswordhash = await this.generateHash(password, this.predefinedSalt);
                return verifypasswordhash === file.verifypasswordhash;
            } else {
                throw new Error('File not found');
            }
        }

        // Function to verify the default password using the predefined salt
        async verifyDefaultPassword(uuid) {
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file) {
				const verifypasswordhash = await this.generateHash(this.getDefaultPassword(), this.predefinedSalt);
				return verifypasswordhash === file.verifypasswordhash;
            } else {
				throw new Error('File not found');
            }
        }

        async savePassword(uuid, plainpassword) {
            if (!plainpassword) {
                console.error("No password found");
            }
            try {
                // Generate the hash for the plainpassword
                const passwordHash = await this.generateHash(plainpassword, "1111");

                // Save the hash into sessionStorage with the uuid as the key
                sessionStorage.setItem(`password_of_${uuid}`, passwordHash);
                //sessionStorage.setItem(`password_of_all`, passwordHash);

                console.log('Password hash saved successfully!');

                return passwordHash;
            } catch (error) {
                console.error('Error saving password hash:', error);
            }
        }

        async saveDefaultPassword(plainpassword) {
            if (!plainpassword) {
                console.error("No password found");
            }
            try {
                // Generate the hash for the plainpassword
                const passwordHash = await this.generateHash(plainpassword, "1111");

                // Save the hash into sessionStorage with the uuid as the key
                //sessionStorage.setItem(`password_of_${uuid}`, passwordHash);
                sessionStorage.setItem("password_of_all", passwordHash);

                const defaultpasswordhash = await this.generateHash(this.getDefaultPassword(), this.predefinedSalt);
                console.log("saveDefaultPassword():", defaultpasswordhash);

                localStorage.setItem("defaultpasswordhash", defaultpasswordhash);

                console.log('saveDefaultPassword(): Password hash saved successfully!');

                return passwordHash;
            } catch (error) {
                console.error('Error saving password hash:', error);
            }
        }


        // Function to prompt for password and encrypt the note
        async encryptFile(uuid, password) {
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file) {
                const content = localStorage.getItem(uuid);
                const {
                    encryptedContent,
                    saltHex
                } = await this.encryptNoteContent(content, password);
                localStorage.setItem(uuid, encryptedContent);
                //file.hash = saltHex;
                const verifypasswordhash = await this.generateHash(password, this.predefinedSalt);
                //file.encrypted = true;
                filesManager.updateFile(uuid, {
                    "hash": saltHex,
                    "verifypasswordhash": verifypasswordhash,
                    "encrypted": true
                });
                //this.saveFilesList();
            } else {
                throw new Error('File not found');
            }
        }

        // Function to prompt for password and decrypt the note
        async decryptFile(uuid, password) {
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file) {
                const encryptedContent = localStorage.getItem(uuid);
                const saltHex = file.hash;
                const decryptedContent = await this.decryptNoteContent(encryptedContent, password, saltHex);
                //return;
                return decryptedContent;
            } else {
                throw new Error('File not found');
            }
        }

        // Function to encrypt a note for the first time
        async encryptFirstTime(uuid, content, password) {
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file && !file.encrypted) {
                const {
                    encryptedContent,
                    saltHex
                } = await this.encryptNoteContent(content, password);
                localStorage.setItem(uuid, encryptedContent);
                //file.hash = saltHex;
                const verifypasswordhash = await this.generateHash(password, this.predefinedSalt);
                //file.encrypted = true;
                filesManager.updateFile(uuid, {
                    "hash": saltHex,
                    "verifypasswordhash": verifypasswordhash,
                    "encrypted": true
                });
                //this.saveFilesList();
            } else if (!file) {
                // If the file doesn't exist, create a new file entry
                const {
                    encryptedContent,
                    saltHex
                } = await this.encryptNoteContent(content, password);
                //this.filesList.push({
                // filesManager({
                // uuid,
                // hash: saltHex,
                // verifypasswordhash: await this.generateHash(password, this.predefinedSalt),
                // encrypted: true
                // });
                const verifypasswordhash = await this.generateHash(password, this.predefinedSalt);
                filesManager.pushFile({
                    uuid,
                    hash: saltHex,
                    verifypasswordhash,
                    encrypted: true
                });
                localStorage.setItem(uuid, encryptedContent);
                //this.saveFilesList();
            } else {
                throw new Error('Note is already encrypted');
            }
        }

        // Function to remove encryption and restore decrypted text
        async removeEncryption(uuid, password) {
            const file = this.filesList.find(file => file.uuid === uuid);
            if (file && file.encrypted) {
                const encryptedContent = localStorage.getItem(uuid);
                const saltHex = file.hash;
                const decryptedContent = await this.decryptNoteContent(encryptedContent, password, saltHex);

                // Restore the decrypted content back into localStorage
                localStorage.setItem(uuid, decryptedContent);

                // Update file properties
                // file.encrypted = false;
                // file.hash = '';
                // file.verifypasswordhash = '';
                filesManager.updateFile(uuid, {
                    "encrypted": false,
                    "hash": "",
                    "verifypasswordhash": ""
                });

                // clean up sessionStorage
                sessionStorage.setItem(`password${uuid}`, "");

                //this.saveFilesList();
            } else {
                throw new Error('File not found or not encrypted');
            }
        }

        // async changePasswordAll(oldPassword, newPassword) {
        // const filesAll = this.filesList;
        // for (const file of filesAll) {
        // if (file && file.encrypted) {
        // const newPasswordHash = await this.generateHash(newPassword, this.predefinedSalt);
        // filesManager.updateFile(file.uuid, {
        // "verifypasswordhash": newPasswordHash,
        // "encrypted": false
        // });
        // file.verifypasswordhash = newPasswordHash;
        // file.encrypted = false;
        // let content = "";
        // try {
        // const content = await this.decryptFile(file.uuid, oldPassword);
        // await this.removeEncryption(uuid, oldPassword);
        // await this.encryptFirstTime(file.uuid, content, newPassword);
        // return true;
        // } catch (e) {
        // console.error("Error while changing password", e);
        // }
        // }
        // });
        // }

        async changePasswordAll(oldPassword, newPassword) {
            const filesAll = this.filesList;
            const rollbackTasks = []; // To store tasks for rollback

            //oldPassword = await this.generateHash(oldPassword, "1111");
            //newPassword = await this.generateHash(newPassword, "1111"); // no need is already new

            for (const file of filesAll) {
                if (file && file.encrypted) {
                    const newPasswordHash = await this.generateHash(newPassword, this.predefinedSalt);
                    let originalContent = ""; // To store the file's original decrypted content

                    try {
                        // Decrypt file with old password
                        originalContent = await this.decryptFile(file.uuid, oldPassword);


                        // Update file properties
                        filesManager.updateFile(file.uuid, {
                            "verifypasswordhash": newPasswordHash,
                            "encrypted": false
                        });

                        // Add rollback task to restore the file's original state
                        rollbackTasks.push(async () => {
                            const originalPasswordHash = await this.generateHash(oldPassword, this.predefinedSalt);
                            filesManager.updateFile(file.uuid, {
                                "verifypasswordhash": originalPasswordHash,
                                "encrypted": false
                            });

                            // Re-encrypt the file with the old password
                            await this.encryptFirstTime(file.uuid, originalContent, oldPassword);
                        });

                        // Re-encrypt file with the new password
                        await this.encryptFirstTime(file.uuid, originalContent, newPassword);

                    } catch (e) {
                        console.error("Error while changing password", e);

                        // Perform rollback for all processed files
                        for (const task of rollbackTasks.reverse()) {
                            try {
                                await task(); // Execute each rollback task
                            } catch (rollbackError) {
                                console.error("Rollback error", rollbackError);
                            }
                        }
                        return false; // Indicate failure
                    }
                }
            }
            return true; // Indicate success
        }



        async changePassword(uuid, oldPassword, newPassword) {
            const file = this.filesList.find(file => file.uuid === uuid);
            oldPassword = await this.generateHash(oldPassword, "1111");
            newPassword = await this.generateHash(newPassword, "1111");
            if (file && file.encrypted) {
                const newPasswordHash = await this.generateHash(newPassword, this.predefinedSalt);
                filesManager.updateFile(uuid, {
                    "verifypasswordhash": newPasswordHash,
                    "encrypted": false
                });
                // file.verifypasswordhash = newPasswordHash;
                // file.encrypted = false;
                try {
                    const content = await this.decryptFile(uuid, oldPassword);
                    //await this.removeEncryption(uuid, oldPassword);
                    await this.encryptFirstTime(uuid, content, newPassword);
                    return true;
                } catch (e) {
                    console.error("Error while changing password", e);
                }
            } else {
                throw new Error('File not found');
            }
        }

        async getPasswords() {

        }

        getDefaultPassword() {
            //const password_of_all = sessionStorage.getItem("password_of_all");
            const default_password = sessionStorage.getItem("password_of_all");
            if (!default_password) {
                console.error("No default password");
                return null;
            }
            return default_password;
        }

        async checkDefaultPassword(password) {
            const default_password = await this.generateHash(password, "1111");
            const verifypasswordhash = await this.generateHash(default_password, this.predefinedSalt);

            //console.log(localStorage.getItem("defaultpasswordhash"), verifypasswordhash);
            return verifypasswordhash === localStorage.getItem("defaultpasswordhash");
        }

        async clearAllPassword() {
            sessionStorage.setItem("password_of_all", "");
            localStorage.setItem("defaultpasswordhash", "");
            return true;
        }
    }



    // Retrieve files from localStorage
    //let files = JSON.parse(localStorage.getItem('filesList')) || [];
    // important crypto manager object
    let cryptoManager = new CryptoManager();
    cryptoManager.predefinedSalt = "0000";

    // Sort files by last saved time
    filesManager.getAllFiles().sort((a, b) => new Date(b.saved) - new Date(a.saved));

    // prompt password
    async function promptPassword(uuid = getCurrentNoteUid(), newPassword = false) {
        let password_of_all = await cryptoManager.getDefaultPassword();
        if (password_of_all && newPassword) {
            const defaultconfirmation = await customConfirm("Use saved password?");
            if (defaultconfirmation) {
                return password_of_all;
            } else {
                await customAlert("Not using default password. Please clear or change password.");
                return null;
            }
        }
        let isPasswordValid = await cryptoManager.verifyDefaultPassword(uuid);

        while (!isPasswordValid) {
            sessionStorage.setItem("promptingpassword", true);
            const plainpassword = prompt("Enter password:");
            if (plainpassword === null) {
                await customAlert("You have canceled the operation. You will not be able to view the file.");
                return null;
            }

            password_of_all = await cryptoManager.saveDefaultPassword(plainpassword);

            isPasswordValid = await cryptoManager.verifyDefaultPassword(uuid);
            if (!isPasswordValid) {
                console.log("invalid");
            }
            if (newPassword) {
                console.log("SET new password");
				sessionStorage.setItem("promptingpassword", false);
                return password_of_all;
            }
        }		
		
		sessionStorage.setItem("promptingpassword", false);

        return password_of_all;
    }

    async function promptNewPassword(uuid = getCurrentNoteUid()) {
        const confirmation = await customConfirm("Change password of all notes?");
        if (!confirmation) {
            await customAlert("Cancelling new password");
            return null;
        }
        if (!cryptoManager.isNoteEncrypted(uuid)) {
            // await customAlert("Note is not encrypted, cannot enter new password");
            // return null;
        }

        // TODO
        sessionStorage.setItem("promptingpassword", true);

        const oldPasswordPlain = prompt("Enter old password for confirmation:");
        if (oldPasswordPlain) {
            const oldPasswordIsValid = await cryptoManager.checkDefaultPassword(oldPasswordPlain);
            if (!oldPasswordIsValid) {
                await customAlert("Invalid old password, cannot change password");
                return null;
            }
        }
        const oldPassword = await cryptoManager.getDefaultPassword();

        sessionStorage.setItem("promptingpassword", true);

        const newPasswordPlain = prompt("Enter new password:");
        if (newPasswordPlain === null) {
            await customAlert("No password entered, cancelling new password");
            return null;
        }
        const password_of_all = await cryptoManager.saveDefaultPassword(newPasswordPlain);
        // sessionStorage.setItem(`password_of_uuid${uuid}`, password_of_uuid);
		sessionStorage.setItem("promptingpassword", false);

        return [oldPassword, password_of_all];
    }


    // Function of refresh
    function refreshEntirePage() {
        console.log("Entire page refreshed! Dangerous.");
        document.dispatchEvent(new Event('DOMContentLoaded'));
        //fireReloadViewEvent();
    }

    function fireReloadViewEvent() {
        // Create a new custom event named "ReloadView"
        const reloadViewEvent = new CustomEvent("ReloadView", {
            detail: {
                message: "ReloadView event triggered!"
            } // Optional: Add custom data
        });

        // Dispatch the event on the eventTarget
        document.dispatchEvent(reloadViewEvent);
    }


    // Function of file object

    // Placeholder functions for updating and deleting file details in your data structure
    function updateFileObject(uuid, details) {
        // Update file details in your data structure
        // Get the file list from localStorage
        //const fileList = JSON.parse(localStorage.getItem("filesList")) || [];
        // const fileList = files;

        // Find the file with the matching uuid
        // const fileIndex = fileList.findIndex(file => file.uuid === uuid);
        // if (fileIndex === -1) {
        // console.log("updateFileObject(): no file found");
        // return; // If the file is not found, do nothing
        // }

        // Update the file details with the provided details
        // fileList[fileIndex] = {
        // ...fileList[fileIndex],
        // ...details
        // };
        // console.log(fileList[fileIndex]);

        // Save the updated file list back to localStorage
        // localStorage.setItem("filesList", JSON.stringify(fileList));

        return filesManager.updateFile(uuid, details);

    }

    function deleteFileObject(uuid) {
        // Delete file details from your data structure
        // Get the file list from localStorage
        // const fileList = files;

        // Filter out the file with the matching uuid
        // const updatedFileList = fileList.filter(file => file.uuid !== uuid);
        // console.log(updatedFileList);
        // Save the updated file list back to localStorage
        // localStorage.setItem("filesList", JSON.stringify(updatedFileList));

        filesManager.deleteFile(uuid);

        fireReloadViewEvent();
    }


    function getFileObject(uuid) {
        // Update file details in your data structure
        // Get the file list from localStorage
        //const fileList = JSON.parse(localStorage.getItem("fileList")) || [];
        // const fileList = files;
        //console.log(fileList);
        // Find the file with the matching uuid
        // const fileIndex = fileList.findIndex(file => file["uuid"] === uuid);
        // if (fileIndex === -1) {
        // console.log("No file found.");
        // return; // If the file is not found, do nothing
        // }

        // return fileList[fileIndex];

        return filesManager.getFile(uuid);
    }


    // Function to load file content into textarea
    function renderTextIntoHTML(text) {
        let converter = new showdown.Converter();
        return converter.makeHtml(text);
    }

    function renderTextareaIntoMarkdown() {
        const textPane = document.querySelector("#textPane");
        const text = textPane.value; // Get the text from the textarea
        const renderedHTML = renderTextIntoHTML(text); // Render the text into HTML
        const div = document.createElement('div'); // Create a new div element
        div.innerHTML = renderedHTML; // Set the inner HTML of the div with the rendered HTML
        div.classList.add('card', 'p-3'); // Add Bootstrap classes to the div for styling
        return div; // Return the div element
    }

    function renderTextareaIntoText() {
        const textPane = document.querySelector("#textPane"); // Select the textarea
        const text = textPane.value; // Get the text content from the textarea
        const div = document.createElement('div'); // Create a new div element
        div.textContent = text; // Set the raw text as the div's textContent
        div.classList.add('card', 'p-3'); // Add Bootstrap classes to style the div
        //div.innerHTML = text.replace(/\n/g, '<br>');
        return div; // Return the div element
    }


    function showTextarea(ta = true) {
        if (ta) {
            const textPane = document.querySelector("#textPane");
            textPane.style.display = 'block';
            const renderedElem = document.querySelector('#renderedPane');
            renderedElem.innerHTML = "";
            renderedElem.style.display = 'none';
            textPane.focus();
            showRenderedText(false);
        } else if (!ta) {
            const textPane = document.querySelector("#textPane");
            textPane.style.display = 'none';

        }
    }

    function showRenderedText(ra = true, vt = sessionStorage.getItem("viewType")) {
        const renderedElem = renderTextareaIntoMarkdown();

        if (ra) {
            const elem = document.querySelector('#renderedPane');
            elem.innerHTML = renderedElem.innerHTML;
			elem.style.whiteSpace = ""; // do not set as "pre"
            elem.style.display = 'block';
            showTextarea(false);

            if (vt === 'text') {
                // Render plain text only
                const renderedElem = renderTextareaIntoText(); // Call the function to render raw text
                elem.innerHTML = ""; // Clear previous content
                elem.textContent = renderedElem.textContent; // Append the plain text element
                elem.style.whiteSpace = "pre";
                elem.style.display = 'block'; // Show the rendered pane
                showTextarea(false); // Hide the textarea if necessary
            }

        } else if (!ra) {
            document.querySelector("#renderedPane").innerHTML = "";
            document.querySelector('#renderedPane').display = 'none';
        }
    }


    async function loadFileIntoTextarea(uuid, edit = false) {
        document.getElementById('textPane').value = "";
        if (!uuid) return;
        let fileContent = localStorage.getItem(uuid);

        if (cryptoManager.isNoteEncrypted(uuid)) {
            const password = await promptPassword(uuid);
            console.log("loadFileIntoTextarea():", password);
            if (!password) return;
            try {
                fileContent = await cryptoManager.decryptFile(uuid, password);
            } catch (error) {
                console.error("Decryption failed:", error);
                await customAlert("Failed to decrypt the file. Please check your password or clear your password and try again.");
                document.getElementById('textPane').value = "Cannot decrypt file."
                showTextarea(false);
                showRenderedText(true);
                return;
            }
        }
		
        if (fileContent) {
            document.getElementById('textPane').value = fileContent;
        } else {
            document.getElementById('textPane').value = "nothing!"
        }
        showTextarea(false);
        showRenderedText(true);
    }

    function updateBigNoteTitle(uuid) {
        document.getElementById("file-title").innerHTML = "Note Title";
        const fileTitle = (getFileObject(uuid))["filename"];
        if (fileTitle) {
            document.getElementById("file-title").innerHTML = fileTitle;
        }
    }

    function updateTabTitle(uuid) {
        const fileTitle = (getFileObject(uuid))["filename"];
        if (fileTitle) {
            document.title = `${fileTitle} | Note Taker`;
        }
    }


    document.getElementById('new-file-button').addEventListener('click', function() {
        createNewFile();
    });

    function createNewFile() {
        const newFile = {
            filename: "New File",
            uuid: self.crypto.randomUUID(),
            created: new Date().toISOString(),
            encrypted: false,
            hash: "",
            verifypasswordhash: "",
            saved: new Date().toISOString(),
            savetype: "browser"
        };

        // Retrieve existing files from localStorage
        let files = JSON.parse(localStorage.getItem('filesList')) || [];

        // Add the new file to the list
        //files.push(newFile);
        filesManager.pushFile(newFile);

        // Save the updated files list back to localStorage
        //localStorage.setItem('filesList', JSON.stringify(files));

        // Refresh the files list in the list group
        //document.dispatchEvent(new Event('DOMContentLoaded'));
        // refresh page
        fireReloadViewEvent();
    }

    async function renameFile(uuid) {

        // Get the new filename from the user
        const oldFilename = await filesManager.getFile(uuid).filename;
        const newFilename = await customPrompt("Enter the new filename:", oldFilename);
        if (!newFilename) return; // If the user cancels, do nothing
        //const oldFilename = await filesManager.getFile(uuid).filename;

        // Update the filename in localStorage or your data structure
        // Assuming you have a function to update the file details
        updateFileObject(uuid, {
            filename: newFilename
        });

        // Update the Note Title if it is the current note
        //updateBigNoteTitle(uuid);
        function showRenameNotification(oldName, newName) {
            // Create the toast container if it doesn't already exist
            let toastContainer = document.querySelector('.toast-container');
            if (!toastContainer) {
                toastContainer = document.createElement('div');
                toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                document.body.appendChild(toastContainer);
            }

            // Create the toast element
            const toast = document.createElement('div');
            toast.id = 'liveToast';
            toast.className = 'toast';
            toast.setAttribute('role', 'alert');
            toast.setAttribute('aria-live', 'assertive');
            toast.setAttribute('aria-atomic', 'true');

            // Create the toast header
            const toastHeader = document.createElement('div');
            toastHeader.className = 'toast-header text-bg-info'; // Use text-bg-info for rename notifications
            const headerText = document.createElement('strong');
            headerText.className = 'me-auto';
            headerText.textContent = 'File Renamed'; // Header text for renaming
            toastHeader.appendChild(headerText);

            // Create the toast body
            const toastBody = document.createElement('div');
            toastBody.className = 'toast-body';
            toastBody.textContent = `File renamed from "${oldName}" to "${newName}".`; // Dynamic message with old and new names

            // Append header and body to the toast
            toast.appendChild(toastHeader);
            toast.appendChild(toastBody);

            // Append the toast to the container
            toastContainer.appendChild(toast);

            // Initialize the toast with Bootstrap's Toast component
            const bsToast = new bootstrap.Toast(toast, {
                autohide: true,
                delay: 5000 // Auto-hide after 5 seconds (longer for readability)
            });

            // Show the toast
            bsToast.show();

            // Optional: Remove the toast from the DOM after it's hidden
            toast.addEventListener('hidden.bs.toast', () => {
                toast.remove();
            });
        }

        showRenameNotification(oldFilename, newFilename);
        fireReloadViewEvent();
    }

    async function deleteFile(uuid) {
        // Confirm deletion with the user
        const filename = await filesManager.getFile(uuid).filename;
        const last_saved = await filesManager.getFile(uuid).saved;
        const time_saved = new Date(last_saved).toLocaleString([], {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
        const confirmDelete = await customConfirm(`Are you sure you want to delete this file? <br>Filename: <strong>${filename}</strong>, last saved at <strong>${time_saved}</strong>`);
        if (!confirmDelete) return;

        // Remove the file from localStorage or your data structure
        // Assuming you have a function to delete the file
        deleteFileObject(uuid);



        const currentNoteUid = getCurrentNoteUid();

        await loadFileIntoTextarea(null);

        updateBigNoteTitle(null);

        fireReloadViewEvent();
    }

    const saveButton = document.querySelector('.save-btn');

    async function saveNote(uuid = getCurrentNoteUid(), undocontent = null, redocontent = null) {
        //const uuid = sessionStorage.getItem("currentNoteUid");
        if (uuid) {
            const filesList = JSON.parse(localStorage.getItem("filesList")) || [];

            function updateSaveTimeInStatusBar(uuid) {
                // Retrieve the list of files and the current note UUID from localStorage
                const filesList = JSON.parse(localStorage.getItem("filesList"));

                if (filesList && uuid) {
                    // Find the current file based on the UUID
                    const currentFile = filesList.find(file => file.uuid === uuid);

                    if (currentFile && currentFile.saved) {
                        // Update the status bar's save timestamp
                        const saveTimestampElement = document.querySelector('.save-timestamp');

                        let currentTime = new Date(currentFile.saved).toLocaleTimeString([], {
                            hour: '2-digit',
                            minute: '2-digit'
                        });

                        function isNotToday(timestamp) {
                            const givenDate = new Date(timestamp);
                            const today = new Date();

                            // Get the current date and the previous day's date
                            //today.setDate(today.getDate() - 1);
                            return (
                                givenDate.getDate() !== today.getDate()
                            );
                        }

                        if (isNotToday(currentFile.saved)) {
                            currentTime = new Date(currentFile.saved).toLocaleDateString();
                        }
                        saveTimestampElement.textContent = currentTime; // Set the timestamp
                    } else {
                        console.error("Save timestamp not found for the current file.");
                    }
                } else {
                    console.error("Files list or current note UID is missing from localStorage.");
                }
            }

            const textPane = document.getElementById("textPane").value;
            const previousValue = localStorage.getItem(uuid);
			let previousValueDecrypted = "";
			if (cryptoManager.isNoteEncrypted(uuid)) {
                const password = await promptPassword(uuid);
				if (!password) {
					return;
				}					
				try {
					previousValueDecrypted = await cryptoManager.decryptFile(uuid, password);
				}
				catch (error) {
					console.error("Decrypt failed:", error);
					await customAlert("Failed to decrypt the original file. Please check your password or try again.");
				}
			}
			
            localStorage.setItem(uuid, textPane);
            if (undocontent) {
                // this is undo
                localStorage.setItem(uuid, undocontent);
            }
            if (redocontent) {
                // this is redo
                localStorage.setItem(uuid, redocontent);
            }

            if (cryptoManager.isNoteEncrypted(uuid)) {
                const password = await promptPassword(uuid);
				if (!password) {
					return;
				}					
				
                try {
                    await cryptoManager.encryptFile(uuid, password);
                    fileSaved = filesManager.getAllFiles().find((file) => file.uuid === uuid);
                    filesManager.updateFile(uuid, {
                        "saved": (new Date()).toISOString()
                    });
                    //fileSaved.saved = (new Date()).toISOString();
                    //localStorage.setItem("filesList", filesList);
                } catch (error) {
                    console.error("Encrypt failed:", error);
                    await customAlert("Failed to encrypt the file. Please check your password or try again.");
                    // Revert to the previous value
                    localStorage.setItem(uuid, previousValue);
                    return;
                }
            }

            // for now, saving to cloud is enabled by default for all notes, no way to disable.
            if (await s3Manager.isSavedToCloud(uuid)) {
                // Additional logic
                await s3Manager.uploadSingleFileUUID(getCurrentNoteUid());
                // sync entire
                await s3Manager.syncLatestEntireLibrary();

                //await s3Manager.updateStatusAndSyncLatest();
            }

            //updateSyncTimeInStatusBar(uuid);

            //updateSaveTimeInStatusBar(uuid);

            function showSaveNotification(currentFilename) {
                // Create the toast container if it doesn't already exist
                let toastContainer = document.querySelector('.toast-container');
                if (!toastContainer) {
                    toastContainer = document.createElement('div');
                    toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                    document.body.appendChild(toastContainer);
                }

                // Create the toast element
                const toast = document.createElement('div');
                toast.id = 'liveToast';
                toast.className = 'toast';
                toast.setAttribute('role', 'alert');
                toast.setAttribute('aria-live', 'assertive');
                toast.setAttribute('aria-atomic', 'true');

                // Create the toast header
                const toastHeader = document.createElement('div');
                toastHeader.className = 'toast-header text-bg-primary';
                const headerText = document.createElement('strong');
                headerText.className = 'me-auto';
                headerText.textContent = 'File Saved';
                toastHeader.appendChild(headerText);

                // Create the toast body
                const toastBody = document.createElement('div');
                toastBody.className = 'toast-body';
                toastBody.textContent = `File ${currentFilename} has been saved!`;

                // Append header and body to the toast
                toast.appendChild(toastHeader);
                toast.appendChild(toastBody);

                // Append the toast to the container
                toastContainer.appendChild(toast);

                // Initialize the toast with Bootstrap's Toast component
                const bsToast = new bootstrap.Toast(toast, {
                    autohide: true,
                });

                // Show the toast
                bsToast.show();
            }

            if (!undocontent && !redocontent) {
                // this is a normal save
                function pushHistoryState(previousState, newState) {
                    // Retrieve the current history stack
                    let historyStack = JSON.parse(sessionStorage.getItem(`${uuid}_historyStack`)) || [];

					// Check if the history stack is empty and store the previous value
					if (historyStack.length === 0) {
						historyStack.push(previousState);
					}
	
                    // Add the new state to the stack
                    historyStack.push(newState);

                    // Limit the history stack to 5 entries
                    if (historyStack.length > 5) {
                        historyStack.shift(); // Remove the oldest entry
                    }

                    // Save the updated stack back to localStorage
                    sessionStorage.setItem(`${uuid}_historyStack`, JSON.stringify(historyStack));
                }

                function pushRedoState(newState) {
                    // Retrieve the current history stack
                    let redoStack = JSON.parse(sessionStorage.getItem(`${uuid}_redoStack`));

                    // Add the new state to the stack
                    redoStack.push(newState);

                    // Limit the history stack to 5 entries
                    if (redoStack.length > 5) {
                        redoStack.shift(); // Remove the oldest entry
                    }

                    // Save the updated stack back to localStorage
                    sessionStorage.setItem(`${uuid}_redoStack`, JSON.stringify(redoStack));
                }

                function clearRedoState() {
                    // Save the cleared stack  to localStorage
                    sessionStorage.setItem(`${uuid}_redoStack`, JSON.stringify([]));
                }
				
				if (cryptoManager.isNoteEncrypted(uuid) && previousValueDecrypted) {
					pushHistoryState(previousValueDecrypted, textPane);
				}
				else {
					pushHistoryState(previousValue, textPane); // plaintext stored in session storage only
				}
				
                clearRedoState();
            }

            const currentFilename = filesManager.getAllFiles().find((file) => file.uuid === uuid).filename;
            showSaveNotification(currentFilename);
            filesManager.updateFile(uuid, {
                "saved": (new Date()).toISOString()
            });

            sessionStorage.setItem("editingNoteUid", "");
            await updateStatusBar(uuid);
            showRenderedText(true);
            showTextarea(false);

        } else {
            console.error("No currentNoteUid found in localStorage.");
        }
    }

    async function autoSaveNote(uuid = sessionStorage.getItem("editingNoteUid")) {
        const currentFilename = filesManager.getAllFiles().find((file) => file.uuid === uuid).filename;

        if (!uuid) return true;

        const confirmation = await customConfirm(`You have unsaved changes for note title ${currentFilename}. Save now?`);
        if (!confirmation) {
            //sessionStorage.setItem("editingNoteUid", "");
            return false;
        }

        function showAutoSaveNotification(currentFilename) {
            // Create the toast container if it doesn't already exist
            let toastContainer = document.querySelector('.toast-container');
            if (!toastContainer) {
                toastContainer = document.createElement('div');
                toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                document.body.appendChild(toastContainer);
            }

            // Create the toast element
            const toast = document.createElement('div');
            toast.id = 'liveToast';
            toast.className = 'toast';
            toast.setAttribute('role', 'alert');
            toast.setAttribute('aria-live', 'assertive');
            toast.setAttribute('aria-atomic', 'true');

            // Create the toast header
            const toastHeader = document.createElement('div');
            toastHeader.className = 'toast-header text-bg-warning';
            const headerText = document.createElement('strong');
            headerText.className = 'me-auto';
            headerText.textContent = 'Autosaved!';
            toastHeader.appendChild(headerText);

            // Create the toast body
            const toastBody = document.createElement('div');
            toastBody.className = 'toast-body';
            toastBody.textContent = `File ${currentFilename} has been autosaved!`;

            // Append header and body to the toast
            toast.appendChild(toastHeader);
            toast.appendChild(toastBody);

            // Append the toast to the container
            toastContainer.appendChild(toast);

            // Initialize the toast with Bootstrap's Toast component
            const bsToast = new bootstrap.Toast(toast, {
                autohide: true,
            });

            // Show the toast
            bsToast.show();
        }

        await saveNote(uuid);
        showAutoSaveNotification(currentFilename);
        return true;
    }


    async function encryptAndSaveNote() {
        //console.log("encryptAndSaveNote(): UUID", uuid);
        const uuid = getCurrentNoteUid();
        if (cryptoManager.isNoteEncrypted(uuid)) {
            //Note is already encrypted
            return;
        }
        if (uuid) {
            const textPane = document.getElementById("textPane").value;
            const content = localStorage.getItem(uuid);

            const password = await promptPassword(uuid, true);

            if (password !== null) {
                if (content !== null) {
                    try {
                        await cryptoManager.encryptFirstTime(uuid, textPane, password);
                    } catch (error) {
                        console.error("Encrypt first time failed for file", error);
                    }
                    // Save the cleared stack  to localStorage
                    //localStorage.setItem(`${uuid}_historyStack`, JSON.stringify([]));
                    // Save the cleared stack  to localStorage
                    //localStorage.setItem(`${uuid}_redoStack`, JSON.stringify([]));

                    showRenderedText(true);
                    showTextarea(false);
                    // double save
                    //await saveNote();
                }
            }
			else {
				// still save if no password just in case
				await customAlert("Cannot encrypt, saving normally.");
			}
			await saveNote();
        } else {
            console.log("encryptAndSaveNote(): Cannot find file with uuid");
        }
    }

    async function removeNoteEncryption() {
        const uuid = getCurrentNoteUid();
        if (uuid) {
            const password = await promptPassword(uuid);

            if (password !== null) {
                await cryptoManager.removeEncryption(uuid, password);
                showRenderedText(true);
                showTextarea(false);
            }
        }
    }

    saveButton.addEventListener('click', async () => {
        await saveNote();
    });

    textPane.addEventListener('keydown', async (event) => {
        if (event.ctrlKey && event.key === 'Enter') {
            await saveNote();
        }
    });

    const editButton = document.querySelector('.edit-btn');

    function editNote() {
        const editing = (document.querySelector("#textPane").style.display === 'block');
        if (!editing) {

            sessionStorage.setItem("editingNoteUid", getCurrentNoteUid());
            showTextarea(true);
            showRenderedText(false);
        } else {
			// ensure autosave prompt is shown and no data is lost
            //sessionStorage.setItem("editingNoteUid", "");
            showTextarea(false);
            showRenderedText(true);
        }
    }

    editButton.addEventListener('click', editNote);


    /*document.querySelector('.encrypt-btn').addEventListener('click', (event) => {
    	encryptNote();
    	event.target.style.display = 'none';
    );

    document.querySelector('.remove-encrypt-btn').addEventListener('click', () => {
    	removeEncryption();
    	event.target.style.display= 'none';
    );
    */
    function updateEncryptionButtons(uuid = getCurrentNoteUid()) {
        const encryptBtn = document.querySelector('.encrypt-btn');
        const removeEncryptBtn = document.querySelector('.remove-encrypt-btn');
        //const encryptionAlgorithmStatusBar = document.querySelector('.encryption-algorithm-text');
        if (cryptoManager.isNoteEncrypted(uuid)) {
            encryptBtn.style.display = 'none';
            removeEncryptBtn.style.display = 'block';
            //encryptionAlgorithmStatusBar.innerText= "AES-CBC 512";
            //updateStatusBar(localStorage.getItem("currentNoteUid"), {"encryption": "AES-CBC 512"});
        } else {
            encryptBtn.style.display = 'block';
            removeEncryptBtn.style.display = 'none';
            //encryptionAlgorithmStatusBar.innerText = "Plaintext";
            //updateStatusBar(localStorage.getItem("currentNoteUid"), {"encryption": "Plaintext"});
        }
    }

    // Attach event listeners
    document.querySelector('.encrypt-btn').addEventListener('click', async function(event) {
        await encryptAndSaveNote();
        //updateEncryptionButtons();
        fireReloadViewEvent();
    });
    document.querySelector('.encrypted-save-option').addEventListener('click', async function(event) {
        await encryptAndSaveNote();
        //updateEncryptionButtons();
        fireReloadViewEvent();
    });

    document.querySelector('.remove-encrypt-btn').addEventListener('click', async function(event) {
        await removeNoteEncryption().then(() => {
            fireReloadViewEvent();
        });
        //updateEncryptionButtons();
    });

    //document.querySelector(".dropdown-item[href='#']").addEventListener("click", (event) => {
    //const clickedOption = event.target.innerText.trim();

    // Simulated file object
    // const file = {
    // filename: "file 2",
    // uuid: "723ff3c0-59c1-4ac4-b73a-1d1d3c9d9455",
    // created: "2025-03-07T09:48:36.348Z",
    // encrypted: false,
    // hash: "",
    // verifypasswordhash: "",
    // saved: "2025-03-07T09:48:36.348Z",
    // savetype: "browser"
    // };

    // if (clickedOption === "Save To Browser") {
    // file.savetype = "browser";
    // console.log(`File savetype changed to: ${file.savetype}`);
    // } else if (clickedOption === "Save To Cloud") {
    // file.savetype = "cloud";
    // console.log(`File savetype changed to: ${file.savetype}`);
    // }

    // Update file object (for demonstration purposes, store in localStorage)
    // localStorage.setItem(file.uuid, JSON.stringify(file));
    // });


    // Initial check
    //updateEncryptionButtons();

    //loadFileIntoTextarea(null);

    //updateStatusBar(null);

    //fireReloadViewEvent();

    // File menu options
    document.querySelector('.new-option').addEventListener('click', newFileFunction);
    document.querySelector('.open-option').addEventListener('click', openFileFunction);
    //document.querySelector('.rename-option').addEventListener('click', renameFileFunction);
    document.querySelector('.save-as-option').addEventListener('click', saveAsFileFunction);
    document.querySelector('.save-to-browser-option').addEventListener('click', saveToBrowserFunction);
    document.querySelector('.save-to-cloud-option').addEventListener('click', saveToCloudFunction);
    //document.querySelector('.delete-option').addEventListener('click', deleteFileFunction);
    document.querySelectorAll('.rename-option').forEach(element => {
        element.addEventListener('click', renameFileFunction);
    });

    document.querySelectorAll('.delete-option').forEach(element => {
        element.addEventListener('click', deleteFileFunction);
    });


    // Edit menu options
    document.querySelector('.edit-current-option').addEventListener('click', editCurrentFunction);
    document.querySelector('.undo-edit-option').addEventListener('click', undoEditFunction);
    document.querySelector('.redo-edit-option').addEventListener('click', redoEditFunction);
    document.querySelectorAll('.change-password-option').forEach((elem) => {
        elem.addEventListener('click', changePasswordFunction);
    });
    document.querySelectorAll('.clear-password-option').forEach((elem) => {
        elem.addEventListener('click', clearPasswordFunction);
    });


    // View menu options
    document.querySelector('.view-markdown-option').addEventListener('click', viewInMarkdownFunction);
    document.querySelector('.view-text-option').addEventListener('click', viewInTextFunction);

    // App menu options
    document.querySelector('.reload-app-option').addEventListener('click', () => {
        window.location.reload();
    });
    document.querySelector('.refresh-app-option').addEventListener('click', () => {
        fireReloadViewEvent();
    });

    // Function Definitions (Empty)
    function newFileFunction() {
        createNewFile();
    }

    async function openFileFunction() {
        // Function to open a file using a Bootstrap modal
        function openFilePrompt() {
            // Create a unique ID for the modal to avoid conflicts
            const modalId = `openFileModal-${Date.now()}`;

            // Create the modal HTML structure dynamically
            const modalHTML = `
    <div id="${modalId}" class="modal fade" tabindex="-1" role="dialog">
      <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Open File</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <p>Select a file to open:</p>
            <input type="file" class="form-control file-input">
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary confirm-btn">Open</button>
          </div>
        </div>
      </div>
    </div>
  `;

            // Append the modal to the body
            document.body.insertAdjacentHTML('beforeend', modalHTML);

            // Initialize the Bootstrap modal
            const modalElement = document.getElementById(modalId);
            const modal = new bootstrap.Modal(modalElement, {
                backdrop: 'static', // Prevent closing by clicking outside
                keyboard: false, // Prevent closing by pressing ESC
            });

            // Show the modal
            modal.show();

            // Return a Promise that resolves based on user action
            return new Promise((resolve) => {
                // Add event listeners for the buttons
                const confirmButton = modalElement.querySelector('.confirm-btn');
                const cancelButton = modalElement.querySelector('.btn-secondary');
                const fileInput = modalElement.querySelector('.file-input');

                const handleConfirm = () => {
                    const file = fileInput.files[0]; // Get the selected file
                    if (file) {
                        resolve(file); // Resolve with the selected file
                    } else {
                        console.warn("No file selected.");
                        resolve(null); // Resolve with null if no file is selected
                    }
                    cleanup();
                };

                const handleCancel = () => {
                    resolve(null); // Resolve with null if canceled
                    cleanup();
                };

                confirmButton.addEventListener('click', handleConfirm);
                cancelButton.addEventListener('click', handleCancel);

                // Cleanup function to remove the modal and event listeners
                function cleanup() {
                    modal.hide(); // Hide the modal
                    modalElement.addEventListener('hidden.bs.modal', () => {
                        modalElement.remove(); // Remove the modal from the DOM
                    }, {
                        once: true
                    });

                    // Remove event listeners to prevent memory leaks
                    confirmButton.removeEventListener('click', handleConfirm);
                    cancelButton.removeEventListener('click', handleCancel);
                }
            });
        }

        const openedfile = await openFilePrompt();
        if (openedfile) {
            console.log("openedfile", openedfile);
            await filesManager.loadFile(openedfile); // Load the file using the filesManager

            await customAlert(`Loaded file ${openedfile.name} successfully.`);
        } else {
            await customAlert("Error loading file");
        }

        // Example usage
        //openFile('example'); // Pass a file name without an extension
    }

    function renameFileFunction() {
        renameFile(getCurrentNoteUid());
    }

    function saveAsFileFunction() {
        saveNote();
    }

    function saveToBrowserFunction() {
        saveNote();
    }

    function saveToCloudFunction() {
        saveNote();
    }

    function deleteFileFunction() {
        deleteFile(getCurrentNoteUid());
    }

    function editCurrentFunction() {
        editNote();
    }

    async function undoEditFunction() {
        const uuid = getCurrentNoteUid();
        let historyStack = JSON.parse(sessionStorage.getItem(`${uuid}_historyStack`)) || [];
        let redoStack = JSON.parse(sessionStorage.getItem(`${uuid}_redoStack`)) || [];

        if (historyStack.length > 1) { // Ensure there's a state to undo to
            // Move the current state to redoStack
            let currentValue = historyStack.pop();
            redoStack.push(currentValue);

            // Save the updated stacks
            sessionStorage.setItem(`${uuid}_historyStack`, JSON.stringify(historyStack));
            sessionStorage.setItem(`${uuid}_redoStack`, JSON.stringify(redoStack));

            // Load the previous value
            let previousValue = historyStack[historyStack.length - 1];
            await saveNote(uuid, previousValue, null);
            fireReloadViewEvent();
        } else {
            await customAlert("Cannot undo.");
        }
    }

    async function redoEditFunction() {
        const uuid = getCurrentNoteUid();
        let historyStack = JSON.parse(sessionStorage.getItem(`${uuid}_historyStack`)) || [];
        let redoStack = JSON.parse(sessionStorage.getItem(`${uuid}_redoStack`)) || [];

        if (redoStack.length > 0) { // Ensure there's a state to redo to
            // Move the top state from redoStack to historyStack
            let redoValue = redoStack.pop();
            historyStack.push(redoValue);

            // Save the updated stacks
            sessionStorage.setItem(`${uuid}_historyStack`, JSON.stringify(historyStack));
            sessionStorage.setItem(`${uuid}_redoStack`, JSON.stringify(redoStack));

            // Load the redone value
            await saveNote(uuid, null, redoValue);
            fireReloadViewEvent();
        } else {
            await customAlert("Cannot redo.");
        }
    }


    async function changePasswordFunction() {
        const [oldPassword, newPassword] = await promptNewPassword();
        //const success = await cryptoManager.changePassword(getCurrentNoteUid(), oldPassword, newPassword);
        const success = await cryptoManager.changePasswordAll(oldPassword, newPassword);
        if (success) {
            await customAlert(`Set new password.`);
        } else {
            await customAlert("Set new password failed, please try again");
        }
    }
    async function clearPasswordFunction() {
        const confirmation = await customConfirm("Forget all saved passwords without removing encryption?");
        if (!confirmation) {
            await customAlert("Clear password cancelled, not proceeding with clearing password.");
			return;
        }
        const success = await cryptoManager.clearAllPassword();
        //const success = await cryptoManager.changePassword(getCurrentNoteUid(), oldPassword, newPassword);
        //const success = await cryptoManager.changePasswordAll(oldPassword, newPassword);
        if (success) {
            await customAlert(`Cleared all passwords.`);
        } else {
            await customAlert(`Cannot clear all passwords, please try agian.`);
        }
    }


    function viewInMarkdownFunction() {
        //viewType = "markdown";
        sessionStorage.setItem("viewType", "markdown");
        fireReloadViewEvent();
    }

    function viewInTextFunction() {
        //viewType = "text";
        sessionStorage.setItem("viewType", "text");
        fireReloadViewEvent();
    }

    class S3Manager {
        constructor(accessKeyId, secretAccessKey, endpoint, bucketName) {
            // Initialize default configuration
            this.accessKeyId = accessKeyId;
            this.secretAccessKey = secretAccessKey;
            this.endpoint = endpoint;
            this.bucketName = bucketName;
            this.enabled = false;

            // Configure AWS S3 client
            this.configureS3Client();
        }

        // Method to dynamically update AWS credentials
        setCredentials(accessKeyId, secretAccessKey) {
            this.accessKeyId = accessKeyId;
            this.secretAccessKey = secretAccessKey;
            this.configureS3Client(); // Reconfigure the S3 client with new credentials
        }

        // Method to dynamically update the endpoint
        setEndpoint(endpoint) {
            this.endpoint = endpoint;
            this.configureS3Client(); // Reconfigure the S3 client with the new endpoint
        }

        // Method to dynamically update the bucket name
        setBucketName(bucketName) {
            this.bucketName = bucketName;
        }

        // Method to enable or disable the S3 manager
        setEnabled(enabled) {
            this.enabled = enabled;
        }

        // Internal method to configure the S3 client
        configureS3Client() {
            AWS.config.update({
                accessKeyId: this.accessKeyId,
                secretAccessKey: this.secretAccessKey
            });

            this.s3 = new AWS.S3({
                endpoint: this.endpoint, // Custom endpoint, e.g., MinIO
                s3ForcePathStyle: true, // Required for MinIO or S3-compatible servers
                signatureVersion: 'v4'
            });
        }

        // Create a bucket
        createBucket() {
            this.s3.createBucket({
                Bucket: this.bucketName
            }, (err, data) => {
                if (err) {
                    console.error("Error creating bucket:", err.message);
                } else {
                    console.log("Bucket created successfully:", data);
                }
            });
        }

        // List objects in the bucket
        listObjects() {
            this.s3.listObjects({
                Bucket: this.bucketName
            }, (err, data) => {
                if (err) {
                    console.error("Error listing objects:", err.message);
                } else {
                    console.log("Objects in bucket:", data.Contents);
                }
            });
        }

        // Upload a single file
        async uploadSingleFile(fileObj) {
            const {
                filename,
                uuid
            } = fileObj;

            // Retrieve file content from localStorage
            const fileContent = localStorage.getItem(uuid);
            if (!fileContent) {
                console.error(`No file content found for UUID: ${uuid}`);
                return;
            }

            // Prepare file as a Blob
            const fileBlob = new Blob([fileContent], {
                type: "application/octet-stream"
            });

            // Set up S3 upload parameters
            const params = {
                Bucket: this.bucketName,
                Key: uuid,
                Body: fileBlob,
                ACL: "public-read" // Optional permissions
            };

            try {
                const result = await this.s3.upload(params).promise();
            } catch (error) {
                console.error(`Upload failed for file: ${filename}`, error);
            }
        }
        // Upload a single file
        async uploadSingleFileUUID(uuid) {
            const fileObj = (JSON.parse(localStorage.getItem("filesList")).find((file) => file.uuid === uuid))
            const {
                filename
            } = fileObj;
            // Retrieve file content from localStorage
            const fileContent = localStorage.getItem(uuid);
            if (!fileContent) {
                console.error(`No file content found for UUID: ${uuid}`);
                return;
            }

            //const fileObj = (JSON.parse(localStorage.getItem("filesList")).find((file) => file.uuid===uuid))

            // Prepare file as a Blob
            const fileBlob = new Blob([fileContent], {
                type: "application/octet-stream"
            });

            // Set up S3 upload parameters
            const params = {
                Bucket: this.bucketName,
                Key: uuid,
                Body: fileBlob,
                ACL: "public-read" // Optional permissions
            };

            try {
                const result = await this.s3.upload(params).promise();
            } catch (error) {
                console.error(`Upload failed for file: ${filename}`, error);
            }
        }

        // Upload all files in filesList
        async uploadFilesList(filesList) {
            for (const fileObj of filesList) {
                await this.uploadSingleFile(fileObj);
            }
        }

        // Upload a simple "hi" file
        async uploadSimpleHi() {
            // Simulate a dummy file object
            const dummyFile = {
                filename: "simple-hi.txt",
                uuid: "dummy-uuid"
            };

            // Store "hi" in localStorage with the dummy UUID
            localStorage.setItem(dummyFile.uuid, "hi");

            // Upload the file
            await this.uploadSingleFile(dummyFile);
        }

        // Upload the entire filesList as one object
        async uploadFilesListAsBlob() {
            const fileContent = localStorage.getItem("filesList");
            if (!fileContent) {
                console.error(`No filesList found in localStorage`);
                return;
            }

            // Prepare the filesList as a Blob
            const fileBlob = new Blob([fileContent], {
                type: "text/plain"
            });

            // Set up S3 upload parameters
            const params = {
                Bucket: this.bucketName,
                Key: "filesList", // Object key for the filesList
                Body: fileBlob,
                ACL: "public-read" // Optional permissions
            };

            try {
                const result = await this.s3.upload(params).promise();
                console.log(`FilesList uploaded successfully: ${result.Location}`);
            } catch (error) {
                console.error("Upload failed for filesList", error);
            }
        }

        async uploadKeyHash() {
            const fileContent = localStorage.getItem("filesList");
            if (!fileContent) {
                console.error(`No filesList found in localStorage`);
                return;
            }

            // Prepare the filesList as a Blob
            const fileBlob = new Blob([fileContent], {
                type: "text/plain"
            });

            // Set up S3 upload parameters
            const params = {
                Bucket: this.bucketName,
                Key: "filesList", // Object key for the filesList
                Body: fileBlob,
                ACL: "public-read" // Optional permissions
            };

            try {
                const result = await this.s3.upload(params).promise();
                console.log(`FilesList uploaded successfully: ${result.Location}`);
            } catch (error) {
                console.error("Upload failed for filesList", error);
            }
        }


        // Download filesList as a Blob from S3
        async downloadFilesListAsBlob() {
            const params = {
                Bucket: this.bucketName,
                Key: `filesList`, // Key of the object to download
                ResponseCacheControl: 'no-cache',
            };

            try {
                const result = await this.s3.getObject(params).promise();
                console.log("FilesList downloaded successfully.");
                // Convert file content to a string and store it in localStorage
                const fileContent = result.Body.toString('utf-8');
                localStorage.setItem("filesList", fileContent);
                //console.log(fileContent);
            } catch (error) {
                console.error("Download failed for filesList", error);
            }
        }

        // Download a single file from S3
        async downloadSingleFileUUID(uuid) {
            const params = {
                Bucket: this.bucketName,
                Key: uuid,
                ResponseCacheControl: 'no-cache',
            };

            try {
                const result = await this.s3.getObject(params).promise();
                // Store the file content in localStorage
                localStorage.setItem(uuid, result.Body.toString('utf-8'));
            } catch (error) {
                console.error(`Download failed for file: ${uuid}`, error);
            }
        }

        // Download all files in filesList
        async downloadFilesList(filesList) {
            for (const fileObj of filesList) {
                await this.downloadSingleFileUUID(fileObj.uuid);
            }
        }

        // Create a new filesList with the newest files
        async latestFilesList() {
            const localFilesList = JSON.parse(localStorage.getItem("filesList")); // Assuming it's stored in localStorage
            // Download the filesList from S3 first
            await this.downloadFilesListAsBlob();

            const downloadedFilesList = JSON.parse(localStorage.getItem("filesList"));

            if (!downloadedFilesList || !localFilesList) {
                console.error("FilesList not found either locally or in the downloaded files.");
                return;
            }

            const updatedFilesList = localFilesList.map(localFile => {
                const matchingFile = downloadedFilesList.find(
                    remoteFile => remoteFile.uuid === localFile.uuid
                );

                if (matchingFile) {
                    // Compare timestamps and select the latest version
                    return new Date(localFile.saved) > new Date(matchingFile.saved) ?
                        localFile :
                        matchingFile;
                }
                return localFile; // Keep the local file if no matching file is found
            });

            localStorage.setItem("filesList", JSON.stringify(updatedFilesList));
            console.log("Updated filesList with the latest files.");
        }


        async forceUploadEntireLibrary(filesList) {
            try {
                // Upload all files individually
                console.log("Starting to upload files from filesList...");
                await this.uploadFilesList(filesList);
                console.log("Files uploaded successfully.");

                // Upload the entire filesList as a Blob
                console.log("Starting to upload filesList as a Blob...");
                await this.uploadFilesListAsBlob();
                console.log("FilesList Blob uploaded successfully.");

                console.log("Library sync completed!");
            } catch (error) {
                console.error("Error during library synchronization:", error);
            }
        }

        // Delete a single file from S3
        async deleteSingleFileUUID(uuid) {
            const params = {
                Bucket: this.bucketName,
                Key: uuid
            };

            try {
                const result = await this.s3.deleteObject(params).promise();
                console.log(`File deleted successfully: ${uuid}`);
            } catch (error) {
                console.error(`Error deleting file: ${uuid}`, error);
            }
        }

        // Check if a file is saved to the cloud
        // async isSavedToCloud(uuid) {
        // const params = {
        // Bucket: this.bucketName,
        // Key: uuid
        // };

        // try {
        //Attempt to retrieve the file's metadata
        // await this.s3.headObject(params).promise();
        // console.log(`File exists in the cloud: ${uuid}`);
        // return true; // The file exists in the cloud
        // } catch (error) {
        // if (error.code === "NotFound") {
        // console.log(`File not found in the cloud: ${uuid}`);
        // return false; // The file does not exist in the cloud
        // } else {
        // console.error(`Error checking file in the cloud: ${uuid}`, error);
        // throw error; // Re-throw the error for further handling
        // }
        // }
        // }

        async isSavedToCloud(uuid) {
            return this.enabled;
        }

        async isEnabled(uuid) {
            return this.enabled;
        }

        // Synchronize the latest entire library by downloading the latest files if applicable
        async syncLatestEntireLibrary() {
            try {
                console.log("Starting to synchronize the latest library...");

                const localFilesList = JSON.parse(localStorage.getItem("filesList")); // Local version

                // Step 1: Download the uploaded filesList from S3

                await this.downloadFilesListAsBlob();

                // Step 2: Retrieve the uploaded filesList and the local filesList from localStorage
                const uploadedFilesList = JSON.parse(localStorage.getItem("filesList")); // S3 version

                if (!uploadedFilesList || !localFilesList) {
                    console.error("One or both filesLists are missing. Sync cannot proceed.");
                    return;
                }
                if (JSON.stringify(uploadedFilesList) !== JSON.stringify(localFilesList)) {
                    console.log("Need to sync.");
                } else {
                    //console.log("No need to sync now.");
                    //return;
                }

                // Step 3: Synchronize each file by comparing timestamps
                for (const localFile of localFilesList) {
                    const matchingFile = uploadedFilesList.find(
                        remoteFile => remoteFile.uuid === localFile.uuid
                    );

                    if (matchingFile) {
                        // Compare timestamps to determine the latest file
                        if (new Date(localFile.saved) < new Date(matchingFile.saved)) {
                            console.log(`Downloading latest version of: ${localFile.uuid} (filename ${localFile.filename}`);
                            await this.downloadSingleFileUUID(localFile.uuid); // Download the newer file
                        }
                    } else {
                        console.log(`No remote version found for: ${localFile.uuid} filename ${localFile.filename}. Keeping local version.`);
                    }
                }

                // Check for remote files that are not in local files
                for (const remoteFile of uploadedFilesList) {
                    const isLocalMatch = localFilesList.some(localFile => localFile.uuid === remoteFile.uuid);

                    if (!isLocalMatch) {
                        // Download the missing remote file
                        await this.downloadSingleFileUUID(remoteFile.uuid);

                        // Add the remote file to the localFilesList
                        localFilesList.push(remoteFile);
                    }
                }


                // Step 4: Update the local storage with the synchronized latest filesList
                const latestFiles = localFilesList.map(localFile => {
                    const matchingFile = uploadedFilesList.find(
                        remoteFile => remoteFile.uuid === localFile.uuid
                    );
                    if (!matchingFile) {
                        console.log(localFile, localFile.uuid);
                    }
                    return matchingFile ?
                        new Date(localFile.saved) < new Date(matchingFile.saved) ?
                        matchingFile :
                        localFile :
                        localFile;
                });

                localStorage.setItem("filesList", JSON.stringify(latestFiles));
                console.log("FilesList synchronized with the latest files.");

                localStorage.setItem("latestSyncTimestamp", new Date().toISOString());
                console.log("Latest sync timestamp updated with current time.");

                // Step 5: Upload the updated filesList back to the cloud
                await this.uploadFilesList(latestFiles);
                await this.uploadFilesListAsBlob();

                console.log("Sync operation completed successfully.");
            } catch (error) {
                console.error("Error during syncLatestEntireLibrary:", error);
            }
        }

        async getSignedUrl(uuid) {
            if (!this.enabled) {
                console.err("Cloud sync not enabled!");
                return null;
            }
            return new Promise((resolve, reject) => {
                const params = {
                    Bucket: this.bucketName,
                    Key: uuid,
                    Expires: 86400, // URL valid for 60 seconds 
                };
                this.s3.getSignedUrl("getObject", params, (err, url) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(url);
                    }
                });
            });
        }


    }


    // Example usage:
    // Initialize the S3Manager class
    const s3Manager = new S3Manager(
        "", // Access key
        "", // Secret key
        "", // MinIO endpoint
        "" // Bucket name
    );

    // functions required: uploadFilesListAsBlob(), uploadFilesList(), uploadSingleFile(), downloadFilesListAsBlob(), downloadFilesList(), downloadSingleFile(), latestFilesList()
    // for each user, use email, uuid is hash of email, can upload only to uuid/path on the bucket

    // Create a bucket
    //s3Manager.createBucket();

    //Upload all files from filesList
    // const filesList = JSON.parse(localStorage.getItem("filesList")) || [];

    // s3Manager.uploadFilesList(filesList);

    //Upload the filesList as a single object
    // s3Manager.uploadFilesListAsBlob();


    // document.querySelector('.save-btn').addEventListener('click', async () => {
    // await s3Manager.uploadSingleFileUUID(localStorage.getItem("currentNoteUid"));
    // await updateStatusAndSyncLatest();
    // });


    // document.querySelectorAll('.delete-file').forEach((elem) => {
    // elem.addEventListener('click', async(event) => {
    // event.stopPropagation();
    // await s3Manager.deleteSingleFileUUID(event.target.getAttribute("data-delete-uid")); 


    // });
    // });

    // document.querySelector('.sync-now-option').addEventListener('click', async (event) => {
    // event.stopPropagation();
    // event.target.innerHTML = "<span class=\"text-muted\">Syncing...</span>";
    // await s3Manager.syncLatestEntireLibrary();
    // event.target.innerHTML = "Sync Now";

    // });	

    //Assuming S3Manager is already defined and instantiated as s3Manager

    //Function to update the status item
    // async function updateStatusAndSyncLatest() {
    // const statusItem = document.querySelector('.status-item .save-cloud-timestamp');
    // const icon = document.querySelector('.status-item i');

    // if (await s3Manager.isSavedToCloud(localStorage.getItem("currentNoteUid"))) {
    //If saved to cloud
    // const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    // statusItem.innerHTML = `Synced with cloud at <strong class="">${currentTime}</strong>`;

    //Trigger sync function
    // await s3Manager.syncLatestEntireLibrary();
    // } else {
    //If not saved to cloud
    // statusItem.innerHTML = 'No Cloud Save';
    // }
    // }
    // Enable autosync
    document.querySelector(".autosync-dropdown").addEventListener('click', async (event) => {
        if (event.target && event.target.classList.contains('toggle-autosync-option')) {
            //document.querySelector('.toggle-autosync-option').addEventListener('click', async () => {
            //});
            //document.querySelector('.toggle-autosync-option').addEventListener('click', async() => {
            async function promptForCredentials() {

                await customAlert("Please create an s3 account and prepare access key, secret key, and bucketname.");
                const sync_prompt = await customMultiPrompt("Autosync configuration", [{
                        "name": "url",
                        "prompt": "Enter endpoint URL for s3 server",
                        type: "url"
                    },
                    {
                        "name": "bucketName",
                        "prompt": "Enter bucket name for s3 server"
                    },
                    {
                        "name": "accessKey",
                        "prompt": "Enter access key for s3 server"
                    },
                    {
                        "name": "secret",
                        "prompt": "Enter secret for s3 server",
                        type: "password"
                    }
                ]);

                return sync_prompt;
                //const url = await customPrompt("Enter endpoint URL for s3 server");
                //const bucketName = await customPrompt("Enter bucket name for s3 server");
                //const accessKey = await customPrompt("Enter access key for s3 server");
                //const secret = await customPrompt("Enter secret for s3 server");
            }

            const endpoint = localStorage.getItem("s3Endpoint");
            const bucket = localStorage.getItem("s3BucketName");
            const accessKey2 = localStorage.getItem("s3AccessKey");
            const secret2 = localStorage.getItem("s3SecretKey");


            if (endpoint && bucket && accessKey2 && secret2) {
                const confirmation = await customConfirm(`Use saved S3 account with Endpoint: ${endpoint} BucketName: ${bucket} AccessKey: ${accessKey2} Secret: ${secret2}?`);
                if (!confirmation) {
                    //const url = await customPrompt("Enter endpoint URL for s3 server");
                    //const bucketName = await customPrompt("Enter bucket name for s3 server");
                    //const accessKey = await customPrompt("Enter access key for s3 server");
                    //const secret = await customPrompt("Enter secret for s3 server");
                    const {
                        url,
                        bucketName,
                        accessKey,
                        secret
                    } = await promptForCredentials();
                    // Save credentials into localStorage 
                    localStorage.setItem("s3Endpoint", url);
                    localStorage.setItem("s3BucketName", bucketName);
                    localStorage.setItem("s3AccessKey", accessKey);
                    localStorage.setItem("s3SecretKey", secret);
                }

                s3Manager.setEndpoint(localStorage.getItem("s3Endpoint"));
                s3Manager.setBucketName(localStorage.getItem("s3BucketName"));
                s3Manager.setCredentials(localStorage.getItem("s3AccessKey"), localStorage.getItem("s3SecretKey"));
            } else {
                const {
                    url,
                    bucketName,
                    accessKey,
                    secret
                } = await promptForCredentials();
                // Save credentials into localStorage 
                localStorage.setItem("s3Endpoint", url);
                localStorage.setItem("s3BucketName", bucketName);
                localStorage.setItem("s3AccessKey", accessKey);
                localStorage.setItem("s3SecretKey", secret);

                s3Manager.setEndpoint(url);
                s3Manager.setBucketName(bucketName);
                s3Manager.setCredentials(accessKey, secret);

            }

            await customAlert(`Autosync is now enabled for bucket: ${localStorage.getItem("s3BucketName")}`);
            s3Manager.enabled = true;
            localStorage.setItem("s3SyncIsOn", true);

            // Add additional event listeners
            // Update dropdown menu
            const dropdownMenu = document.querySelector('.dropdown-menu[aria-labelledby="navbarDropdownViewCloud"]');
            dropdownMenu.innerHTML = '<li><a class="dropdown-item sync-now-option" href="#">Sync Now</a></li><li><a class="dropdown-item disable-autosync-option" href="#">Disable Autosync</a></li><li><a class="dropdown-item force-upload-option" href="#">Force upload entire library without syncing</a></li><li><a class="dropdown-item syncing-info-option" href="#">Syncing Info</a></li>';
            //';
            //<li><a class="dropdown-item change-account-option" href="#">Change Account...</a></li>
            //`;

            // Add event listener to "Disable Autosync"
            document.querySelector('.disable-autosync-option').addEventListener('click', async () => {
                //clearInterval(autoSyncInterval); // Stop autosync
                event.stopPropagation();
                await customAlert("Autosync disabled.");
                s3Manager.enabled = false;
                localStorage.removeItem("s3Endpoint");
                localStorage.removeItem("s3BucketName");
                localStorage.removeItem("s3AccessKey");
                localStorage.removeItem("s3SecretKey");
                localStorage.setItem("s3SyncIsOn", false);

                // Revert dropdown menu
                dropdownMenu.innerHTML = `
                <li><a class="dropdown-item toggle-autosync-option" href="#">Enable Autosync</a></li>
                <li><a class="dropdown-item change-account-option" href="#">About syncing</a></li>
            `;
            });
            document.querySelector('.syncing-info-option').addEventListener('click', async () => {
                event.stopPropagation();
                //clearInterval(autoSyncInterval); // Stop autosync
                await customAlert(`Synced to S3 account with endpoint ${s3Manager.endpoint} and bucketName ${s3Manager.bucketName}`);
                //`;
            });

            document.querySelector('.force-upload-option').addEventListener('click', async (event) => {
                event.stopPropagation();
                const confirmation = await customConfirm("This will replace your existing filesList in the cloud and may make other files inaccessible. Are you sure you want to continue?");
                if (!confirmation) {
                    return;
                }
                event.target.innerHTML = "<span class=\"text-muted\">Uploading...</span>";
                await s3Manager.forceUploadEntireLibrary();
                event.target.innerHTML = "Force upload entire library without syncing";
            });

            document.querySelector('.sync-now-option').addEventListener('click', async (event) => {
                event.stopPropagation();
                event.target.innerHTML = "<span class=\"text-muted\">Syncing...</span>";
                await s3Manager.syncLatestEntireLibrary();
                event.target.innerHTML = "Sync Now";
            });

            // Get the dropdown item element
            //const changeAccountOption = document.querySelector('.change-account-option');

            // Add the event listener
            //changeAccountOption.addEventListener('click', async () => {
            // Get the old username from s3manager.bucketName
            //const oldusername = s3manager.bucketName;

            // Prompt the user for the new username, showing the old username
            //const newusername = await customPrompt(`Current username: ${oldusername}\nPlease enter the new username:`);

            // Check if the user entered a valid new username
            //if (newusername && newusername.trim()) {
            // Call the changeaccount method with the old and new usernames
            //    s3manager.changeaccount(oldusername, newusername.trim());
            //    console.log(`Account changed from '${oldusername}' to '${newusername.trim()}'`);
            //} else {
            //    console.log('Change account operation canceled or invalid input.');
            //}
            //});

            //});
            //}
        } else {
            //await customAlert("Autosync was not enabled. Bucket name is required.");
        }

        //}
    });

    async function updateStatusBar(uuid, preferences) {
        if (!uuid) {
            console.error("UUID is required to update the status bar.");
            return;
        }

        // Retrieve the list of files from localStorage
        const filesList = filesManager.getAllFiles();

        if (!filesManager.getAllFiles().find((file) => file.uuid === uuid)) {
            console.error("UUID is not found in filesList in localStorage.");
            return;
        }

        if (filesList) {
            // Find the current file based on the UUID
            const currentFile = filesManager.getAllFiles().find(file => file.uuid === uuid);

            if (currentFile && currentFile.saved) {
                // Update the save timestamp in the status bar
                const saveTimestampElement = document.querySelector('.save-timestamp');

                let currentTime = new Date(currentFile.saved).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit'
                });

                function isNotToday(timestamp) {
                    const givenDate = new Date(timestamp);
                    const today = new Date();

                    return givenDate.getDate() !== today.getDate() ||
                        givenDate.getMonth() !== today.getMonth() ||
                        givenDate.getFullYear() !== today.getFullYear();
                }

                if (isNotToday(currentFile.saved)) {
                    currentTime = new Date(currentFile.saved).toLocaleDateString();
                }
                if (saveTimestampElement) {
                    saveTimestampElement.textContent = currentTime; // Set the timestamp
                } else {
                    console.error("Save timestamp element not found.");
                }
            } else {
                console.error("Save timestamp not found for the current file.");
            }
        } else {
            console.error("Files list is missing from localStorage.");
        }

        // Update the cloud sync status in the status bar
        const statusItem = document.querySelector('.status-item .save-cloud-timestamp');

        if (statusItem) {
            // Check cloud sync status
            const isCloudSaved = await s3Manager.isSavedToCloud(uuid);

            if (isCloudSaved) {
                const currentTime = new Date().toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit'
                });
                statusItem.innerHTML = `Cloud: <strong class="">synced at ${currentTime}</strong>`;
            } else {
                statusItem.innerHTML = 'Cloud: Local Save';
            }
        } else {
            console.error("Cloud sync status element not found.");
        }

        // Update the encryption algorithm status in the status bar
        const encryptionAlgorithmStatusBar = document.querySelector('.encryption-algorithm-text');
        if (encryptionAlgorithmStatusBar) {
            try {
                const isEncrypted = cryptoManager.isNoteEncrypted(uuid);

                if (isEncrypted) {

                    // TODO is AES-CBC 128 AES-128?
                    encryptionAlgorithmStatusBar.textContent = "AES 128-bits";
                } else {
                    encryptionAlgorithmStatusBar.textContent = "Not Encrypted";
                }
            } catch (error) {
                console.error("Error checking encryption status:", error);
            }
        } else {
            console.error("Encryption algorithm status bar element not found.");
        }

        // Update the file type status item
        // Get the viewType from sessionStorage
        const viewType = sessionStorage.getItem("viewType");

        // Select the elements to update
        const fileTypeIcon = document.querySelector('.view-type-item i');
        const fileTypeText = document.querySelector('.status-item .view-type-status');

        if (fileTypeIcon && fileTypeText) {
            // Update the icon and text based on the viewType
            if (viewType === "markdown") {
                fileTypeIcon.className = "bi bi-markdown me-2"; // Use the Markdown icon
                fileTypeText.textContent = "View: Markdown";
            } else if (viewType === "text") {
                fileTypeIcon.className = "bi bi-filetype-txt me-2"; // Use the Text icon
                fileTypeText.textContent = "View: Plain Text";
            } else {
                // Default case if viewType is not recognized
                fileTypeIcon.className = "bi bi-file-earmark me-2"; // Default generic file icon
                fileTypeText.textContent = "View: Markdown";
            }
        }
    }

    async function loadNote(this_uuid = getCurrentNoteUid()) {
        //await autosaveIfCurrentNoteIsUnsavedNote();

        updateEncryptionButtons(this_uuid);
        console.log("loadNote()");
        await loadFileIntoTextarea(this_uuid);
        await updateStatusBar(this_uuid);
        updateBigNoteTitle(this_uuid);
        updateTabTitle(this_uuid);
    }

    async function autosaveIfCurrentNoteIsUnsavedNote(nextUid) {
        //const currentNoteUid = getCurrentNoteUid();
        // const textpane = document.querySelector("#textPane").value;
        // const originalcontent = localStorage.getItem(currentNoteUid);
        // const originalcontent = localStorage.getItem(currentNoteUid);
        const editingNoteUid = sessionStorage.getItem("editingNoteUid");
        if (editingNoteUid) {
            // user clicked away
            //const response = await autoSaveNote(editingNoteUid);
            //return response;
            return await autoSaveNote(editingNoteUid);
        } else {
            return true;
        }
    }

    document.addEventListener("ReloadView", async () => {

        // Get the list group element
        const listGroup = document.querySelector('.list-group');

        // Clear any existing content
        listGroup.innerHTML = '';

        // Populate the list group with sorted files
        filesManager.getAllFiles().sort((a, b) => new Date(b.saved) - new Date(a.saved)).forEach(file => {
            const listItem = document.createElement('div');
            listItem.classList.add('list-group-item', 'list-group-item-action', 'd-flex');
            listItem.setAttribute('data-filename', file.filename);
            listItem.setAttribute('data-uid', file.uuid);
            listItem.setAttribute('data-filetype', file.filetype || 'markdown');
            //listItem.innerHTML = `<i class="bi bi-file-earmark-text"></i> ${file.filename}`;
            listItem.innerHTML = `<span class="list-item-title flex-grow-1">${file.encrypted ? '<i class="bi bi-lock"></i>' : ''}<i class="bi bi-file-earmark-text"></i> <span class="list-item-filename">${file.filename}</span></span>
    <div class="dropdown" style="float: right;">
      <button class="btn btn-secondary btn-sm dropdown-toggle" type="button" id="dropdownMenuButton${file.uuid}" data-bs-toggle="dropdown" aria-expanded="false">
        <i class="bi bi-three-dots"></i>
      </button>
      <ul class="dropdown-menu" aria-labelledby="dropdownMenuButton${file.uuid}">
	    <li><a class="dropdown-item open-in-new-tab" data-link-open-uid="${file.uuid}" href="#">Open in new tab</a></li>
        <li><a class="dropdown-item rename-file" data-rename-uid="${file.uuid}" href="#">Rename</a></li>
        <li><a class="dropdown-item delete-file" data-delete-uid="${file.uuid}" href="#">Delete</a></li>
		<li><a class="dropdown-item link-share-file" data-link-share-uid="${file.uuid}" href="#">Share file</a></li>
      </ul>
	</div>
	`;
            listGroup.appendChild(listItem);

            // Add click event listener to each list item
            listItem.querySelector(".list-item-title").addEventListener('click', async function(event) {
                if (event.isTrusted && await autosaveIfCurrentNoteIsUnsavedNote() === false) {
                    return;
                }

                // Remove 'text-bg-primary' class from all list items
                document.querySelectorAll('.list-group-item').forEach(item => item.classList.remove('text-bg-primary'));

                // Add 'text-bg-primary' class to the clicked list item
                listItem.classList.add('text-bg-primary');

                // Set currentNoteUid in localStorage
                sessionStorage.setItem('currentNoteUid', file.uuid);

                // Load file content into textarea
                //await loadFileIntoTextarea(file.uuid);

                // Update Note Title
                //document.getElementById('file-title').textContent = file.filename;

                //const currentNoteUid = localStorage.getItem("currentNoteUid");

                if (event.isTrusted) {
                    // user click
                    const currentURL = new URL(window.location.href);
                    currentURL.searchParams.set("uuid", file.uuid);
                    //console.log("event.isTrusted is true", currentURL.toString());
                    if (window.location.href !== currentURL.toString()) {
                        history.pushState(0, null, currentURL.toString());
                    }
                }


                await loadNote(file.uuid);
                // updateEncryptionButtons(file.uuid);
                // await loadFileIntoTextarea(file.uuid);
                // await updateStatusBar(file.uuid);
                // updateBigNoteTitle(file.uuid);
                // updateTabTitle(file.uuid);


            });

            // Add event listeners to the dropdown items
            const renameLinks = listItem.querySelectorAll('.rename-file');
            const deleteLinks = listItem.querySelectorAll('.delete-file');
            const linkShareLinks = listItem.querySelectorAll('.link-share-file');
            const openInNewTabLinks = listItem.querySelectorAll('.open-in-new-tab');

            renameLinks.forEach((elem) => {
                elem.addEventListener('click', function(event) {
                    event.stopPropagation(); // Prevent the list item click event from firing
                    //console.log(event.target.getAttribute("data-rename-uid"));
                    renameFile(event.target.getAttribute("data-rename-uid"));
                });
            });

            deleteLinks.forEach((elem) => {
                elem.addEventListener('click', function(event) {
                    event.stopPropagation(); // Prevent the list item click event from firing
                    deleteFile(event.target.getAttribute("data-delete-uid"));
                });
            });

            linkShareLinks.forEach((elem) => {
                elem.addEventListener('click', async function(event) {
                    event.stopPropagation();
                    if (s3Manager.enabled) {
                        await customAlert(await s3Manager.getSignedUrl(event.target.getAttribute("data-link-share-uid")));
                    } else {
                        await customAlert("Enable cloud auto syncing to share");
                    }
                });
            });

            openInNewTabLinks.forEach((elem) => {
                elem.addEventListener('click', async function(event) {
                    const currentURL = new URL(window.location.href);
                    const open_uuid = event.target.getAttribute("data-link-open-uid");
                    if (currentURL && open_uuid) {
                        currentURL.searchParams.set("uuid", open_uuid);
                        window.open(currentURL.toString(), "_blank");
                    }
                });
            });


        });

        // reset
        //sessionStorage.setItem("editingNoteUid", "");

        // After populating the list
        const currentNoteUid = getCurrentNoteUid();

        if (currentNoteUid) {
            document.querySelectorAll('.list-group-item').forEach(item => {
                if (item.getAttribute('data-uid') === currentNoteUid) {
                    item.querySelector('.list-item-title').click();
                    // const currentURL = new URL(window.location.href);
                    // currentURL.searchParams.set("uuid", currentNoteUid);
                    // history.pushState(null, "", currentURL.href);

                }
            });
            // console.log("loadNote(currentNoteUid)");
            // await loadNote(currentNoteUid);
            //await loadNote(getCurrentNoteUid());
            //updateEncryptionButtons(currentNoteUid);
            //await loadFileIntoTextarea(currentNoteUid);
            //await updateStatusBar(currentNoteUid);
            //updateBigNoteTitle(currentNoteUid);
        }

    });

    const currentURL = new URL(window.location.href);
    if (currentURL.searchParams.get("uuid")) {
        sessionStorage.setItem("currentNoteUid", currentURL.searchParams.get("uuid"));
    }

    fireReloadViewEvent();

    sessionStorage.setItem("editingNoteUid", "");

    async function checkAndEnableCloudSync() {
        function updateVisualElements() {
            const dropdownMenu = document.querySelector('.dropdown-menu[aria-labelledby="navbarDropdownViewCloud"]');
            dropdownMenu.innerHTML = '<li><a class="dropdown-item sync-now-option" href="#">Sync Now</a></li><li><a class="dropdown-item disable-autosync-option" href="#">Disable Autosync</a></li><li><a class="dropdown-item force-upload-option" href="#">Force upload entire library without syncing</a></li><li><a class="dropdown-item syncing-info-option" href="#">Syncing Info</a></li>';


            // Add event listener to "Disable Autosync"
            document.querySelector('.disable-autosync-option').addEventListener('click', async () => {
                //clearInterval(autoSyncInterval); // Stop autosync
                event.stopPropagation();
                await customAlert("Autosync disabled.");
                s3Manager.enabled = false;
                localStorage.removeItem("s3Endpoint");
                localStorage.removeItem("s3BucketName");
                localStorage.removeItem("s3AccessKey");
                localStorage.removeItem("s3SecretKey");
                localStorage.setItem("s3SyncIsOn", false);

                // Revert dropdown menu
                dropdownMenu.innerHTML = `
                <li><a class="dropdown-item toggle-autosync-option" href="#">Enable Autosync</a></li>
                <li><a class="dropdown-item change-account-option" href="#">About syncing</a></li>
            `;
            });
            document.querySelector('.syncing-info-option').addEventListener('click', async () => {
                event.stopPropagation();
                //clearInterval(autoSyncInterval); // Stop autosync
                await customAlert(`Synced to S3 account with endpoint ${s3Manager.endpoint} and bucketName ${s3Manager.bucketName}`);
            });

            document.querySelector('.force-upload-option').addEventListener('click', async (event) => {
                event.stopPropagation();
                const confirmation = await customConfirm("This will replace your existing filesList in the cloud and may make other files inaccessible. Are you sure you want to continue?");
                if (!confirmation) {
                    return;
                }
                event.target.innerHTML = "<span class=\"text-muted\">Uploading...</span>";
                await s3Manager.forceUploadEntireLibrary();
                event.target.innerHTML = "Force upload entire library without syncing";
            });

            document.querySelector('.sync-now-option').addEventListener('click', async (event) => {
                event.stopPropagation();
                event.target.innerHTML = "<span class=\"text-muted\">Syncing...</span>";
                await s3Manager.syncLatestEntireLibrary();
                event.target.innerHTML = "Sync Now";
				
            });
        }
        const endpoint = localStorage.getItem("s3Endpoint");
        const bucket = localStorage.getItem("s3BucketName");
        const accessKey2 = localStorage.getItem("s3AccessKey");
        const secret2 = localStorage.getItem("s3SecretKey");
        const s3SyncIsOn = localStorage.getItem("s3SyncIsOn");

        if (endpoint && bucket && accessKey2 && secret2 && s3SyncIsOn) {
            s3Manager.setEndpoint(localStorage.getItem("s3Endpoint"));
            s3Manager.setBucketName(localStorage.getItem("s3BucketName"));
            s3Manager.setCredentials(localStorage.getItem("s3AccessKey"), localStorage.getItem("s3SecretKey"));
            s3Manager.enabled = true;
            updateVisualElements();
            //await customAlert("Cloud sync enabled, please wait while syncing...");
            function showCloudSyncNotification() {
                // Create the toast container if it doesn't already exist
                let toastContainer = document.querySelector('.toast-container');
                if (!toastContainer) {
                    toastContainer = document.createElement('div');
                    toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                    document.body.appendChild(toastContainer);
                }

                // Create the toast element
                const toast = document.createElement('div');
                toast.id = 'liveToast';
                toast.className = 'toast';
                toast.setAttribute('role', 'alert');
                toast.setAttribute('aria-live', 'assertive');
                toast.setAttribute('aria-atomic', 'true');

                // Create the toast header
                const toastHeader = document.createElement('div');
                toastHeader.className = 'toast-header text-bg-info';
                const headerText = document.createElement('strong');
                headerText.className = 'me-auto';
                headerText.textContent = 'Cloud sync enabled';
                toastHeader.appendChild(headerText);

                // Create the toast body
                const toastBody = document.createElement('div');
                toastBody.className = 'toast-body';
                toastBody.textContent = `Cloud sync is enabled. Syncing now.`;

                // Append header and body to the toast
                toast.appendChild(toastHeader);
                toast.appendChild(toastBody);

                // Append the toast to the container
                toastContainer.appendChild(toast);

                // Initialize the toast with Bootstrap's Toast component
                const bsToast = new bootstrap.Toast(toast, {
                    autohide: true,
                });

                // Show the toast
                bsToast.show();
            }

            showCloudSyncNotification();
            document.querySelector('.sync-now-option').innerHTML = "<span class=\"text-muted\">Syncing...</span>";
            await s3Manager.syncLatestEntireLibrary();
            document.querySelector('.sync-now-option').innerHTML = "Sync Now";
        }
    }

    checkAndEnableCloudSync();




    window.addEventListener("popstate", async function(event) {
        const currentURL = new URL(window.location.href);
        const this_uuid = currentURL.searchParams.get("uuid");
        //await loadNote(this_uuid);
        sessionStorage.setItem("currentNoteUid", this_uuid);
        fireReloadViewEvent();
    });

    window.addEventListener('beforeunload', (event) => {
        if (sessionStorage.getItem("editingNoteUid")) {
            // Display a confirmation message
            event.preventDefault();
            event.returnValue = ''; // Modern browsers use this property for the prompt
        }
    });

    async function resolveConflict(uuid = getCurrentNoteUid()) {
        const userResponse = await customConfirm("This file changed while you were away. Keep this file?");
        if (!userResponse) {
            fireReloadViewEvent();
            sessionStorage.setItem("editingNoteUid", "");
        }
    }

    window.addEventListener('blur', async (event) => {
        if (sessionStorage.getItem("editingNoteUid")) {
            const savedNote = localStorage.getItem(sessionStorage.getItem("editingNoteUid"));
            const currentSavedNote = sessionStorage.setItem("editingNoteSaved", savedNote);
        }
    });

    window.addEventListener('focus', async (event) => {
        if (sessionStorage.getItem("editingNoteUid")) {
            // still editing
            // check for if the saved file changed.
            const savedNote = localStorage.getItem(sessionStorage.getItem("editingNoteUid"));
            const currentNote = sessionStorage.getItem("editingNoteSaved");
            if (savedNote !== currentNote) {
                await resolveConflict(sessionStorage.getItem("editingNoteUid"));
            }
        } else if (!sessionStorage.getItem("promptingpassword")) {
            //console.log("uhoh");
            fireReloadViewEvent();
            sessionStorage.setItem("editingNoteUid", "");
            //await s3Manager.syncLatestEntireLibrary();
        }
    });

});