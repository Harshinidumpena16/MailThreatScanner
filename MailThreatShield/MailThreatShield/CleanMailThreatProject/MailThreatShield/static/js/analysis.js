/**
 * MailThreat Scanner - Analysis Page JavaScript
 * Handles email upload and analysis functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const emailDropzone = document.getElementById('emailDropzone');
    const emailFileInput = document.getElementById('emailFileInput');
    const selectFileBtn = document.getElementById('selectFileBtn');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    const selectedFileName = document.getElementById('selectedFileName');
    const selectedFileSize = document.getElementById('selectedFileSize');
    const removeFileBtn = document.getElementById('removeFileBtn');
    const startAnalysisBtn = document.getElementById('startAnalysisBtn');
    const emailContentInput = document.getElementById('emailContentInput');
    const startAnalysisPasteBtn = document.getElementById('startAnalysisPasteBtn');
    const analysisProgress = document.getElementById('analysisProgress');
    const analysisProgressBar = document.getElementById('analysisProgressBar');
    const analysisStatusText = document.getElementById('analysisStatusText');
    
    // File Upload Tab functionality
    if (emailFileInput && selectFileBtn) {
        // Trigger file input when select button is clicked
        selectFileBtn.addEventListener('click', function() {
            emailFileInput.click();
        });
        
        // Handle file selection
        emailFileInput.addEventListener('change', function() {
            handleFileSelection(this.files);
        });
    }
    
    // Dropzone functionality
    if (emailDropzone) {
        // Prevent default behavior for drag events
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            emailDropzone.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        // Highlight dropzone on dragenter/dragover
        ['dragenter', 'dragover'].forEach(eventName => {
            emailDropzone.addEventListener(eventName, highlight, false);
        });
        
        // Unhighlight dropzone on dragleave/drop
        ['dragleave', 'drop'].forEach(eventName => {
            emailDropzone.addEventListener(eventName, unhighlight, false);
        });
        
        function highlight() {
            emailDropzone.classList.add('active');
        }
        
        function unhighlight() {
            emailDropzone.classList.remove('active');
        }
        
        // Handle file drop
        emailDropzone.addEventListener('drop', function(e) {
            const files = e.dataTransfer.files;
            handleFileSelection(files);
        });
    }
    
    // Handle file selection (from input or drop)
    function handleFileSelection(files) {
        if (files.length > 0) {
            const file = files[0];
            
            // Check file extension
            const validExtensions = ['.eml', '.msg', '.txt', '.pdf'];
            const fileName = file.name.toLowerCase();
            const isValidFile = validExtensions.some(ext => fileName.endsWith(ext));
            
            if (!isValidFile) {
                alert('Please select a valid email file (.eml, .msg, .txt, .pdf)');
                return;
            }
            
            // Check file size (25MB max)
            const maxSize = 25 * 1024 * 1024; // 25MB in bytes
            if (file.size > maxSize) {
                alert('File size exceeds the maximum limit of 25MB');
                return;
            }
            
            // Update file info display
            selectedFileName.textContent = file.name;
            selectedFileSize.textContent = `(${formatFileSize(file.size)})`;
            selectedFileInfo.classList.remove('d-none');
            emailDropzone.classList.add('d-none');
            
            // Enable analysis button
            startAnalysisBtn.disabled = false;
        }
    }
    
    // Format file size for display
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Remove selected file
    if (removeFileBtn) {
        removeFileBtn.addEventListener('click', function() {
            // Reset file input
            if (emailFileInput) {
                emailFileInput.value = '';
            }
            
            // Hide file info and show dropzone
            selectedFileInfo.classList.add('d-none');
            emailDropzone.classList.remove('d-none');
            
            // Disable analysis button
            startAnalysisBtn.disabled = true;
        });
    }
    
    // Enable/disable paste tab analysis button based on content
    if (emailContentInput && startAnalysisPasteBtn) {
        emailContentInput.addEventListener('input', function() {
            startAnalysisPasteBtn.disabled = this.value.trim().length === 0;
        });
    }
    
    // Handle analysis submission (file upload)
    if (startAnalysisBtn) {
        startAnalysisBtn.addEventListener('click', function() {
            if (emailFileInput.files.length === 0) {
                alert('Please select an email file to analyze');
                return;
            }
            
            // Show progress overlay
            showAnalysisProgress();
            
            // Create form data
            const formData = new FormData();
            formData.append('emailFile', emailFileInput.files[0]);
            
            // Submit the form
            submitAnalysis(formData);
        });
    }
    
    // Handle analysis submission (pasted content)
    if (startAnalysisPasteBtn) {
        startAnalysisPasteBtn.addEventListener('click', function() {
            const content = emailContentInput.value.trim();
            if (content.length === 0) {
                alert('Please paste email content to analyze');
                return;
            }
            
            // Show progress overlay
            showAnalysisProgress();
            
            // Create form data
            const formData = new FormData();
            formData.append('emailContent', content);
            
            // Submit the form
            submitAnalysis(formData);
        });
    }
    
    // Show analysis progress overlay
    function showAnalysisProgress() {
        if (analysisProgress) {
            analysisProgress.classList.remove('d-none');
            simulateProgress();
        }
    }
    
    // Simulate progress updates
    function simulateProgress() {
        if (analysisProgressBar && analysisStatusText) {
            let progress = 0;
            const statuses = [
                { percent: 10, text: "Parsing email content..." },
                { percent: 25, text: "Checking authentication (SPF, DKIM, DMARC)..." },
                { percent: 40, text: "Analyzing sender reputation..." },
                { percent: 55, text: "Scanning URLs for threats..." },
                { percent: 70, text: "Examining attachments..." },
                { percent: 85, text: "Looking for QR codes and analyzing audio..." },
                { percent: 95, text: "Generating final report..." }
            ];
            
            // Update progress at intervals
            const interval = setInterval(function() {
                // Find the next status to show
                const nextStatus = statuses.find(status => status.percent > progress);
                
                if (nextStatus) {
                    progress = nextStatus.percent;
                    analysisProgressBar.style.width = `${progress}%`;
                    analysisProgressBar.setAttribute('aria-valuenow', progress);
                    analysisStatusText.textContent = nextStatus.text;
                } else {
                    // Clear interval when all statuses are shown
                    clearInterval(interval);
                }
            }, 700);
        }
    }
    
    // Get current timestamp in YYYY-MM-DD HH:MM:SS format
    function getCurrentTimestamp() {
        const now = new Date();
        return now.getFullYear() + '-' + 
               String(now.getMonth() + 1).padStart(2, '0') + '-' +
               String(now.getDate()).padStart(2, '0') + ' ' +
               String(now.getHours()).padStart(2, '0') + ':' +
               String(now.getMinutes()).padStart(2, '0') + ':' +
               String(now.getSeconds()).padStart(2, '0');
    }

    // Submit analysis to server
    function submitAnalysis(formData) {
        // Add current timestamp to form data
        formData.append('analysis_timestamp', getCurrentTimestamp());
        fetch('/api/upload-email', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success && data.redirect_url) {
                // Redirect to the report page
                window.location.href = data.redirect_url;
            } else if (data.error) {
                // Handle error
                alert('Error: ' + data.error);
                if (analysisProgress) {
                    analysisProgress.classList.add('d-none');
                }
            }
        })
        .catch(error => {
            console.error('Error during analysis:', error);
            alert('An error occurred during analysis. Please try again.');
            if (analysisProgress) {
                analysisProgress.classList.add('d-none');
            }
        });
    }
});
