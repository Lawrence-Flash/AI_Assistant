/**
 * Main JavaScript functionality for the cybersecurity assistant
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the voice assistant
    const assistant = new VoiceAssistant();
    window.assistant = assistant;

    // Welcome message
    assistant.speak("Welcome to the Cybersecurity Assistant. How can I help you today?");

    // Set up event listeners for the microphone button
    const micButton = document.getElementById('mic-button');
    if (micButton) {
        micButton.addEventListener('click', function() {
            if (assistant.isListening) {
                assistant.stopListening();
            } else {
                assistant.startListening();
            }
        });
    }

    // Handle form submission for network scanning
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const targetInput = document.getElementById('target-input');
            const target = targetInput.value.trim();
            const resultsContainer = document.getElementById('scan-results');
            const loadingSpinner = document.getElementById('loading-spinner');
            
            if (!target) {
                showAlert('Please enter a target IP address or domain name.', 'danger');
                assistant.speak('Please enter a target IP address or domain name.');
                return;
            }
            
            // Show loading spinner
            if (loadingSpinner) loadingSpinner.classList.remove('d-none');
            if (resultsContainer) resultsContainer.innerHTML = '';
            
            // Disable the submit button during scan
            const submitButton = scanForm.querySelector('button[type="submit"]');
            if (submitButton) submitButton.disabled = true;
            
            // Make the AJAX request to perform the scan
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    'target': target
                })
            })
            .then(response => response.json())
            .then(data => {
                // Hide loading spinner
                if (loadingSpinner) loadingSpinner.classList.add('d-none');
                
                if (data.success) {
                    // Display the results
                    if (resultsContainer) {
                        // Format and display the scan results
                        const formattedResult = formatScanResults(data.result);
                        resultsContainer.innerHTML = `
                            <div class="alert alert-success" role="alert">
                                Scan completed successfully!
                            </div>
                            <div class="card bg-dark text-light mb-4">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">Scan Results for ${target}</h5>
                                    <a href="/scan/${data.scan_id}" class="btn btn-sm btn-outline-info">View Details</a>
                                </div>
                                <div class="card-body">
                                    <pre class="mb-0">${formattedResult}</pre>
                                </div>
                            </div>
                        `;
                    }
                    
                    // Announce the scan completion
                    assistant.speak(`Scan of ${target} completed successfully. Check the results on screen.`);
                } else {
                    // Display error message
                    showAlert(data.error, 'danger');
                    assistant.speak(`Error: ${data.error}`);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                if (loadingSpinner) loadingSpinner.classList.add('d-none');
                showAlert('An error occurred while processing your request.', 'danger');
                assistant.speak('An error occurred while processing your request.');
            })
            .finally(() => {
                // Re-enable the submit button
                if (submitButton) submitButton.disabled = false;
            });
        });
    }

    // Check if Nmap is available on the system
    fetch('/check_nmap')
        .then(response => response.json())
        .then(data => {
            if (!data.available) {
                showAlert('Warning: Nmap is not installed on the system. Scanning functionality will not work.', 'warning', true);
            }
        })
        .catch(error => {
            console.error('Error checking Nmap availability:', error);
        });

    // Helper function to display alerts
    function showAlert(message, type = 'info', persistent = false) {
        const alertsContainer = document.getElementById('alerts-container');
        if (!alertsContainer) return;
        
        const alertId = 'alert-' + Date.now();
        const alertHtml = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        
        alertsContainer.innerHTML += alertHtml;
        
        // Auto-dismiss non-persistent alerts after 5 seconds
        if (!persistent) {
            setTimeout(() => {
                const alertElement = document.getElementById(alertId);
                if (alertElement) {
                    const bsAlert = new bootstrap.Alert(alertElement);
                    bsAlert.close();
                }
            }, 5000);
        }
    }

    // Helper function to format scan results for display
    function formatScanResults(rawResults) {
        // Escape HTML to prevent XSS
        const escapeHtml = (text) => {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        };
        
        // Basic colorization of scan results
        let formatted = escapeHtml(rawResults);
        
        // Highlight open ports (green)
        formatted = formatted.replace(/(\d+\/\w+\s+open\s+\w+)/g, '<span class="text-success">$1</span>');
        
        // Highlight closed ports (red)
        formatted = formatted.replace(/(\d+\/\w+\s+closed\s+\w+)/g, '<span class="text-danger">$1</span>');
        
        // Highlight filtered ports (yellow)
        formatted = formatted.replace(/(\d+\/\w+\s+filtered\s+\w+)/g, '<span class="text-warning">$1</span>');
        
        return formatted;
    }
});
