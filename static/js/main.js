// Handle file upload UI and analysis type toggle
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the toggle immediately
    toggleAnalysisType();

    // Add event listeners to radio buttons
    const radioButtons = document.querySelectorAll('input[name="analysis_type"]');
    radioButtons.forEach(function(radio) {
        radio.addEventListener('change', function() {
            // Run immediately when radio button changes
            toggleAnalysisType();
        });
    });

    // File upload handling
    const fileInput = document.getElementById('file-upload');
    const fileNameDisplay = document.getElementById('file-name');
    const dropArea = document.querySelector('.file-upload');

    if (fileInput && fileNameDisplay) {
        fileInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                // Check file size (1GB limit)
                const maxSize = 1024 * 1024 * 1024; // 1GB in bytes
                if (file.size > maxSize) {
                    alert(`File size (${(file.size / (1024 * 1024)).toFixed(2)}MB) exceeds the maximum limit of 1GB. Please select a smaller file.`);
                    this.value = ''; // Clear the file input
                    fileNameDisplay.textContent = 'No file selected';
                    return;
                }

                const fileName = file.name;
                const fileSize = (file.size / (1024 * 1024)).toFixed(2);
                fileNameDisplay.textContent = `${fileName} (${fileSize}MB)`;
            } else {
                fileNameDisplay.textContent = 'No file selected';
            }
        });
    }

    // Drag and drop functionality
    if (dropArea && fileInput) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, unhighlight, false);
        });

        function highlight() {
            dropArea.classList.add('border-blue-500', 'bg-blue-50');
        }

        function unhighlight() {
            dropArea.classList.remove('border-blue-500', 'bg-blue-50');
        }

        dropArea.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length) {
                fileInput.files = files;
                const event = new Event('change');
                fileInput.dispatchEvent(event);
            }
        }
    }

    // Handle form submission
    const form = document.getElementById('analysis-form');
    if (form) {
        form.addEventListener('submit', function(e) {
            const analysisType = document.querySelector('input[name="analysis_type"]:checked').value;
            const urlInput = document.getElementById('url-input');
            const fileInput = document.getElementById('file-upload');

            if (analysisType === 'url') {
                // For URL analysis, ensure URL is provided
                if (!urlInput || !urlInput.value.trim()) {
                    e.preventDefault();
                    alert('Please enter a URL to analyze.');
                    if (urlInput) urlInput.focus();
                    return false;
                }
                // Remove file input name to avoid form data issues
                if (fileInput) fileInput.removeAttribute('name');
            } else {
                // For file analysis, ensure file is selected
                if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
                    e.preventDefault();
                    alert('Please select a file to analyze.');
                    if (fileInput) fileInput.click();
                    return false;
                }
                // Remove URL input name to avoid form data issues
                if (urlInput) urlInput.removeAttribute('name');
            }

            // Show loading state
            const submitBtn = document.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `
                    <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing...
                `;
            }
        });
    }
});

// Toggle between file and URL analysis
function toggleAnalysisType() {
    const analysisType = document.querySelector('input[name="analysis_type"]:checked').value;
    const fileSection = document.getElementById('file-section');
    const urlSection = document.getElementById('url-section');
    const fileInput = document.getElementById('file-upload');
    const urlInput = document.getElementById('url-input');
    const btnText = document.getElementById('btn-text');
    const form = document.getElementById('analysis-form');

    if (analysisType === 'file') {
        if (fileSection) fileSection.style.display = 'block';
        if (urlSection) urlSection.style.display = 'none';
        if (fileInput) fileInput.required = true;
        if (urlInput) urlInput.required = false;
        if (btnText) btnText.textContent = 'Analyze File';
        if (form) form.enctype = 'multipart/form-data';
    } else {
        if (fileSection) fileSection.style.display = 'none';
        if (urlSection) urlSection.style.display = 'block';
        if (fileInput) fileInput.required = false;
        if (urlInput) urlInput.required = true;
        if (btnText) btnText.textContent = 'Analyze URL';
        if (form) form.enctype = 'application/x-www-form-urlencoded';
    }
}

// Show error message
function showError(message) {
    const errorDiv = document.getElementById('error');
    const errorMessage = document.getElementById('error-message');
    if (errorDiv && errorMessage) {
        errorMessage.textContent = message;
        errorDiv.classList.remove('hidden');
        setTimeout(() => {
            errorDiv.classList.add('hidden');
        }, 5000);
    }
}

// Initialize charts
function initCharts(threatActors, probabilities) {
    const ctx = document.getElementById('threatChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: threatActors,
            datasets: [{
                label: 'Confidence Score',
                data: probabilities,
                backgroundColor: [
                    'rgba(239, 68, 68, 0.7)',
                    'rgba(245, 158, 11, 0.7)',
                    'rgba(16, 185, 129, 0.7)'
                ],
                borderColor: [
                    'rgba(239, 68, 68, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(16, 185, 129, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.x.toFixed(1)}% confidence`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });
}