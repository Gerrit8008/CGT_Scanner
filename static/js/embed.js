(function() {
    // Find scanner container
    const container = document.getElementById('cybrscan-scanner');
    if (!container) {
        console.error('CybrScan: Scanner container not found');
        return;
    }

    // Get API key from data attribute
    const apiKey = container.getAttribute('data-key');
    if (!apiKey) {
        console.error('CybrScan: API key not provided');
        return;
    }

    // Load scanner configuration
    fetch(`https://scanner.cybrscan.com/api/scanner/${apiKey}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                initializeScanner(data.configuration);
            } else {
                console.error('CybrScan: Failed to load scanner configuration');
            }
        })
        .catch(error => {
            console.error('CybrScan: Error loading scanner:', error);
        });

    function initializeScanner(config) {
        // Apply custom styles
        const styles = document.createElement('style');
        styles.textContent = `
            #cybrscan-scanner {
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                padding: 20px;
                max-width: 800px;
                margin: 0 auto;
            }
            .cybrscan-header {
                background-color: ${config.customization.primary_color};
                color: #fff;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
            }
            /* Add more custom styles based on configuration */
        `;
        document.head.appendChild(styles);

        // Create scanner UI
        container.innerHTML = `
            <div class="cybrscan-header">
                <h2>${config.name}</h2>
            </div>
            <div class="cybrscan-content">
                <!-- Add scanner content here -->
            </div>
        `;

        // Initialize scanner functionality
        // ... implement scanner logic ...
    }
})();
