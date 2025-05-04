document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    initFormValidation();
    initComponentTesting();
    initResultsVisualization();
});

/**
 * Form validation for the verification form
 */
function initFormValidation() {
    const verificationForm = document.getElementById('verification-form');
    
    if (verificationForm) {
        verificationForm.addEventListener('submit', function(e) {
            const frameworkPath = document.getElementById('framework_path').value;
            const errorContainer = document.getElementById('form-errors');
            
            errorContainer.innerHTML = '';
            errorContainer.style.display = 'none';
            
            if (!frameworkPath.trim()) {
                e.preventDefault();
                errorContainer.innerHTML = 'Framework path is required';
                errorContainer.style.display = 'block';
                return false;
            }
            
            // Show loading state
            const submitBtn = document.querySelector('#verification-form button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> Verifying...';
        });
    }
}

/**
 * Component testing functionality
 */
function initComponentTesting() {
    const componentTestBtns = document.querySelectorAll('.test-component-btn');
    
    componentTestBtns.forEach(btn => {
        btn.addEventListener('click', async function() {
            const component = this.dataset.component;
            const frameworkPath = document.getElementById('framework_path').value;
            
            if (!frameworkPath.trim()) {
                alert('Please enter a framework path first');
                return;
            }
            
            // Show loading state
            const originalText = this.innerHTML;
            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Testing...';
            
            try {
                // Send API request to test component
                const response = await fetch('/api/verify-component', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        component: component,
                        framework_path: frameworkPath
                    })
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    displayComponentResult(component, data.data);
                } else {
                    throw new Error(data.message || 'Unknown error');
                }
            } catch (error) {
                const resultContainer = document.getElementById(`${component}-result`);
                if (resultContainer) {
                    resultContainer.innerHTML = `
                        <div class="error-message">
                            <i class="feather icon-alert-triangle"></i>
                            Error: ${error.message}
                        </div>
                    `;
                }
            } finally {
                // Restore button state
                this.disabled = false;
                this.innerHTML = originalText;
            }
        });
    });
}

/**
 * Display component test results
 */
function displayComponentResult(component, data) {
    const resultContainer = document.getElementById(`${component}-result`);
    if (!resultContainer) return;
    
    let html = '<div class="component-result">';
    
    // Success status with icon
    if (data.success) {
        html += `<div class="result-status success">
            <i class="feather icon-check-circle"></i> Component Verified
        </div>`;
    } else {
        html += `<div class="result-status error">
            <i class="feather icon-x-circle"></i> Verification Failed
        </div>`;
    }
    
    // Details table
    html += '<table class="detail-table">';
    html += '<tbody>';
    
    Object.entries(data).forEach(([key, value]) => {
        if (key === 'success') return; // Skip the success flag, already displayed
        
        html += `<tr>
            <th>${formatLabel(key)}</th>
            <td>${formatValue(value)}</td>
        </tr>`;
    });
    
    html += '</tbody></table></div>';
    
    resultContainer.innerHTML = html;
}

/**
 * Format label for display (convert snake_case to Title Case)
 */
function formatLabel(key) {
    return key
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

/**
 * Format value for display
 */
function formatValue(value) {
    if (typeof value === 'boolean') {
        return value ? 
            '<span class="badge success">Yes</span>' : 
            '<span class="badge error">No</span>';
    }
    
    if (typeof value === 'object' && value !== null) {
        if (Array.isArray(value)) {
            return value.length === 0 ? 
                '<em>Empty array</em>' : 
                `<ul>${value.map(item => `<li>${formatValue(item)}</li>`).join('')}</ul>`;
        }
        
        return '<pre class="code-block">' + JSON.stringify(value, null, 2) + '</pre>';
    }
    
    return String(value);
}

/**
 * Results page visualization
 */
function initResultsVisualization() {
    const detailToggles = document.querySelectorAll('.detail-toggle');
    
    detailToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const targetId = this.dataset.target;
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                const isVisible = targetElement.style.display !== 'none';
                targetElement.style.display = isVisible ? 'none' : 'block';
                this.innerHTML = isVisible ? 
                    'Show Details <i class="feather icon-chevron-down"></i>' : 
                    'Hide Details <i class="feather icon-chevron-up"></i>';
            }
        });
    });
    
    // Initialize any charts if present
    const chartElements = document.querySelectorAll('.result-chart');
    
    chartElements.forEach(chartElement => {
        const chartType = chartElement.dataset.chartType;
        const chartData = JSON.parse(chartElement.dataset.chartData || '{}');
        
        if (chartType && chartData) {
            renderChart(chartElement, chartType, chartData);
        }
    });
}

/**
 * Render chart using Chart.js
 */
function renderChart(element, type, data) {
    // This would be implemented if using Chart.js
    // For now, just provide a placeholder for the chart
    if (type === 'pie') {
        element.innerHTML = '<div class="chart-placeholder">Pie Chart Visualization</div>';
    } else if (type === 'bar') {
        element.innerHTML = '<div class="chart-placeholder">Bar Chart Visualization</div>';
    } else {
        element.innerHTML = '<div class="chart-placeholder">Chart Visualization</div>';
    }
}
