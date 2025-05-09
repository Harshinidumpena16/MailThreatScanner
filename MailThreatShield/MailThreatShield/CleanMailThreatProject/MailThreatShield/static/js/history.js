/**
 * MailThreat Scanner - History Page JavaScript
 * Handles scan history functionality and search
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const historySearchInput = document.getElementById('historySearchInput');
    const historyTableBody = document.getElementById('historyTableBody');
    const noResultsMessage = document.getElementById('noResultsMessage');
    const clearSearchBtn = document.getElementById('clearSearchBtn');
    
    // Track original table rows
    let originalRows = [];
    
    // Initialize function to capture original table state
    function initializeTable() {
        if (historyTableBody) {
            // Store original rows for reference
            originalRows = Array.from(historyTableBody.querySelectorAll('tr'));
        }
    }
    
    // Call initialize on page load
    initializeTable();
    
    // Search functionality
    if (historySearchInput) {
        historySearchInput.addEventListener('input', function() {
            const searchTerm = this.value.trim().toLowerCase();
            
            // If search is empty, restore original table
            if (searchTerm === '') {
                restoreOriginalTable();
                return;
            }
            
            // Filter scan history via API
            fetchFilteredHistory(searchTerm);
        });
    }
    
    // Clear search button
    if (clearSearchBtn) {
        clearSearchBtn.addEventListener('click', function() {
            if (historySearchInput) {
                historySearchInput.value = '';
                restoreOriginalTable();
            }
        });
    }
    
    // Restore original table (before search)
    function restoreOriginalTable() {
        if (historyTableBody && noResultsMessage) {
            // Clear current content
            historyTableBody.innerHTML = '';
            
            // If we have original rows, add them back
            if (originalRows.length > 0) {
                originalRows.forEach(row => {
                    historyTableBody.appendChild(row.cloneNode(true));
                });
                
                // Hide no results message
                noResultsMessage.classList.add('d-none');
            } else {
                // Show empty state
                const emptyRow = createEmptyStateRow();
                historyTableBody.appendChild(emptyRow);
            }
        }
    }
    
    // Create empty state row for table
    function createEmptyStateRow() {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.setAttribute('colspan', '7');
        td.classList.add('text-center', 'py-4');
        
        td.innerHTML = `
            <div class="empty-state">
                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-inbox"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg>
                <h5>No scan history found</h5>
                <p>When you analyze emails, they will appear here</p>
                <a href="/analysis" class="btn btn-primary">Analyze an Email</a>
            </div>
        `;
        
        tr.appendChild(td);
        return tr;
    }
    
    // Fetch filtered history from API
    function fetchFilteredHistory(query) {
        fetch(`/api/scan-history?query=${encodeURIComponent(query)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                updateHistoryTable(data);
            })
            .catch(error => {
                console.error('Error fetching filtered history:', error);
            });
    }
    
    // Update history table with filtered results
    function updateHistoryTable(data) {
        if (historyTableBody && noResultsMessage) {
            // Clear current content
            historyTableBody.innerHTML = '';
            
            // If we have results, add them to the table
            if (data.length > 0) {
                data.forEach(item => {
                    const row = createHistoryRow(item);
                    historyTableBody.appendChild(row);
                });
                
                // Hide no results message
                noResultsMessage.classList.add('d-none');
            } else {
                // Show no results message
                noResultsMessage.classList.remove('d-none');
            }
        }
    }
    
    // Create a table row for a history item
    function createHistoryRow(item) {
        const tr = document.createElement('tr');
        
        // Date column
        const dateCell = document.createElement('td');
        dateCell.textContent = item.date;
        tr.appendChild(dateCell);
        
        // Report ID column
        const reportIdCell = document.createElement('td');
        reportIdCell.textContent = item.report_id;
        tr.appendChild(reportIdCell);
        
        // Subject column
        const subjectCell = document.createElement('td');
        if (item.subject) {
            subjectCell.textContent = item.subject;
        } else {
            const em = document.createElement('em');
            em.textContent = 'No Subject';
            subjectCell.appendChild(em);
        }
        tr.appendChild(subjectCell);
        
        // Sender column
        const senderCell = document.createElement('td');
        senderCell.textContent = item.sender;
        tr.appendChild(senderCell);
        
        // Threat Level column
        const threatLevelCell = document.createElement('td');
        const badge = document.createElement('span');
        badge.classList.add('badge');
        
        if (item.threat_level === 'malicious') {
            badge.classList.add('bg-danger');
            badge.textContent = 'High';
        } else if (item.threat_level === 'suspicious') {
            badge.classList.add('bg-warning', 'text-dark');
            badge.textContent = 'Medium';
        } else {
            badge.classList.add('bg-success');
            badge.textContent = 'Low';
        }
        
        threatLevelCell.appendChild(badge);
        tr.appendChild(threatLevelCell);
        
        // Status column
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.classList.add('status-badge');
        
        if (item.status === 'Completed') {
            statusBadge.classList.add('completed');
            statusBadge.textContent = 'Completed';
        } else {
            statusBadge.classList.add('in-progress');
            statusBadge.textContent = 'In Progress';
        }
        
        statusCell.appendChild(statusBadge);
        tr.appendChild(statusCell);
        
        // Actions column
        const actionsCell = document.createElement('td');
        const viewButton = document.createElement('a');
        viewButton.href = `/report/${item.report_id}`;
        viewButton.classList.add('btn', 'btn-sm', 'btn-outline-primary');
        viewButton.textContent = 'View Report';
        actionsCell.appendChild(viewButton);
        tr.appendChild(actionsCell);
        
        return tr;
    }
});
