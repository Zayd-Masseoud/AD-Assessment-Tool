document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tabs
    const triggerTabList = [].slice.call(document.querySelectorAll('#resultTabs button'));
    triggerTabList.forEach(function(triggerEl) {
        const tabTrigger = new bootstrap.Tab(triggerEl);
        triggerEl.addEventListener('click', function(event) {
            event.preventDefault();
            tabTrigger.show();
        });
    });

    // Export to PDF function
    function exportToPdf() {
        console.log('Exporting to PDF...');
        fetch('/export_pdf')
            .then(response => response.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'assessment_report.pdf';
                a.click();
                window.URL.revokeObjectURL(url);
            })
            .catch(error => {
                console.error('Error exporting PDF:', error);
                alert('Failed to generate PDF report.');
            });
    }

    // Export to CSV function
    function exportToCsv() {
        console.log('Exporting to CSV...');
        fetch('/export_csv')
            .then(response => response.text())
            .then(csv => {
                const url = window.URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
                const a = document.createElement('a');
                a.href = url;
                a.download = 'assessment_results.csv';
                a.click();
                window.URL.revokeObjectURL(url);
            })
            .catch(error => {
                console.error('Error exporting CSV:', error);
                alert('Failed to generate CSV report.');
            });
    }

    // Add event handlers for PDF export button
    const pdfButton = document.getElementById('downloadPdf');
    if (pdfButton) {
        pdfButton.addEventListener('click', function() {
            exportToPdf();
        });
    }

    // Add event handlers for CSV export button
    const csvButton = document.querySelector('button.btn-outline-secondary:nth-child(2)');
    if (csvButton) {
        csvButton.addEventListener('click', function() {
            exportToCsv();
        });
    }

    // Handle toggle button text for all collapse buttons
    const toggleButtons = document.querySelectorAll('[data-bs-toggle="collapse"]');
    toggleButtons.forEach(button => {
        const collapseTargetId = button.getAttribute('data-bs-target');
        const collapseTarget = document.querySelector(collapseTargetId);
        if (collapseTarget) {
            // Use event delegation to handle show/hide events efficiently
            collapseTarget.addEventListener('show.bs.collapse', () => {
                const span = button.querySelector('span');
                if (span) {
                    if (button.classList.contains('toggle-details')) {
                        span.textContent = 'Hide Details';
                    } else if (button.classList.contains('toggle-members')) {
                        span.textContent = 'Hide Members';
                    }
                }
            });
            collapseTarget.addEventListener('hide.bs.collapse', () => {
                const span = button.querySelector('span');
                if (span) {
                    if (button.classList.contains('toggle-details')) {
                        span.textContent = 'Details';
                    } else if (button.classList.contains('toggle-members')) {
                        span.textContent = 'Members';
                    } 
                }
            });
        }
    });

    // Initialize Bootstrap modals for vulnerability details
    const detailModals = [].slice.call(document.querySelectorAll('[id^="detailModal"]'));
    detailModals.forEach(function(modalEl) {
        new bootstrap.Modal(modalEl);
    });

    // Initialize Bootstrap modals for misconfiguration details
    const misconfigModals = [].slice.call(document.querySelectorAll('[id^="misconfigModal"]'));
    misconfigModals.forEach(function(modalEl) {
        new bootstrap.Modal(modalEl);
    });

    // Create modal function for misconfiguration details
    function createMisconfigModal(misconfigId) {
        console.log(`Creating modal for misconfiguration ${misconfigId}`);
    }
});