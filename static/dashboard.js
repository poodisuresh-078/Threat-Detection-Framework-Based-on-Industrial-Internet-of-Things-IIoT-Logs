/**
 * IIoT Sentinel - Dashboard & Analytics Visualizations
 * Utilizes Chart.js for interactive cybersecurity reporting
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Mobile Sidebar Navigation Toggle
    const menuToggle = document.getElementById("menuToggle");
    const sidebar = document.querySelector(".sidebar");

    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", function () {
            sidebar.classList.toggle("open");
        });
    }

    // Chart.js Global Theme Customization
    if (typeof Chart !== "undefined") {
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "system-ui, -apple-system, sans-serif";
        Chart.defaults.plugins.tooltip.backgroundColor = "#1e293b";
        Chart.defaults.plugins.tooltip.titleColor = "#f8fafc";
        Chart.defaults.plugins.tooltip.bodyColor = "#cbd5e1";
        Chart.defaults.plugins.tooltip.borderColor = "#334155";
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        Chart.defaults.plugins.tooltip.padding = 10;
        Chart.defaults.plugins.tooltip.cornerRadius = 6;
    }

    // 2. Initialize Dashboard Charts
    if (window.dashboardMetrics) {
        initDashboardCharts(window.dashboardMetrics);
    }

    // 3. Initialize Reports Charts
    if (window.reportsData) {
        initReportsCharts(window.reportsData);
    }
});

/**
 * Initializes charts on the primary Dashboard
 */
function initDashboardCharts(data) {
    // Chart 1: Threat Risk Distribution (Doughnut)
    const riskCtx = document.getElementById("riskDistributionChart");
    if (riskCtx) {
        const counts = [
            data.criticalAlerts || 0,
            data.highAlerts || 0,
            data.mediumAlerts || 0,
            data.lowAlerts || 0,
        ];
        const hasData = counts.some(c => c > 0);

        new Chart(riskCtx, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low"],
                datasets: [{
                    data: hasData ? counts : [0, 0, 0, 0],
                    backgroundColor: [
                        "#ef4444", // Critical Red
                        "#f97316", // High Orange
                        "#eab308", // Medium Yellow
                        "#3b82f6", // Low Blue
                    ],
                    borderWidth: 2,
                    borderColor: "#141d2f",
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { boxWidth: 12, padding: 14 }
                    }
                },
                cutout: "70%"
            }
        });
    }

    // Chart 2: Security Health Ratio (Normal vs Flagged)
    const healthCtx = document.getElementById("healthRatioChart");
    if (healthCtx) {
        const normal = data.normalEvents || 0;
        const suspicious = data.suspiciousEvents || 0;
        const hasData = (normal + suspicious) > 0;

        new Chart(healthCtx, {
            type: "pie",
            data: {
                labels: ["Normal Baseline", "Suspicious Flagged"],
                datasets: [{
                    data: hasData ? [normal, suspicious] : [1, 0],
                    backgroundColor: [
                        "#10b981", // Emerald Normal
                        "#f59e0b", // Amber Suspicious
                    ],
                    borderWidth: 2,
                    borderColor: "#141d2f"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { boxWidth: 12, padding: 14 }
                    }
                }
            }
        });
    }
}

/**
 * Initializes detailed charts on the Reports page
 */
function initReportsCharts(data) {
    // Report Chart 1: Risk Tiers Bar Chart
    const reportRiskCtx = document.getElementById("reportRiskChart");
    if (reportRiskCtx) {
        new Chart(reportRiskCtx, {
            type: "bar",
            data: {
                labels: ["Critical Alerts", "High Risk", "Medium Risk", "Low Risk"],
                datasets: [{
                    label: "Alert Count",
                    data: [
                        data.criticalCount || 0,
                        data.highCount || 0,
                        data.mediumCount || 0,
                        data.lowCount || 0
                    ],
                    backgroundColor: [
                        "rgba(239, 68, 68, 0.8)",
                        "rgba(249, 115, 22, 0.8)",
                        "rgba(234, 179, 8, 0.8)",
                        "rgba(59, 130, 246, 0.8)"
                    ],
                    borderColor: [
                        "#ef4444",
                        "#f97316",
                        "#eab308",
                        "#3b82f6"
                    ],
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { stepSize: 1 }
                    },
                    x: {
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // Report Chart 2: Top Attack Vectors Horizontal Bar
    const reportEventsCtx = document.getElementById("reportEventsChart");
    if (reportEventsCtx) {
        const labels = data.eventLabels && data.eventLabels.length > 0 ? data.eventLabels : ["No threats recorded"];
        const counts = data.eventCounts && data.eventCounts.length > 0 ? data.eventCounts : [0];

        new Chart(reportEventsCtx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Incidents",
                    data: counts,
                    backgroundColor: "rgba(0, 180, 216, 0.75)",
                    borderColor: "#00b4d8",
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { stepSize: 1 }
                    },
                    y: {
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
}

