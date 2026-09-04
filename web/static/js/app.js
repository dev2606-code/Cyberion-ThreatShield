const fileInput =
    document.getElementById("evtx_file");

const fileLabel =
    document.querySelector(".upload-title");

const scanButton =
    document.querySelector(".scan-button");

const uploadForm =
    document.querySelector(".upload-form");


if (fileInput) {

    fileInput.addEventListener(
        "change",
        function () {

            if (
                this.files &&
                this.files.length > 0
            ) {

                fileLabel.textContent =
                    this.files[0].name;

            } else {

                fileLabel.textContent =
                    "Select an EVTX file";

            }

        }
    );

}


if (uploadForm) {

    uploadForm.addEventListener(
        "submit",
        function () {

            scanButton.disabled = true;

            scanButton.textContent =
                "Scanning...";

        }
    );

}



const searchInput =
    document.getElementById(
        "alertSearch"
    );

const severityFilter =
    document.getElementById(
        "severityFilter"
    );

const alertCards =
    document.querySelectorAll(
        ".alert-card"
    );


function filterAlerts() {

    const searchValue =
        searchInput
            ? searchInput.value
                .toLowerCase()
                .trim()
            : "";


    const severityValue =
        severityFilter
            ? severityFilter.value
            : "all";


    alertCards.forEach(
        (card) => {

            const severity =
                card.dataset.severity || "";

            const searchText =
                card.dataset.search || "";


            const matchesSearch =
                searchText.includes(
                    searchValue
                );


            const matchesSeverity =
                severityValue === "all" ||
                severity === severityValue;


            if (
                matchesSearch &&
                matchesSeverity
            ) {

                card.style.display =
                    "block";

            } else {

                card.style.display =
                    "none";

            }

        }
    );

}


if (searchInput) {

    searchInput.addEventListener(
        "input",
        filterAlerts
    );

}


if (severityFilter) {

    severityFilter.addEventListener(
        "change",
        filterAlerts
    );

}
// --------------------------------------------------
// RECENT SCAN ACTIVITY CHART
// --------------------------------------------------

const scanChart =
    document.getElementById("scanActivityChart");

if (scanChart) {

    const scanData =
        scanChart.querySelectorAll(".chart-data");

    const scans = Array.from(scanData).reverse();

    scanChart.innerHTML = "";

    scans.forEach((scan) => {

        const filename =
            scan.dataset.filename || "Unknown";

        const events =
            Number(scan.dataset.events || 0);

        const alerts =
            Number(scan.dataset.alerts || 0);

        const row =
            document.createElement("div");

        row.className = "chart-row";

        row.innerHTML = `
            <div class="chart-label"
                 title="${filename}">
                ${filename}
            </div>

            <div class="chart-bars">

                <div class="chart-metric">
                    <span>Events: ${events}</span>
                    <div class="chart-track">
                        <div
                            class="chart-bar events-bar"
                            style="width: ${Math.min(events * 4, 100)}%"
                        ></div>
                    </div>
                </div>

                <div class="chart-metric">
                    <span>Alerts: ${alerts}</span>
                    <div class="chart-track">
                        <div
                            class="chart-bar alerts-bar"
                            style="width: ${Math.min(alerts * 10, 100)}%"
                        ></div>
                    </div>
                </div>

            </div>
        `;

        scanChart.appendChild(row);
    });

}