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