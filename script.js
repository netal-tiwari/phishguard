// ==========================================
// PHISHGUARD - BASIC URL SCANNER
// ==========================================

console.log("🔥 PHISHGUARD SCRIPT.JS LOADED 🔥");

// ==========================================
// KNOWN BRANDS
// ==========================================

const trustedBrands = {
    flipkart: "flipkart.com",
    amazon: "amazon.in",
    myntra: "myntra.com",
    meesho: "meesho.com",
    paytm: "paytm.com"
};

// ==========================================
// INITIALIZE PHISHGUARD
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("✅ PHISHGUARD DOM LOADED");

    const urlInput = document.getElementById("urlInput");
    const scanButton = document.getElementById("scanButton");

    // Check whether required HTML elements exist
    if (!urlInput) {
        console.error("❌ ERROR: #urlInput was not found in HTML.");
        return;
    }

    if (!scanButton) {
        console.error("❌ ERROR: #scanButton was not found in HTML.");
        return;
    }

    console.log("✅ URL input found:", urlInput);
    console.log("✅ Scan button found:", scanButton);

    // ==========================================
    // SCAN BUTTON
    // ==========================================

    scanButton.addEventListener("click", scanURL);

    console.log("✅ PhishGuard scanner is ready.");

    // ==========================================
    // MAIN SCANNING FUNCTION
    // ==========================================

    function scanURL() {

        console.log("🔍 Scan button clicked.");

        let userURL = urlInput.value.trim();

        // ==========================================
        // CHECK EMPTY INPUT
        // ==========================================

        if (userURL === "") {

            alert("Please enter a website URL.");

            return;
        }

        // ==========================================
        // ADD HTTPS IF NEEDED
        // ==========================================

        if (
            !userURL.startsWith("http://") &&
            !userURL.startsWith("https://")
        ) {

            userURL = "https://" + userURL;
        }

        console.log("🌐 URL being scanned:", userURL);

        // ==========================================
        // PARSE URL
        // ==========================================

        let parsedURL;

        try {

            parsedURL = new URL(userURL);

        } catch (error) {

            console.error("❌ Invalid URL:", error);

            alert("That doesn't appear to be a valid URL.");

            return;
        }

        // ==========================================
        // INITIAL VALUES
        // ==========================================

        let riskScore = 0;

        let warnings = [];

        let detectedBrand = "";

        const hostname = parsedURL.hostname.toLowerCase();

        const lowerURL = userURL.toLowerCase();

        // ==========================================
        // CHECK 1: HTTPS
        // ==========================================

        if (parsedURL.protocol !== "https:") {

            riskScore += 20;

            warnings.push(
                "Website is not using HTTPS."
            );
        }

        // ==========================================
        // CHECK 2: IP ADDRESS
        // ==========================================

        const ipPattern =
            /^(\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {

            riskScore += 25;

            warnings.push(
                "Website uses an IP address instead of a normal domain."
            );
        }

        // ==========================================
        // CHECK 3: VERY LONG URL
        // ==========================================

        if (userURL.length > 100) {

            riskScore += 10;

            warnings.push(
                "URL is unusually long."
            );
        }

        // ==========================================
        // CHECK 4: SUSPICIOUS @ CHARACTER
        // ==========================================

        if (userURL.includes("@")) {

            riskScore += 20;

            warnings.push(
                "URL contains the '@' character."
            );
        }

        // ==========================================
        // CHECK 5: SUSPICIOUS KEYWORDS
        // ==========================================

        const suspiciousWords = [
            "login",
            "verify",
            "verification",
            "account",
            "update",
            "secure",
            "payment",
            "password",
            "signin",
            "confirm",
            "wallet"
        ];

        let foundKeywords = [];

        suspiciousWords.forEach(function (word) {

            if (lowerURL.includes(word)) {

                foundKeywords.push(word);
            }
        });

        if (foundKeywords.length >= 2) {

            riskScore += 15;

            warnings.push(
                "URL contains multiple security-sensitive keywords: " +
                foundKeywords.join(", ")
            );
        }

        // ==========================================
        // CHECK 6: POSSIBLE BRAND IMPERSONATION
        // ==========================================

        for (const brand in trustedBrands) {

            // Check if brand name appears anywhere in URL
            if (lowerURL.includes(brand)) {

                const officialDomain =
                    trustedBrands[brand];

                // Check whether hostname belongs to official domain
                const isOfficialDomain =
                    hostname === officialDomain ||
                    hostname.endsWith("." + officialDomain);

                if (!isOfficialDomain) {

                    detectedBrand = brand;

                    riskScore += 25;

                    warnings.push(
                        "Possible " +
                        brand.charAt(0).toUpperCase() +
                        brand.slice(1) +
                        " brand impersonation detected."
                    );

                    console.warn(
                        "🚨 Possible brand impersonation:",
                        brand
                    );

                    break;
                }
            }
        }

        // ==========================================
        // CHECK 7: SUSPICIOUS DOMAIN CHARACTERS
        // ==========================================

        const hyphenCount =
            (hostname.match(/-/g) || []).length;

        if (hyphenCount >= 3) {

            riskScore += 10;

            warnings.push(
                "Domain contains an unusually high number of hyphens."
            );
        }

        // ==========================================
        // CHECK 8: MANY SUBDOMAINS
        // ==========================================

const domainParts = hostname.split(".");

if (
    !ipPattern.test(hostname) &&
    domainParts.length >= 4
) {

    riskScore += 10;

    warnings.push(
        "Domain contains an unusually large number of subdomains."
    );
}

        // ==========================================
        // LIMIT SCORE TO 100
        // ==========================================

        if (riskScore > 100) {

            riskScore = 100;
        }

        // ==========================================
        // DETERMINE RISK LEVEL
        // ==========================================

        let riskLevel;

        if (riskScore < 20) {

            riskLevel = "LOW RISK";

        } else if (riskScore < 50) {

            riskLevel = "MEDIUM RISK";

        } else {

            riskLevel = "HIGH RISK";
        }

        // ==========================================
        // CONSOLE RESULT
        // ==========================================

        console.log("📊 Scan completed.");
        console.log("Domain:", hostname);
        console.log("Risk Score:", riskScore);
        console.log("Risk Level:", riskLevel);
        console.log("Warnings:", warnings);
        console.log("Detected Brand:", detectedBrand || "None");

        // ==========================================
        // DISPLAY RESULT
        // ==========================================

        showResult(
            riskScore,
            riskLevel,
            warnings,
            hostname,
            detectedBrand
        );
    }

    // ==========================================
    // DISPLAY RESULT
    // ==========================================

    function showResult(
        score,
        level,
        warnings,
        hostname,
        detectedBrand
    ) {

        // Find existing result section
        let resultSection =
            document.getElementById("resultSection");

        // Create result section if it doesn't exist
        if (!resultSection) {

            resultSection =
                document.createElement("div");

            resultSection.id =
                "resultSection";

            const hero =
                document.querySelector(".hero");

            if (hero) {

                hero.appendChild(resultSection);

            } else {

                document.body.appendChild(resultSection);
            }
        }

        // ==========================================
        // CREATE WARNING LIST
        // ==========================================

        let warningHTML = "";

        if (warnings.length === 0) {

            warningHTML = `
                <p>✓ No major suspicious indicators detected.</p>
            `;

        } else {

            warningHTML = "<ul>";

            warnings.forEach(function (warning) {

                warningHTML += `
                    <li>⚠️ ${warning}</li>
                `;
            });

            warningHTML += "</ul>";
        }

        // ==========================================
        // BRAND WARNING
        // ==========================================

        let brandWarningHTML = "";

        if (detectedBrand) {

            const brandName =
                detectedBrand.charAt(0).toUpperCase() +
                detectedBrand.slice(1);

            brandWarningHTML = `
                <div class="brand-warning">
                    🚨 Possible ${brandName} impersonation
                </div>
            `;
        }

        // ==========================================
        // DISPLAY FINAL RESULT
        // ==========================================

        resultSection.innerHTML = `

            <div class="result-card">

                <p class="result-label">
                    SECURITY ANALYSIS
                </p>

                <h2>
                    ${level}
                </h2>

                <div class="risk-score">
                    ${score}/100
                </div>

                <p class="scanned-domain">
                    Scanned domain: ${hostname}
                </p>

                <div class="warnings">

                    <h3>
                        Why was this score given?
                    </h3>

                    ${brandWarningHTML}

                    ${warningHTML}

                </div>

            </div>

        `;

        // ==========================================
        // SCROLL TO RESULT
        // ==========================================

        resultSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

        console.log("✅ Result displayed successfully.");
    }

});
