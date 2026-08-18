// ==========================================
// PHISHGUARD - BASIC URL SCANNER
// ==========================================
// ==========================================
// KNOWN BRANDS
// ==========================================

const trustedBrands = {
    "flipkart": "flipkart.com",
    "amazon": "amazon.in",
    "myntra": "myntra.com",
    "meesho": "meesho.com",
    "paytm": "paytm.com"
};

// Get the elements from our HTML page
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");


// When the user clicks "Scan Website"
scanButton.addEventListener("click", scanURL);


// Main scanning function
function scanURL() {

    // Get the URL entered by the user
    let userURL = urlInput.value.trim();


    // Check if the user entered anything
    if (userURL === "") {

        alert("Please enter a website URL.");

        return;
    }


    // Add https:// if the user didn't type a protocol
    if (!userURL.startsWith("http://") &&
        !userURL.startsWith("https://")) {

        userURL = "https://" + userURL;
    }


    // Try to understand the URL
    let parsedURL;

    try {

        parsedURL = new URL(userURL);

    } catch (error) {

        alert("That doesn't appear to be a valid URL.");

        return;
    }


    // Start risk score
    let riskScore = 0;

    // Store reasons why the URL may be suspicious
    let warnings = [];


    // ==========================================
    // CHECK 1: HTTPS
    // ==========================================

    if (parsedURL.protocol !== "https:") {

        riskScore += 20;

        warnings.push("Website is not using HTTPS.");

    }


    // ==========================================
    // CHECK 2: IP ADDRESS
    // ==========================================

    const hostname = parsedURL.hostname;

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
    // CHECK 4: SUSPICIOUS CHARACTERS
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


    const lowerURL = userURL.toLowerCase();


    let foundKeywords = [];


    suspiciousWords.forEach(function(word) {

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

let brandImpersonation = false;

let detectedBrand = "";

for (const brand in trustedBrands) {

    // Check whether the URL contains a known brand name
    if (lowerURL.includes(brand)) {

        const officialDomain = trustedBrands[brand];

        // Check whether the actual hostname belongs
        // to the official domain
        if (
            hostname !== officialDomain &&
            !hostname.endsWith("." + officialDomain)
        ) {

            brandImpersonation = true;

            detectedBrand = brand;

            riskScore += 25;

            warnings.push(
                "Possible " +
                brand.charAt(0).toUpperCase() +
                brand.slice(1) +
                " brand impersonation detected."
            );

            break;
        }
    }
}

// ==========================================
// CHECK 7: SUSPICIOUS DOMAIN CHARACTERS
// ==========================================

const hyphenCount = (hostname.match(/-/g) || []).length;

if (hyphenCount >= 3) {

    riskScore += 10;

    warnings.push(
        "Domain contains an unusually high number of hyphens."
    );
}




    // ==========================================
    // CHECK 6: MANY SUBDOMAINS
    // ==========================================

    const domainParts = hostname.split(".");


    if (domainParts.length >= 4) {

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


    if (riskScore <= 20) {

        riskLevel = "LOW RISK";

    } else if (riskScore <= 50) {

        riskLevel = "MEDIUM RISK";

    } else {

        riskLevel = "HIGH RISK";

    }


    // ==========================================
    // SHOW RESULT
    // ==========================================

    showResult(
        riskScore,
        riskLevel,
        warnings,
        hostname
    );

}
// ==========================================
// DISPLAY RESULT
// ==========================================

function showResult(score, level, warnings, hostname,detectedBrand) {

    // Find an existing result section
    let resultSection = document.getElementById("resultSection");


    // If the result section doesn't exist yet,
    // create it
    if (!resultSection) {

        resultSection = document.createElement("div");

        resultSection.id = "resultSection";

        document.querySelector(".hero").appendChild(resultSection);

    }


    // Create the warning list
    let warningHTML = "";


    if (warnings.length === 0) {

        warningHTML = `
            <p>✓ No major suspicious indicators detected.</p>
        `;

    } else {

        warningHTML = "<ul>";

        warnings.forEach(function(warning) {

            warningHTML += `
                <li>⚠️ ${warning}</li>
            `;

        });

        warningHTML += "</ul>";
    }


    // Display the final result
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
${detectedBrand
    ? `<div class="brand-warning">
        🚨 Possible ${detectedBrand.charAt(0).toUpperCase() + detectedBrand.slice(1)} impersonation
       </div>`
    : ""
}
                ${warningHTML}

            </div>

        </div>

    `;


    // Scroll down to the result
    resultSection.scrollIntoView({
        behavior: "smooth"
    });

}