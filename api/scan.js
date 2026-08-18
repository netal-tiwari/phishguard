// ==========================================
// PHISHGUARD - URL SCANNER
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


// ==========================================
// GET HTML ELEMENTS
// ==========================================

const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");


// ==========================================
// SCAN BUTTON
// ==========================================

scanButton.addEventListener("click", scanURL);


// ==========================================
// MAIN URL SCANNER
// ==========================================

async function scanURL() {

    // Get URL entered by the user
    let userURL = urlInput.value.trim();


    // ==========================================
    // CHECK EMPTY INPUT
    // ==========================================

    if (userURL === "") {

        alert("Please enter a website URL.");

        return;
    }


    // ==========================================
    // ADD HTTPS IF PROTOCOL IS MISSING
    // ==========================================

    if (
        !userURL.startsWith("http://") &&
        !userURL.startsWith("https://")
    ) {

        userURL = "https://" + userURL;
    }


    // ==========================================
    // PARSE URL
    // ==========================================

    let parsedURL;

    try {

        parsedURL = new URL(userURL);

    } catch (error) {

        alert("That doesn't appear to be a valid URL.");

        return;
    }


    // ==========================================
    // INITIAL RISK SCORE
    // ==========================================

    let riskScore = 0;

    let warnings = [];


    // ==========================================
    // GET HOSTNAME
    // ==========================================

    const hostname = parsedURL.hostname;


    // Lowercase version for analysis
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
    // CHECK 4: @ CHARACTER
    // ==========================================

    if (userURL.includes("@")) {

        riskScore += 20;

        warnings.push(
            "URL contains the '@' character."
        );
    }


    // ==========================================
    // CHECK 5: SENSITIVE KEYWORDS
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
    // CHECK 6: BRAND IMPERSONATION
    // ==========================================

    let brandImpersonation = false;

    let detectedBrand = "";


    for (const brand in trustedBrands) {

        // Does URL contain a known brand name?
        if (lowerURL.includes(brand)) {

            const officialDomain =
                trustedBrands[brand];


            // Is the current hostname different
            // from the official brand domain?
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
    // CHECK 7: MANY HYPHENS
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

    const domainParts =
        hostname.split(".");


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
    // DETERMINE LOCAL RISK LEVEL
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
    // SEND URL TO OUR BACKEND
    // ==========================================

    try {

        const response = await fetch(
            "/api/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: userURL
                })
            }
        );


        const virusTotalData =
            await response.json();


        // Show VirusTotal response
        // in browser console for now
        console.log(
            "VirusTotal response:",
            virusTotalData
        );


        // If backend returned an error
        if (!response.ok) {

            console.error(
                "VirusTotal error:",
                virusTotalData
            );
        }


    } catch (error) {

        console.error(
            "Could not connect to VirusTotal:",
            error
        );
    }


    // ==========================================
    // SHOW OUR CURRENT RESULT
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

    // Find result section
    let resultSection =
        document.getElementById("resultSection");


    // Create result section if it doesn't exist
    if (!resultSection) {

        resultSection =
            document.createElement("div");

        resultSection.id =
            "resultSection";


        document
            .querySelector(".hero")
            .appendChild(resultSection);
    }


    // ==========================================
    // WARNING HTML
    // ==========================================

    let warningHTML = "";


    if (warnings.length === 0) {

        warningHTML = `
            <p>
                ✓ No major suspicious indicators detected.
            </p>
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


    // ==========================================
    // BRAND WARNING
    // ==========================================

    let brandWarningHTML = "";


    if (detectedBrand) {

        const formattedBrand =
            detectedBrand.charAt(0).toUpperCase() +
            detectedBrand.slice(1);


        brandWarningHTML = `
            <div class="brand-warning">
                🚨 Possible ${formattedBrand} impersonation
            </div>
        `;
    }


    // ==========================================
    // DISPLAY RESULT
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

            ${brandWarningHTML}

            <div class="warnings">

                <h3>
                    Why was this score given?
                </h3>

                ${warningHTML}

            </div>

        </div>

    `;


    // ==========================================
    // SCROLL TO RESULT
    // ==========================================

    resultSection.scrollIntoView({
        behavior: "smooth"
    });

}
