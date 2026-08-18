export default async function handler(req, res) {

    // Only allow POST requests
    if (req.method !== "POST") {

        return res.status(405).json({
            error: "Method not allowed"
        });
    }


    try {

        // Get URL from the browser
        const { url } = req.body;


        // Check that a URL was provided
        if (!url) {

            return res.status(400).json({
                error: "URL is required"
            });
        }


        // Get the secret API key from the server
        const apiKey = process.env.VIRUSTOTAL_API_KEY;


        if (!apiKey) {

            return res.status(500).json({
                error: "VirusTotal API key is not configured"
            });
        }


        // Send URL to VirusTotal
        const formData = new URLSearchParams();

        formData.append("url", url);


        const response = await fetch(
            "https://www.virustotal.com/api/v3/urls",
            {
                method: "POST",

                headers: {
                    "x-apikey": apiKey,
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: formData
            }
        );


        const data = await response.json();


        // Return VirusTotal response to our website
        return res.status(response.status).json(data);


    } catch (error) {

        console.error(error);


        return res.status(500).json({
            error: "Something went wrong while checking the URL."
        });
    }
}