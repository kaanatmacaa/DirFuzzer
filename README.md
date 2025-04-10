# DirFuzzer
Lightweight directory brute-force extension for Burp Suite. Includes filtering, coloring, CSV export, custom headers, method selection, and more...

✨ Features

🚀 Fuzzing Core

    Sends directory fuzzing requests using the provided wordlist
    Supports GET, POST, and HEAD HTTP methods
    Custom headers (e.g. Authorization) can be added to each request

🧠 Filtering

    Status filter: View only a specific status code (e.g., 200, 403, 404)
    Exclude statuses: Exclude multiple codes (e.g., 404,403)
    Exclude lengths: Filter out response lengths that are noise (e.g., 1234, 5678)
    Combines all filters dynamically

🎨 Colorize Results

    Toggle to color rows based on status code:
        🟩 2xx → Green
        🟨 3xx → Yellow
        🟧 4xx → Orange
        🟥 5xx → Red

📤 Export Results

    Export table results to CSV format via one click
    Automatically includes: Path, Status, Response Length

🔁 Send to Tools

    Right-click any result to:
        ➡️ Send to Repeater
        ➡️ Send to Intruder

🧼 Table Management

    Clear Table button instantly resets results
    Request and response viewer available for each selected entry

💡 Why DirFuzzer?

✅ Clean UI
✅ Fast setup
✅ Flexible for black-box or authenticated fuzzing
✅ Built for real-world assessments by a penetration tester

