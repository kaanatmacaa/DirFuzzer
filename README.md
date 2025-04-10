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

Example screenshots

Simple directory fuzzing:
<img width="1438" alt="resim" src="https://github.com/user-attachments/assets/ba620f51-0e5e-4b77-98c3-d1788895a123" />


Add custom headers:
<img width="1429" alt="resim" src="https://github.com/user-attachments/assets/515ccc49-092e-468e-a734-26a7e510c8ab" />

Filter results:
Select status code:
<img width="1433" alt="resim" src="https://github.com/user-attachments/assets/32f516c9-1df5-4a5d-aa2f-13c00be2a5db" />

Exclude status code:
<img width="1431" alt="resim" src="https://github.com/user-attachments/assets/03ed2dbd-bc84-4d28-97de-4d26a00e5d6f" />

Exclude length:
<img width="1439" alt="resim" src="https://github.com/user-attachments/assets/02ffcb8d-33d9-4e19-851f-90e69f43afe1" />

Colorize results:
<img width="1435" alt="resim" src="https://github.com/user-attachments/assets/18966114-a824-4d47-a844-653a34be350a" />

Send to repeater or intruder:
<img width="1433" alt="resim" src="https://github.com/user-attachments/assets/5301ec8c-c689-4787-9271-8cb08beb9c9c" />

Export CSV:
<img width="1434" alt="resim" src="https://github.com/user-attachments/assets/948cc540-850f-4571-81e5-c1ba1c309031" />


