# WhistleVault

## Overview
WhistleVault is a sophisticated web-based application developed to provide a secure platform for users to store, manage, and share sensitive information, including confidential documents, personal notes, and multimedia files. This project was created as part of a course focusing on integrating practical software development with database management system (DBMS) concepts. It leverages a combination of modern technologies to ensure data security, scalability, and usability.

## Technologies Used
- **Flask:** A lightweight Python web framework for building the application.
- **SQLite:** A serverless database engine for efficient data storage and retrieval.
- **Cryptography:** Python library for secure encryption of sensitive data.
- **Jinja2:** Templating engine for dynamic HTML page rendering.
- **Flask-Bcrypt:** Extension for secure password hashing.
- **HTML/CSS:** For a responsive and user-friendly interface.
- **Git:** Version control for collaborative development.

## System Architecture
WhistleVault follows the Model-View-Controller (MVC) architectural pattern:
- **Model:** Managed by SQLite, handling data entities like users, secrets, categories, and logs.
- **View:** Rendered using Jinja2 templates for an intuitive user interface.
- **Controller:** Implemented in `app.py`, managing routes, logic, and encryption.

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- Flask, Flask-Bcrypt, and Cryptography Python packages
- SQLite3
- A web server environment (e.g., local Flask server or PythonAnywhere)

### Local Installation
1. Install required packages:
   pip install flask flask-bcrypt cryptography
2. Create a virtual environment:
  python3 -m venv venv
3. Activate the virtual environment:
  - Linux/Mac: `source venv/bin/activate`
  - Windows: `venv\Scripts\activate`
4. Initialize the database:
   sqlite3 whistlevault.db < scripts/setup.sql
5. Update the database path in `app.py` (e.g., `/path/to/whistlevault.db`).
6. Run the application:
   python app.py

### Deployment on PythonAnywhere
1. Upload the project as a ZIP file (e.g., `WhistleVault.zip`) to `/home/yourusername/`.
2. Extract files:
   unzip WhistleVault.zip -d /home/yourusername/
3. Configure a web app with the source directory `/home/yourusername/WhistleVault` and update the WSGI file.
4. Install dependencies in a virtual environment on PythonAnywhere.
5. Reload the web app to go live.

## Code Structure
- **app.py:** Main file with Flask routes, business logic, and encryption functions.
- **templates/:**
- `view_all.html`: Displays sortable secret list.
- `submit.html`: Form for secret submission.
- `login.html`: User login page.
- `profile.html`: User profile management.
- **static/:** Stores uploaded photos and CSS files.
- **scripts/setup.sql:** SQL script for database initialization.

## How to Pull the Project
To clone the WhistleVault repository from GitHub to your local machine:
1. Ensure Git is installed (`git --version` to check, or install with `sudo apt install git` on Ubuntu).
2. Open a terminal and navigate to your desired directory:
   
   cd /path/to/your/directory
4. Clone the repository using the URL (replace with your repository URL):
   
   git clone https://github.com/PratikDhage/WhistleVault.git
6. Navigate into the project folder:
cd WhistleVault
5. (Optional) Update your local copy by pulling the latest changes:
  git pull origin main
  (Use `master` if your default branch is named differently.)

## How to Run the Project
After pulling the project or setting it up locally:
1. Activate the virtual environment (if created):
  - Linux/Mac: `source venv/bin/activate`
  - Windows: `venv\scripts\activate`
2. Ensure the database (`whistlevault.db`) is initialized as per the Installation steps.
3. Start the Flask application:

python app.py
4. Open a web browser and navigate to `http://localhost:5000` (or the port specified in `app.py`) to access WhistleVault.
5. To stop the server, press `Ctrl+C` in the terminal.

## Future Improvements
- Integrate two-factor authentication (2FA).
- Add a search bar for quick secret retrieval.
- Introduce moderator roles.
- Implement automated database backups.
- Develop a mobile-friendly interface.

## Contributors
- Dhage Pratik Bhishmacharya (CS23B1047)
- Yadynesh D Sonale (CS23B1055)
- Ala Pavan Sai Teja (CS23B1069)

## License
MIT License

Copyright (c) 2025 Dhage Pratik Bhishmacharya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments
We thank our instructors and peers for their guidance and support during the development of WhistleVault.

## Contact
For questions or contributions, please open an issue or contact the team at [cs23b1047@iiitdm.ac.in].
