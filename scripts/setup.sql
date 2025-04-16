-- Users table
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    profile_picture VARCHAR(255),
    is_admin INTEGER DEFAULT 0, 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Categories table
CREATE TABLE categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    is_custom INTEGER DEFAULT 0
);

-- Secrets table
CREATE TABLE secrets (
    secret_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    secret_text BLOB,
    title VARCHAR(100) NOT NULL,
    category_id INTEGER NOT NULL,
    priority TEXT CHECK(priority IN ('Low', 'Medium', 'High')) DEFAULT 'Medium',
    custom_category VARCHAR(50),
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    views INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (category_id) REFERENCES categories(category_id)
);

-- Secret Photos table
CREATE TABLE secret_photos (
    photo_id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL,
    photo_path VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(secret_id) ON DELETE CASCADE
);

-- Shares table
CREATE TABLE shares (
    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    share_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(secret_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Secret Logs table
CREATE TABLE secret_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL,
    user_id INTEGER,
    view_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(secret_id) ON DELETE CASCADE
);

-- Trigger for view counting
CREATE TRIGGER increment_views
AFTER INSERT ON secret_logs
BEGIN
    UPDATE secrets SET views = views + 1 WHERE secret_id = NEW.secret_id;
END;

-- Prepopulate categories
INSERT INTO categories (name, is_custom) VALUES
    ('Corruption', 0),
    ('Fraud', 0),
    ('Misconduct', 0),
    ('Whistleblower', 0),
    ('Ethics Violation', 0),
    ('Safety Concern', 0),
    ('Financial Irregularity', 0),
    ('Harassment', 0),
    ('Discrimination', 0),
    ('Environmental Violation', 0),
    ('Data Breach', 0),
    ('Security Incident', 0),
    ('Policy Violation', 0),
    ('Conflict of Interest', 0),
    ('Bribery', 0),
    ('Theft', 0),
    ('Vandalism', 0),
    ('Substance Abuse', 0),
    ('Negligence', 0),
    ('Privacy Violation', 0),
    ('Intellectual Property Theft', 0),
    ('Cybercrime', 0),
    ('Insider Trading', 0),
    ('Other', 0);

INSERT INTO users (username, email, hashed_password, is_admin) VALUES ('admin1', 'admin1@example.com', '$2b$12$8WrV19jwEmWg2ol6yXd2e.BpoCGny8BfMFbOjqcX73b9mRbXa8thy', 1),('admin2', 'admin2@example.com', '$2b$12$8WrV19jwEmWg2ol6yXd2e.BpoCGny8BfMFbOjqcX73b9mRbXa8thy', 1),('admin3', 'admin3@example.com', '$2b$12$8WrV19jwEmWg2ol6yXd2e.BpoCGny8BfMFbOjqcX73b9mRbXa8thy', 1);