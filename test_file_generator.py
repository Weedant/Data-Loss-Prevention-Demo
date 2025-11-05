# test_file_generator.py -- Generate test files with sensitive data for DLP testing
import random
import os
import time
from datetime import datetime

# Configure output - generate in TEMP folder first, then copy to watch folder
TEMP_DIR = os.path.join(os.path.dirname(__file__), "temp_test_files")
WATCH_DIR = r"C:\Users\VEDANT\Desktop\Data_Exfiltration\watch"
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(WATCH_DIR, exist_ok=True)

# Sample data for filler text
LOREM_IPSUM = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor 
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation 
ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit 
in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat 
non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."""

BUSINESS_TEXT = """The quarterly report shows significant growth in all departments. Revenue has 
increased by 15% compared to last quarter. Our marketing team has successfully launched three new 
campaigns targeting key demographics. The sales department exceeded their targets by implementing 
new customer relationship strategies. Operations have been streamlined through automation."""

TECH_TEXT = """The application architecture follows modern microservices patterns. Each service 
is containerized using Docker and orchestrated with Kubernetes. The database layer uses PostgreSQL 
for relational data and Redis for caching. API endpoints are secured with JWT authentication and 
rate limiting. The frontend is built with React and implements responsive design principles."""

FILLER_TEXTS = [LOREM_IPSUM, BUSINESS_TEXT, TECH_TEXT]


# Sensitive data generators
def generate_email():
    """Generate a random email address"""
    names = ["john.doe", "alice.smith", "bob.johnson", "emma.wilson", "michael.brown",
             "sarah.davis", "david.miller", "jennifer.taylor", "william.anderson", "lisa.moore"]
    domains = ["gmail.com", "yahoo.com", "outlook.com", "company.com", "example.org", "test.net"]
    return f"{random.choice(names)}{random.randint(1, 999)}@{random.choice(domains)}"


def generate_aadhaar():
    """Generate a random Aadhaar number (format: 1234 5678 9012)"""
    return f"{random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}"


def generate_credit_card():
    """Generate a random credit card number"""
    # Generate 16 digit number
    return " ".join([str(random.randint(1000, 9999)) for _ in range(4)])


def generate_confidential_text():
    """Generate text with confidential marker"""
    markers = ["CONFIDENTIAL", "SECRET", "RESTRICTED", "Confidential Information", "Secret Document"]
    contexts = [
        f"This document is marked as {random.choice(markers)} and should not be shared externally.",
        f"[{random.choice(markers)}] Internal use only - do not distribute.",
        f"Classification: {random.choice(markers)} - Handle with care.",
        f"NOTICE: This is {random.choice(markers).lower()} material."
    ]
    return random.choice(contexts)


def generate_test_file(filename, size_kb=100, pattern_count=5, pattern_type="mixed"):
    """
    Generate a test file with sensitive data patterns.

    Args:
        filename: Name of the file to create
        size_kb: Approximate target size in KB
        pattern_count: Number of sensitive patterns to include
        pattern_type: Type of pattern ("email", "aadhaar", "credit_card", "confidential", "mixed")
    """
    # Generate in temp folder first
    temp_path = os.path.join(TEMP_DIR, filename)

    # Calculate approximate lines needed for target size
    avg_line_length = 80
    lines_needed = (size_kb * 1024) // avg_line_length

    sensitive_data = []

    # Generate sensitive data based on type
    if pattern_type == "mixed":
        for _ in range(pattern_count):
            choice = random.choice(["email", "aadhaar", "credit_card", "confidential"])
            if choice == "email":
                sensitive_data.append(f"Contact: {generate_email()}")
            elif choice == "aadhaar":
                sensitive_data.append(f"Aadhaar Number: {generate_aadhaar()}")
            elif choice == "credit_card":
                sensitive_data.append(f"Card: {generate_credit_card()}")
            elif choice == "confidential":
                sensitive_data.append(generate_confidential_text())
    elif pattern_type == "email":
        sensitive_data = [f"Email: {generate_email()}" for _ in range(pattern_count)]
    elif pattern_type == "aadhaar":
        sensitive_data = [f"Aadhaar: {generate_aadhaar()}" for _ in range(pattern_count)]
    elif pattern_type == "credit_card":
        sensitive_data = [f"Credit Card: {generate_credit_card()}" for _ in range(pattern_count)]
    elif pattern_type == "confidential":
        sensitive_data = [generate_confidential_text() for _ in range(pattern_count)]

    # Positions to insert sensitive data (distributed throughout the file)
    sensitive_positions = sorted(random.sample(range(lines_needed), min(pattern_count, lines_needed)))

    print(f"\n{'=' * 60}")
    print(f"Generating: {filename}")
    print(f"Target size: ~{size_kb} KB")
    print(f"Pattern type: {pattern_type}")
    print(f"Pattern count: {pattern_count}")
    print(f"{'=' * 60}")

    with open(temp_path, "w", encoding="utf-8") as f:
        # Write header
        f.write(f"TEST DOCUMENT - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        sensitive_idx = 0
        for i in range(lines_needed):
            # Insert sensitive data at predetermined positions
            if sensitive_idx < len(sensitive_positions) and i == sensitive_positions[sensitive_idx]:
                f.write(f"\n{sensitive_data[sensitive_idx]}\n\n")
                print(f"  → Line {i}: {sensitive_data[sensitive_idx][:60]}...")
                sensitive_idx += 1
            else:
                # Write filler text
                filler = random.choice(FILLER_TEXTS)
                lines = filler.split("\n")
                f.write(random.choice(lines).strip() + "\n")

    actual_size = os.path.getsize(temp_path) / 1024
    print(f"\nFile created in temp: {temp_path}")
    print(f"Actual size: {actual_size:.2f} KB")

    # Now copy to watch folder (this should trigger the watcher)
    import shutil
    final_path = os.path.join(WATCH_DIR, filename)
    print(f"Copying to watch folder: {final_path}")
    shutil.copy2(temp_path, final_path)
    print(f"✓ File deployed to watch folder")
    print(f"{'=' * 60}\n")

    return final_path


def interactive_mode():
    """Interactive mode for testing"""
    print("\n" + "=" * 60)
    print("INTERACTIVE TEST MODE")
    print("=" * 60)
    print("\nOptions:")
    print("1. Generate small email test (10 KB)")
    print("2. Generate medium mixed test (100 KB)")
    print("3. Generate large file (500 KB)")
    print("4. Generate huge file (1 MB)")
    print("5. Generate mega file (2 MB)")
    print("6. Custom file")
    print("0. Exit")

    choice = input("\nEnter choice: ").strip()

    if choice == "1":
        generate_test_file("small_email_test.txt", 10, 3, "email")
    elif choice == "2":
        generate_test_file("medium_mixed_test.txt", 100, 10, "mixed")
    elif choice == "3":
        generate_test_file("large_aadhaar_test.txt", 500, 20, "aadhaar")
    elif choice == "4":
        generate_test_file("huge_credit_card_test.txt", 1000, 30, "credit_card")
    elif choice == "5":
        generate_test_file("mega_mixed_test.txt", 2000, 50, "mixed")
    elif choice == "6":
        filename = input("Filename: ").strip()
        size = int(input("Size (KB): ").strip())
        count = int(input("Pattern count: ").strip())
        ptype = input("Pattern type (email/aadhaar/credit_card/confidential/mixed): ").strip()
        generate_test_file(filename, size, count, ptype)
    elif choice == "0":
        return False
    else:
        print("Invalid choice!")

    return True


def main():
    print("\n" + "=" * 60)
    print("DLP TEST FILE GENERATOR")
    print("=" * 60)
    print(f"\nTemp folder: {TEMP_DIR}")
    print(f"Watch folder: {WATCH_DIR}")

    mode = input("\n1. Generate all test files\n2. Interactive mode\n\nChoice: ").strip()

    if mode == "1":
        # Generate various test files
        test_files = [
            ("small_email_test.txt", 10, 3, "email"),
            ("medium_mixed_test.txt", 100, 10, "mixed"),
            ("large_aadhaar_test.txt", 500, 20, "aadhaar"),
            ("huge_credit_card_test.txt", 1000, 30, "credit_card"),
            ("confidential_document.txt", 250, 15, "confidential"),
            ("mega_mixed_test.txt", 2000, 50, "mixed"),
        ]

        print("\nGenerating test files...\n")

        for filename, size_kb, count, ptype in test_files:
            generate_test_file(filename, size_kb, count, ptype)
            time.sleep(1)  # Small delay between files

        print("\n" + "=" * 60)
        print("GENERATION COMPLETE!")
        print("=" * 60)
    elif mode == "2":
        while interactive_mode():
            input("\nPress Enter to continue...")
    else:
        print("Invalid choice!")
        return

    print(f"\nAll files saved to: {WATCH_DIR}")
    print("\nYour DLP system should now detect these files!")
    print("Check the dashboard at http://127.0.0.1:5000")
    print("\nYou can also:")
    print("1. Copy these files to your USB drive (D:\\)")
    print("2. Use the 'Scan Existing Files' button in the dashboard")
    print("3. Modify files and see if changes are detected")
    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()