import os
import platform

def create_directory_structure(base_path):
    """
    Creates the directory structure for the AD assessment tool.

    Args:
        base_path (str): The root directory where the structure will be created.
    """

    directories = [
        os.path.join(base_path, "templates"),
        os.path.join(base_path, "static", "css"),
        os.path.join(base_path, "modules")
    ]

    files = [
        os.path.join(base_path, "app.py"),
        os.path.join(base_path, "templates", "base.html"),
        os.path.join(base_path, "templates", "index.html"),
        os.path.join(base_path, "templates", "target_config.html"),
        os.path.join(base_path, "templates", "attack_selection.html"),
        os.path.join(base_path, "templates", "results.html"),
        os.path.join(base_path, "static", "css", "style.css"),
        os.path.join(base_path, "modules", "__init__.py")
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

    for file in files:
        if not os.path.exists(file):
            open(file, 'a').close()  # Create empty file
            print(f"Created file: {file}")

if __name__ == '__main__':
    # Get the current directory
    current_dir = os.getcwd()

    # Create the directory structure
    create_directory_structure(current_dir)

    print("\nDirectory structure created successfully!")
    print("Remember to create a virtual environment in the base directory.")
    if platform.system() == 'Windows':
        print("python -m venv .venv")
    else:
        print("python3 -m venv .venv")